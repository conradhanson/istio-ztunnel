// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Phase-2 **real-stack** validation of CRL-reload data-plane impact, across both enforcement
//! directions and multiplexing factors.
//!
//! Runs the real encrypted HBONE data plane in network namespaces (like `throughput.rs` and the
//! namespaced CRL tests). Selected per run via env vars:
//!   * `CRL_DIRECTION` = `inbound` (default) | `outbound`
//!       - **inbound**: the *server* ztunnel holds the CRL and revokes *client* certs; teardown is a
//!         server GOAWAY on each inbound `serve_connection`.
//!       - **outbound**: the *client* ztunnel holds the CRL and revokes *server* certs; teardown
//!         drops the pooled client tunnel in `drive_connection`.
//!   * `CRL_STREAMS` = streams multiplexed per tunnel (default `1`). ztunnel pools app connections
//!     with the same `(src_id, dst_id, dst, src)` over one HBONE tunnel (up to
//!     `pool_max_streams_per_conn`, default 100), and holds **one** `ConnectionRevocation` per
//!     tunnel. So `CRL_STREAMS > 1` exercises: per-tunnel enforcement amortized over many streams,
//!     the teardown **blast radius** (one revocation closes all the tunnel's streams), and
//!     `CERT_REVOKED` attribution across those streams. Near 100 tests the real ceiling on one
//!     tunnel; `>= 100` spills the overflow into additional tunnels.
//!   * `CRL_HEALTHY` = number of never-revoked entities generating measured throughput (default 24).
//!   * `CRL_CYCLES` = number of isolated reload events, i.e. dip/latency samples (default 10).
//!     Each entity is a client+server workload pair, so entity count (`CRL_HEALTHY` + `CRL_CYCLES`)
//!     is the expensive axis; raise it as far as the machine sustains for statistical relevance.
//!
//! Topology (symmetric, so the two directions are comparable): each *entity* is one client workload
//! paired with one server workload; the client opens `CRL_STREAMS` connections to its server (→ one
//! tunnel per entity). `HEALTHY_TUNNELS` entities are never revoked and generate measured
//! throughput; `RELOAD_CYCLES × VICTIMS_PER_CYCLE` entities are revoked one batch per **isolated**
//! reload event (recovery between — not continuous churn).
//!
//! Reports per run (labeled with direction + streams): reload→close latency p50/p99/max + teardown
//! spread, healthy-throughput dip mean ± std over the reload events, and the observed blast radius.
//!
//! Leaf/workload-cert revocation only (no intermediate CAs in the harness yet). Requires root.
//! Run e.g.: `sudo -E CRL_DIRECTION=outbound CRL_STREAMS=25 cargo bench --bench crl_reload_real 2>/dev/null`

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use ztunnel::config;
use ztunnel::identity::{DEFAULT_TRUST_DOMAIN, Identity};
use ztunnel::setup_netns_test;
use ztunnel::test_helpers::linux::{TestMode, WorkloadManager};
use ztunnel::test_helpers::tcp::{Mode, TestServer};
use ztunnel::tls::mock::crl_pem_revoking_cert;

// The ctor must run before any tokio runtime — it unshares the user/net/mount namespaces.
#[ctor::ctor(unsafe)]
fn init() {
    // Raise the open-file limit for the many concurrent HBONE connections. Do it here (as real root
    // under `sudo`, *before* the userns unshare), because a shell `ulimit -n` before `sudo` does not
    // propagate — `sudo` gives its child root's configured limits, not the caller's soft limit.
    raise_fd_limit();
    ztunnel::test_helpers::namespaced::initialize_namespace_tests();
}

/// Best-effort raise of `RLIMIT_NOFILE`. Tries to lift the hard limit (allowed as real root, capped
/// by `/proc/sys/fs/nr_open`) and set the soft limit to match; falls back to raising the soft limit
/// up to the existing hard limit (always permitted).
fn raise_fd_limit() {
    const TARGET: libc::rlim_t = 1_048_576;
    unsafe {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            return;
        }
        let hard = TARGET.max(lim.rlim_max);
        let raised = libc::rlimit {
            rlim_cur: hard,
            rlim_max: hard,
        };
        if libc::setrlimit(libc::RLIMIT_NOFILE, &raised) == 0 {
            return;
        }
        // Couldn't raise the hard limit; at least max out the soft limit to it.
        let soft = libc::rlimit {
            rlim_cur: lim.rlim_max,
            rlim_max: lim.rlim_max,
        };
        let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &soft);
    }
}

const LOCAL: &str = "node"; // client-side node
const REMOTE: &str = "remote-node"; // server-side node
const SERVER_PORT: u16 = 8080;

// Scale knobs. HEALTHY_TUNNELS / RELOAD_CYCLES / STREAMS_PER_TUNNEL are overridable at runtime via
// CRL_HEALTHY / CRL_CYCLES / CRL_STREAMS so the limits can be swept without recompiling. Each entity
// is a client+server workload pair (~2 namespaces = 2 ztunnel proxy instances), so entity count is
// the expensive axis; streams are comparatively cheap. ztunnel multiplexes up to
// pool_max_streams_per_conn (default 100) streams per tunnel — CRL_STREAMS near 100 tests the real
// ceiling on one tunnel; >=100 spills the overflow into additional tunnels (blast radius still =
// total streams for the revoked identity).
const DEFAULT_HEALTHY_TUNNELS: usize = 24; // never-revoked entities that generate measured throughput
const DEFAULT_RELOAD_CYCLES: usize = 10; // isolated reload events (more = tighter dip statistics)
const VICTIMS_PER_CYCLE: usize = 1; // entities revoked per reload event
const DEFAULT_STREAMS_PER_TUNNEL: usize = 1;

const BODY: &[u8] = b"hello world";
const RESP: usize = BODY.len() * 2; // server runs ReadDoubleWrite (echoes twice)

/// Prefix on every line this bench prints, so results are greppable even when stdout is captured
/// interleaved with ztunnel's (stderr) telemetry: `... | grep '\[crl-bench\]'`.
macro_rules! bench_out {
    ($($arg:tt)*) => { println!("[crl-bench] {}", format!($($arg)*)) };
}

type Handle = std::thread::JoinHandle<anyhow::Result<()>>;

#[derive(Clone, Copy, PartialEq)]
enum Direction {
    Inbound,
    Outbound,
}

impl Direction {
    fn name(self) -> &'static str {
        match self {
            Direction::Inbound => "inbound",
            Direction::Outbound => "outbound",
        }
    }
}

#[derive(Clone, Copy)]
struct Params {
    direction: Direction,
    streams: usize,
    healthy: usize,
    cycles: usize,
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&v| v >= 1)
        .unwrap_or(default)
}

fn parse_env() -> Params {
    let direction = match std::env::var("CRL_DIRECTION").as_deref() {
        Ok("outbound") => Direction::Outbound,
        _ => Direction::Inbound,
    };
    Params {
        direction,
        streams: env_usize("CRL_STREAMS", DEFAULT_STREAMS_PER_TUNNEL),
        healthy: env_usize("CRL_HEALTHY", DEFAULT_HEALTHY_TUNNELS),
        cycles: env_usize("CRL_CYCLES", DEFAULT_RELOAD_CYCLES),
    }
}

struct Ctx {
    streams_per_tunnel: usize,
    crl_path: PathBuf,
    _crl_file: NamedTempFile,
    ops: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    close_rx: std::sync::mpsc::Receiver<Instant>,
    /// Per-cycle victim cert serials to append to the CRL.
    batches: Vec<Vec<Vec<u8>>>,
}

fn cfg_with_crl(path: &Path) -> config::Config {
    config::Config {
        crl_path: Some(path.to_path_buf()),
        ..config::parse_config().unwrap()
    }
}

/// Connect with a short retry loop, tolerating the target echo not being ready yet.
async fn connect_retry(srv: SocketAddr) -> anyhow::Result<TcpStream> {
    for _ in 0..50 {
        if let Ok(Ok(s)) = timeout(Duration::from_secs(1), TcpStream::connect(srv)).await {
            return Ok(s);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("failed to connect to {srv}")
}

/// Healthy (busy) connection: never revoked; continuous round-trips counted into `ops`.
async fn healthy_conn(
    srv: SocketAddr,
    ops: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let mut stream = connect_retry(srv).await?;
    let mut buf = [0u8; RESP];
    while !stop.load(Ordering::Relaxed) {
        let rt = timeout(Duration::from_secs(5), async {
            stream.write_all(BODY).await?;
            stream.read_exact(&mut buf).await?;
            Ok::<(), anyhow::Error>(())
        })
        .await;
        match rt {
            Ok(Ok(())) => {
                ops.fetch_add(1, Ordering::Relaxed);
            }
            _ => break, // connection unexpectedly died; stop this generator
        }
    }
    Ok(())
}

/// Victim connection: establish, confirm liveness, then block until torn down; report close time.
async fn victim_conn(
    srv: SocketAddr,
    tx: std::sync::mpsc::Sender<Instant>,
    stop: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let mut stream = connect_retry(srv).await?;
    stream.write_all(BODY).await?;
    let mut buf = [0u8; RESP];
    stream.read_exact(&mut buf).await?;
    let mut b = [0u8; 1];
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match timeout(Duration::from_millis(500), stream.read(&mut b)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {
                let _ = tx.send(Instant::now());
                break;
            }
            Ok(Ok(_)) => {} // unexpected data; keep waiting
            Err(_) => {}    // read timeout; re-check stop and keep waiting
        }
    }
    Ok(())
}

async fn setup(
    mut manager: WorkloadManager,
    params: Params,
) -> anyhow::Result<(Ctx, WorkloadManager, Vec<Handle>)> {
    let streams = params.streams;
    let mut handles: Vec<Handle> = Vec::new();

    let crl_file = NamedTempFile::new()?; // starts empty => no revocations
    let crl_path = crl_file.path().to_path_buf();

    // Deploy both ztunnels; the enforcer (server for inbound, client for outbound) holds the CRL.
    let (client_zt, server_zt) = match params.direction {
        Direction::Inbound => {
            let c = manager.deploy_ztunnel(LOCAL).await?;
            let s = manager
                .deploy_dedicated_ztunnel(REMOTE, Some(cfg_with_crl(&crl_path)), None)
                .await?;
            (c, s)
        }
        Direction::Outbound => {
            let c = manager
                .deploy_dedicated_ztunnel(LOCAL, Some(cfg_with_crl(&crl_path)), None)
                .await?;
            let s = manager.deploy_ztunnel(REMOTE).await?;
            (c, s)
        }
    };

    let total = params.healthy + params.cycles * VICTIMS_PER_CYCLE;
    let ops = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let (close_tx, close_rx) = std::sync::mpsc::channel::<Instant>();
    let mut victim_serials: Vec<Vec<u8>> = Vec::new();

    for i in 0..total {
        let is_healthy = i < params.healthy;

        // Server workload (echo) for this entity.
        let sname = format!("server-e{i}");
        let server_ns = manager
            .workload_builder(&sname, REMOTE)
            .hbone()
            .register()
            .await?;
        handles.push(server_ns.run_ready(|ready| async move {
            let echo = TestServer::new(Mode::ReadDoubleWrite, SERVER_PORT).await;
            ready.set_ready();
            echo.run().await;
            Ok(())
        })?);
        let srv = SocketAddr::new(
            manager.resolver().resolve(&sname).expect("resolve server"),
            SERVER_PORT,
        );

        // Client workload for this entity.
        let cname = format!("client-e{i}");
        let client_ns = manager.workload_builder(&cname, LOCAL).register().await?;

        // For victims, capture the serial of the cert that gets revoked: the client cert (inbound,
        // enforced at the server) or the server cert (outbound, enforced at the client).
        if !is_healthy {
            let (zt, name) = match params.direction {
                Direction::Inbound => (&client_zt, &cname),
                Direction::Outbound => (&server_zt, &sname),
            };
            let id = Identity::from_parts(
                DEFAULT_TRUST_DOMAIN.into(),
                "default".into(),
                name.as_str().into(),
            );
            let cert = zt.cert_manager.fetch_certificate(&id).await?;
            victim_serials.push(cert.cert.serial_bytes());
        }

        // Open `streams` connections from this entity's client to its server (→ one tunnel).
        let ops = ops.clone();
        let stop = stop.clone();
        let tx = close_tx.clone();
        handles.push(client_ns.run(move || async move {
            if is_healthy {
                let futs: Vec<_> = (0..streams)
                    .map(|_| healthy_conn(srv, ops.clone(), stop.clone()))
                    .collect();
                futures_util::future::join_all(futs).await;
            } else {
                let futs: Vec<_> = (0..streams)
                    .map(|_| victim_conn(srv, tx.clone(), stop.clone()))
                    .collect();
                futures_util::future::join_all(futs).await;
            }
            Ok(())
        })?);
    }
    drop(close_tx);

    let batches: Vec<Vec<Vec<u8>>> = victim_serials
        .chunks(VICTIMS_PER_CYCLE)
        .map(|c| c.to_vec())
        .collect();

    Ok((
        Ctx {
            streams_per_tunnel: streams,
            crl_path,
            _crl_file: crl_file,
            ops,
            stop,
            close_rx,
            batches,
        },
        manager,
        handles,
    ))
}

/// Round-trips/s between the samples bracketing `[from, to]`.
fn rate(samples: &[(Instant, u64)], from: Instant, to: Instant) -> f64 {
    let start = samples.iter().find(|(t, _)| *t >= from);
    let end = samples.iter().rev().find(|(t, _)| *t <= to);
    match (start, end) {
        (Some((t0, v0)), Some((t1, v1))) if t1 > t0 && v1 >= v0 => {
            (v1 - v0) as f64 / (*t1 - *t0).as_secs_f64()
        }
        _ => 0.0,
    }
}

struct Report {
    lats: Vec<Duration>,
    spreads: Vec<Duration>,
    dips: Vec<f64>,
    expected_closes: usize,
}

async fn run_cycles(ctx: Ctx) -> Report {
    let samples: Arc<Mutex<Vec<(Instant, u64)>>> = Arc::new(Mutex::new(Vec::new()));
    let sampler_stop = Arc::new(AtomicBool::new(false));
    let sampler = {
        let ops = ctx.ops.clone();
        let samples = samples.clone();
        let sstop = sampler_stop.clone();
        tokio::spawn(async move {
            while !sstop.load(Ordering::Relaxed) {
                samples
                    .lock()
                    .unwrap()
                    .push((Instant::now(), ops.load(Ordering::Relaxed)));
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
    };

    // Let healthy throughput stabilize (and all connections finish establishing) before reloading.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let mut lats = Vec::new();
    let mut spreads = Vec::new();
    let mut dips = Vec::new();
    let mut revoked: Vec<Vec<u8>> = Vec::new();
    let mut expected_closes = 0usize;

    for cycle in 0..ctx.batches.len() {
        // One revoked entity closes `streams_per_tunnel` connections (blast radius).
        let want = ctx.batches[cycle].len() * ctx.streams_per_tunnel;
        expected_closes += want;
        let t0 = Instant::now();
        revoked.extend(ctx.batches[cycle].iter().cloned());
        // CRL revokes every serial so far; CrlManager unions same-issuer CRL blocks.
        let pem: String = revoked.iter().map(|s| crl_pem_revoking_cert(s)).collect();
        if std::fs::write(&ctx.crl_path, pem).is_err() {
            break;
        }

        let mut got = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(15);
        while got.len() < want && Instant::now() < deadline {
            match ctx.close_rx.try_recv() {
                Ok(inst) => {
                    lats.push(inst.saturating_duration_since(t0));
                    got.push(inst);
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    tokio::time::sleep(Duration::from_millis(5)).await
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
            }
        }
        if got.is_empty() {
            bench_out!("cycle {cycle}: no closes observed (reload not applied?)");
            continue;
        }
        let t_first = *got.iter().min().unwrap();
        let t_last = *got.iter().max().unwrap();
        spreads.push(t_last.saturating_duration_since(t_first));

        tokio::time::sleep(Duration::from_millis(500)).await;
        {
            let s = samples.lock().unwrap();
            let before = rate(
                &s,
                t_first
                    .checked_sub(Duration::from_millis(300))
                    .unwrap_or(t_first),
                t_first
                    .checked_sub(Duration::from_millis(50))
                    .unwrap_or(t_first),
            );
            let during = rate(
                &s,
                t_first
                    .checked_sub(Duration::from_millis(25))
                    .unwrap_or(t_first),
                t_last + Duration::from_millis(25),
            );
            let after = rate(
                &s,
                t_last + Duration::from_millis(100),
                t_last + Duration::from_millis(400),
            );
            if before > 0.0 {
                dips.push((before - during) / before * 100.0);
            }
            bench_out!(
                "cycle {cycle}: closed={}/{want} before={before:.0} during={during:.0} after={after:.0} rt/s",
                got.len()
            );
        }

        tokio::time::sleep(Duration::from_millis(700)).await; // recovery -> isolated events
    }

    ctx.stop.store(true, Ordering::Relaxed);
    sampler_stop.store(true, Ordering::Relaxed);
    let _ = sampler.await;

    Report {
        lats,
        spreads,
        dips,
        expected_closes,
    }
}

fn pct(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    sorted[((sorted.len() as f64 * p) as usize).min(sorted.len() - 1)]
}

fn mean(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        0.0
    } else {
        xs.iter().sum::<f64>() / xs.len() as f64
    }
}

fn std_dev(xs: &[f64]) -> f64 {
    if xs.len() < 2 {
        return 0.0;
    }
    let m = mean(xs);
    (xs.iter().map(|x| (x - m).powi(2)).sum::<f64>() / (xs.len() - 1) as f64).sqrt()
}

fn current_fd_soft_limit() -> libc::rlim_t {
    unsafe {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) == 0 {
            lim.rlim_cur
        } else {
            0
        }
    }
}

fn main() {
    let params = parse_env();
    bench_out!(
        "effective open-file (RLIMIT_NOFILE) soft limit: {}",
        current_fd_soft_limit()
    );
    let manager = setup_netns_test!(TestMode::Shared);

    let setup_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (ctx, _manager, _handles) = setup_rt
        .block_on(setup(manager, params))
        .expect("real-stack CRL bench setup failed");
    drop(setup_rt);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut report = rt.block_on(run_cycles(ctx));

    report.lats.sort_unstable();
    let spread_mean = mean(
        &report
            .spreads
            .iter()
            .map(|d| d.as_secs_f64() * 1e3)
            .collect::<Vec<_>>(),
    );

    bench_out!("=== CRL reload data-plane impact (real HBONE, netns) ===");
    bench_out!(
        "direction={}  streams/tunnel={}  healthy_tunnels={}  victims/cycle={VICTIMS_PER_CYCLE}  cycles={}",
        params.direction.name(),
        params.streams,
        params.healthy,
        params.cycles,
    );
    bench_out!(
        "blast radius: {} of {} expected connections closed ({} per revoked identity)",
        report.lats.len(),
        report.expected_closes,
        params.streams,
    );
    bench_out!(
        "reload->close latency (CRL write -> connection closed; includes the ~2s watcher debounce):"
    );
    bench_out!(
        "  p50={:.2?}  p99={:.2?}  max={:.2?}   (n={})",
        pct(&report.lats, 0.50),
        pct(&report.lats, 0.99),
        report.lats.last().copied().unwrap_or(Duration::ZERO),
        report.lats.len(),
    );
    bench_out!(
        "  per-cycle teardown spread (herd drain, debounce-independent): mean={spread_mean:.2} ms"
    );
    bench_out!(
        "healthy HBONE throughput dip during teardown: mean={:.1}% +/- {:.1}%  (over {} cycles)",
        mean(&report.dips),
        std_dev(&report.dips),
        report.dips.len(),
    );
    bench_out!(
        "(a dip within +/- its std, or <~noise, means reloads do not measurably disrupt the data plane)"
    );
}
