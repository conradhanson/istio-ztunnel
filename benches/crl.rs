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

//! Phase-1 benchmarks for CRL enforcement on existing connections.
//!
//! These measure the **CPU of revocation re-evaluation** — the work done when a CRL is (re)loaded.
//! There are three benchmark groups:
//!
//! - `crl_build` — parse a CRL and build the revoked `(issuer, serial)` set, swept over revoked-entry count R and issuer count M.
//! - `crl_evaluate` — re-evaluate N tracked connections against a freshly loaded CRL (baseline = scan-all: one `any_revoked` per connection), swept over N and M, for a `leaf` revocation (one cert, ~1 hit) and an `ia` revocation (one issuer, ~N/M hits, L=2 chains).
//! - `crl_check` — a single `any_revoked` call, to confirm it is O(chain length) and independent of the revoked-set size R.
//!
//! O(n²) detection: the sweep groups use `Throughput::Elements`, so criterion reports **time per
//! element**. A flat per-element time across N (or R) ⇒ linear; a rising one ⇒ super-linear.
//! Compare candidate implementations with `--save-baseline` / `--baseline` (see benches/README.md).
//!
//! The `RevocationStrategy` trait is the comparison seam: the current production design is
//! `ScanAll`; future candidates (IA-bucketed, cuckoo, full webpki re-validation) implement the same
//! trait and run the identical sweeps.

mod profiler;

use std::io::Write;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use profiler::{Output, PProfProfiler};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DistinguishedName,
    DnType, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    RevocationReason, RevokedCertParams, SerialNumber,
};
use tempfile::NamedTempFile;
use time::{Duration as TimeDuration, OffsetDateTime};
use ztunnel::tls::CertId;
use ztunnel::tls::crl::CrlManager;

// ---------------------------------------------------------------------------
// Comparison seam: every candidate revocation strategy implements this trait.
// ---------------------------------------------------------------------------

/// A strategy for finding which of the tracked connections must be closed on a CRL (re)load.
trait RevocationStrategy {
    /// Index the given connections (each is the captured `(issuer, serial)` chain of one connection).
    fn build(conns: Vec<Vec<CertId>>) -> Self
    where
        Self: Sized;
    /// On a CRL (re)load, return how many tracked connections are now revoked (and must be closed).
    fn on_reload(&self, crl: &CrlManager) -> usize;
}

/// The current production baseline: no central index — each connection self-checks via
/// `CrlManager::any_revoked`. Modeled here as the aggregate scan over all tracked connections.
struct ScanAll {
    conns: Vec<Vec<CertId>>,
}

impl RevocationStrategy for ScanAll {
    fn build(conns: Vec<Vec<CertId>>) -> Self {
        Self { conns }
    }
    fn on_reload(&self, crl: &CrlManager) -> usize {
        self.conns
            .iter()
            .filter(|chain| crl.any_revoked(chain))
            .count()
    }
}

// ---------------------------------------------------------------------------
// CRL / workload generation.
//
// We generate CRLs with rcgen and derive the matching CertIds by parsing those CRLs with
// x509-parser — i.e. the exact `(issuer.as_raw(), raw_serial())` bytes that CrlManager itself
// stores in its revoked set. This guarantees hits match without generating a leaf cert per
// connection, and keeps the encoding identical to the production path.
// ---------------------------------------------------------------------------

/// One issuer's parsed CRL material: its DER-encoded issuer Name, and the raw serials it revokes.
struct IssuerCrl {
    issuer: Vec<u8>,
    revoked: Vec<Vec<u8>>,
}

/// A serial that we never revoke, so a `(issuer, MISS_SERIAL)` lookup is a guaranteed miss.
const MISS_SERIAL: [u8; 19] = [0xAA; 19];
/// An issuer DER that is never a real CRL issuer key, so lookups for it miss at the first hop.
const SYNTHETIC_ISSUER: [u8; 4] = [0x30, 0x00, 0x00, 0x00];

fn make_ca(idx: usize) -> (KeyPair, CertificateParams) {
    let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("ca key");
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "cluster.local");
    dn.push(DnType::CommonName, format!("ca-{idx}"));
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    (kp, params)
}

/// Build a CRL for one issuer revoking `serials`, returning its PEM (for the on-disk CRL file the
/// CrlManager loads) and its DER (for deriving the exact revoked-set bytes via x509-parser).
fn build_crl(kp: &KeyPair, params: &CertificateParams, serials: &[Vec<u8>]) -> (String, Vec<u8>) {
    let now = OffsetDateTime::now_utc();
    let revoked_certs = serials
        .iter()
        .map(|s| RevokedCertParams {
            serial_number: SerialNumber::from_slice(s),
            revocation_time: now,
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        })
        .collect();
    let crl_params = CertificateRevocationListParams {
        this_update: now,
        next_update: now + TimeDuration::days(30),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::Sha256,
    };
    let issuer = Issuer::from_params(params, kp);
    let crl = crl_params.signed_by(&issuer).expect("sign CRL");
    (crl.pem().expect("CRL PEM"), crl.der().to_vec())
}

/// Parse a CRL's DER into the exact `(issuer, [serial])` bytes CrlManager stores for it.
fn parse_crl(der: &[u8]) -> IssuerCrl {
    let (_, crl) = x509_parser::parse_x509_crl(der).expect("parse CRL");
    IssuerCrl {
        issuer: crl.issuer().as_raw().to_vec(),
        revoked: crl
            .iter_revoked_certificates()
            .map(|rc| rc.raw_serial().to_vec())
            .collect(),
    }
}

/// Generate a CRL file covering `m` issuers, each revoking `revoked_per_issuer` serials, load it
/// into a `CrlManager`, and return the manager plus the parsed per-issuer material. The temp file
/// is returned so the caller keeps it alive for the duration of the benchmark.
fn gen_crl(m: usize, revoked_per_issuer: usize) -> (CrlManager, NamedTempFile, Vec<IssuerCrl>) {
    let mut pem = String::new();
    let mut issuers = Vec::with_capacity(m);
    for idx in 0..m {
        let (kp, params) = make_ca(idx);
        let serials: Vec<Vec<u8>> = (0..revoked_per_issuer)
            .map(|s| (((idx as u64) << 32) | (s as u64 + 1)).to_be_bytes().to_vec())
            .collect();
        let (crl_pem, crl_der) = build_crl(&kp, &params, &serials);
        pem.push_str(&crl_pem);
        issuers.push(parse_crl(&crl_der));
    }
    let mut file = NamedTempFile::new().expect("temp file");
    file.write_all(pem.as_bytes()).expect("write CRL");
    file.flush().expect("flush CRL");
    let crl = CrlManager::new(file.path().to_path_buf()).expect("load CRL");
    (crl, file, issuers)
}

/// Just the on-disk CRL file (for the build benchmark, which times `CrlManager::new`).
fn gen_crl_file(m: usize, revoked_per_issuer: usize) -> NamedTempFile {
    let mut pem = String::new();
    for idx in 0..m {
        let (kp, params) = make_ca(idx);
        let serials: Vec<Vec<u8>> = (0..revoked_per_issuer)
            .map(|s| (((idx as u64) << 32) | (s as u64 + 1)).to_be_bytes().to_vec())
            .collect();
        let (crl_pem, _) = build_crl(&kp, &params, &serials);
        pem.push_str(&crl_pem);
    }
    let mut file = NamedTempFile::new().expect("temp file");
    file.write_all(pem.as_bytes()).expect("write CRL");
    file.flush().expect("flush CRL");
    file
}

/// `leaf` revocation: N single-cert (L=1) chains spread across M issuers; exactly one is revoked.
fn leaf_conns(n: usize, issuers: &[IssuerCrl]) -> Vec<Vec<CertId>> {
    let m = issuers.len();
    (0..n)
        .map(|i| {
            let iss = &issuers[i % m];
            let serial = if i == 0 {
                iss.revoked[0].clone() // the single revoked leaf
            } else {
                MISS_SERIAL.to_vec()
            };
            vec![CertId {
                issuer: iss.issuer.clone(),
                serial,
            }]
        })
        .collect()
}

/// `ia` revocation: N two-cert (L=2: leaf + issuing-CA) chains across M issuers; one issuer is
/// revoked, so the ~N/M connections under it are hit on the upstream (issuer) position.
fn ia_conns(n: usize, issuers: &[IssuerCrl]) -> Vec<Vec<CertId>> {
    let m = issuers.len();
    (0..n)
        .map(|i| {
            let ia = i % m;
            let iss = &issuers[ia];
            // leaf position: always a miss (issuer not a CRL key) — models chain length L=2.
            let leaf = CertId {
                issuer: SYNTHETIC_ISSUER.to_vec(),
                serial: MISS_SERIAL.to_vec(),
            };
            // CA position: hit only for the one revoked issuer (ia == 0).
            let ca = CertId {
                issuer: iss.issuer.clone(),
                serial: if ia == 0 {
                    iss.revoked[0].clone()
                } else {
                    MISS_SERIAL.to_vec()
                },
            };
            vec![leaf, ca]
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Benchmarks.
// ---------------------------------------------------------------------------

/// Build cost: parse a CRL and construct the revoked set. Swept over R (revoked entries) at M=1,
/// and over M (issuers) at a fixed per-issuer count. Time-per-element should stay flat (linear).
fn crl_build(c: &mut Criterion) {
    let mut g = c.benchmark_group("crl_build");
    g.measurement_time(Duration::from_secs(5));

    // Sweep R at a single issuer.
    for &r in &[1_000usize, 10_000, 100_000] {
        let file = gen_crl_file(1, r);
        g.throughput(Throughput::Elements(r as u64));
        g.bench_with_input(BenchmarkId::new("entries_m1", r), &file, |b, file| {
            b.iter(|| CrlManager::new(std::hint::black_box(file.path().to_path_buf())).unwrap())
        });
    }

    // Sweep M (issuers) with a small fixed per-issuer revoked count.
    for &m in &[1usize, 64, 256] {
        let file = gen_crl_file(m, 16);
        g.throughput(Throughput::Elements((m * 16) as u64));
        g.bench_with_input(BenchmarkId::new("issuers_r16", m), &file, |b, file| {
            b.iter(|| CrlManager::new(std::hint::black_box(file.path().to_path_buf())).unwrap())
        });
    }
    g.finish();
}

/// Re-evaluation cost: scan N tracked connections against a freshly loaded CRL. Swept over N and M
/// for both revocation scenarios. `Throughput::Elements(N)` ⇒ time-per-connection; flat = linear.
fn crl_evaluate(c: &mut Criterion) {
    let mut g = c.benchmark_group("crl_evaluate");
    g.measurement_time(Duration::from_secs(5));

    type Builder = fn(usize, &[IssuerCrl]) -> Vec<Vec<CertId>>;
    let scenarios: [(&str, Builder); 2] = [("leaf", leaf_conns), ("ia", ia_conns)];

    for (scenario, build_conns) in scenarios {
        for &m in &[1usize, 64] {
            // A small revoked set per issuer — the scan cost is about N and chain length, not R.
            let (crl, _file, issuers) = gen_crl(m, 4);
            for &n in &[1_000usize, 10_000, 100_000] {
                let strat = ScanAll::build(build_conns(n, &issuers));
                g.throughput(Throughput::Elements(n as u64));
                g.bench_with_input(
                    BenchmarkId::new(format!("{scenario}_m{m}"), n),
                    &n,
                    |b, _| b.iter(|| std::hint::black_box(strat.on_reload(&crl))),
                );
            }
        }
    }
    g.finish();
}

/// Single-check cost: confirm `any_revoked` is O(chain length) and independent of revoked-set size.
fn crl_check(c: &mut Criterion) {
    let mut g = c.benchmark_group("crl_check");
    g.measurement_time(Duration::from_secs(3));

    // A non-trivial revoked set, to show the single-check cost does not grow with it.
    let (crl, _file, issuers) = gen_crl(1, 10_000);
    let iss = &issuers[0];

    let hit_l1 = vec![CertId {
        issuer: iss.issuer.clone(),
        serial: iss.revoked[0].clone(),
    }];
    let miss_l1 = vec![CertId {
        issuer: iss.issuer.clone(),
        serial: MISS_SERIAL.to_vec(),
    }];
    let miss_l3 = vec![
        CertId {
            issuer: SYNTHETIC_ISSUER.to_vec(),
            serial: MISS_SERIAL.to_vec(),
        },
        CertId {
            issuer: SYNTHETIC_ISSUER.to_vec(),
            serial: MISS_SERIAL.to_vec(),
        },
        CertId {
            issuer: iss.issuer.clone(),
            serial: MISS_SERIAL.to_vec(),
        },
    ];

    g.bench_function("hit_l1", |b| {
        b.iter(|| std::hint::black_box(crl.any_revoked(&hit_l1)))
    });
    g.bench_function("miss_l1", |b| {
        b.iter(|| std::hint::black_box(crl.any_revoked(&miss_l1)))
    });
    g.bench_function("miss_l3", |b| {
        b.iter(|| std::hint::black_box(crl.any_revoked(&miss_l3)))
    });
    g.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .with_profiler(PProfProfiler::new(100, Output::Protobuf))
        .warm_up_time(Duration::from_millis(500));
    targets = crl_build, crl_evaluate, crl_check
}

criterion_main!(benches);
