# CRL Enforcement on Existing Connections — Plan & Status

This document tracks the plan and current state of the final piece of the CRL (Certificate
Revocation List) enforcement EPIC for ztunnel: enforcing revocation on **connections that are
already open** when a CRL is updated. It is a companion to [`kickoff-meeting-summary.md`](./kickoff-meeting-summary.md).

It intentionally documents *the approach and where we are*, not every code change.

---

## Background

CRL enforcement has three layers:

1. **New connections** — the cert chain is validated (incl. revocation) at connection-open time.
   Already shipped.
2. **A prerequisite migration** — inbound certificate validation was migrated from rustls's
   built-in verifier to a shared `rustls-webpki` path, so inbound and outbound now use the **same
   verifier**. This aligned the two directions and made CRL apply to *new* connections immediately
   at update time (removing a prior ~12h cert-rotation window).
3. **Existing connections** *(this workstream)* — when a CRL is updated, connections that are
   already open must be re-evaluated and torn down if a cert in their chain is now revoked.

Both **inbound** and **outbound** are in scope.

---

## Goals & constraints

- **No false negatives.** A revoked connection must never be missed. False *positives* (extra
  re-checks) are acceptable — they cost work, not security.
- **Reuse existing correctness guarantees** rather than reimplementing revocation logic where
  practical.
- **Termination is a security event** → connections are torn down **abruptly** (not gracefully
  drained); a revoked peer's in-flight traffic should not be allowed to complete.
- **Cert/revocation logic is separate from RBAC/authz logic** — they are different concerns at
  different granularities and must not be entangled.
- **Scale.** A single ztunnel can hold tens of thousands+ of connections. In multi/cross-cluster
  meshes it also sees **many distinct issuing CAs (IAs)** — potentially hundreds to thousands, one
  (or more) per cluster — so the issuer dimension is high-cardinality, not a single bucket.

---

## The plan: phased implementation **and** benchmarking

No single data structure / approach was pre-selected. The kickoff explicitly called for
**benchmarking with synthetic load** before committing, because each candidate has different
memory/CPU trade-offs that only measurement will settle. The plan is therefore:

> Build a shared foundation, implement each candidate behind it, and **benchmark them head-to-head**
> (memory + CPU, watching for any O(n²) behavior) so we can pick the most performant approach with
> data rather than intuition.

### The decision axes being benchmarked

**1. How a flagged connection is finally judged (and therefore what we cache per connection):**

- **Strategy A — minimal `(issuer, serial)` membership check.** Retain only each chain cert's
  issuer + serial (tens of bytes/conn). On a CRL update, check membership against the CRL's revoked
  `(issuer, serial)` set. This is also the *correct minimal* check: for an already-validated chain,
  the only thing a CRL update can change is revocation status. **(Implemented — see status below.)**
- **Strategy B — full webpki re-validation.** Cache more and re-run the shared `verify_cert_chain`
  path. Honors "reuse the webpki code path," at higher memory/CPU cost. **(To be implemented for the
  benchmark.)**

A practical constraint shaped this: once the TLS stream is consumed by the h2 handshake, the live
peer chain is no longer retrievable, so *something* must be captured at handshake time. Strategy A
keeps that footprint minimal.

**2. How we find *which* connections to re-evaluate on a CRL update:**

- **Scan-all (baseline)** — iterate all tracked connections, gated by a cheap per-connection
  membership check before any expensive work.
- **Issuer/IA-bucketed (tree/"trie")** — group connections by issuing CA. A CRL update is
  per-issuer, so this narrows the scan to the affected cluster's bucket, and an IA revocation
  becomes a bulk drop. Valuable specifically because of the **multi-cluster, many-IA** reality.
- **Cuckoo-filter pre-filter** — a probabilistic "definitely-not / maybe" gate to skip work
  entirely. (Analysis so far suggests an exact issuer-keyed structure dominates it for this
  workload; the benchmark will confirm or refute.)

The benchmark is what decides between these — including whether the simplest option is already fast
enough at our scale.

---

## Key design decisions made so far

- **Per-connection self-check, not a central cache.** Each inbound connection's serving task watches
  for CRL updates and re-checks its own peer cert; there is no central map of every connection's
  cert chain (which would be the dominant memory cost at scale).
- **Abrupt termination via h2 GOAWAY** on the server (inbound) side when a peer cert is revoked.
- **Kept out of the RBAC `ConnectionManager` internals.** Revocation is tracked/triggered
  separately from RBAC connection tracking (different granularity: RBAC is per-stream-context,
  revocation is per-TLS-connection).
- **CRL file watch → reload → notify.** The `CrlManager` notifies subscribers on every successful
  (re)load so open connections can be re-evaluated promptly.
- **Access-log attribution follows the RBAC late-rejection precedent.** A revoked connection's
  serving future resolves to a dedicated `Error::CertificateRevoked`, which the existing
  access-log/metrics path maps to a `CERT_REVOKED` response flag via the same inference mechanism
  RBAC late-rejection uses — i.e. no special-case conditionals, one shared `handle_connection!`
  termination path with symmetric RBAC and CRL arms.
- **Attribution is a `biased` race, signal set before teardown.** Both directions race the data
  future against the shared `await_revocation(rx)` helper; the `select!` is `biased` with the
  revocation arm first. This is what makes attribution deterministic rather than timing-dependent:
  the driver flips the revocation signal *before* it tears the connection down (the act that makes
  the data future fail with a generic reset), so the revocation arm always wins the race when a
  teardown is due to revocation. The receiver lives on the tunnel handle (`H2ConnectClient`),
  surfaced from the pool checkout — **not** on the byte-stream `H2Stream`.
- **Per-connection memory cost of attribution is negligible.** Each active connection holds one
  `watch::Receiver<bool>` (~16 bytes; a refcount bump on the tunnel's shared watch state, **no**
  per-connection heap allocation), and the shared state is one small allocation per tunnel (few).
  Keeping the receiver off `H2Stream` means inbound server streams pay nothing for it. At any scale
  this is dwarfed (<0.1%) by each connection's h2 flow-control/window buffers (KB–MB). We chose the
  racing receiver over a post-hoc `Arc<AtomicBool>` check (which would shave the receiver but
  reintroduce the attribution race) — the determinism is worth the ~16 bytes.

---

## Memory footprint (per-tunnel, Strategy A)

Each open HBONE tunnel — inbound or outbound — carries exactly one `ConnectionRevocation`
(a `Box<Self>`), so the memory this workstream adds is **O(open tunnels)**, not O(streams): one
tunnel multiplexes up to `pool_max_streams_per_conn`=100 streams behind a *single* revocation
object. Per-tunnel breakdown (x86-64):

| Component | Cost | Notes |
|---|---|---|
| `Box<ConnectionRevocation>` inline | ~88 B (→ ~96 B allocated) | two `Arc` ptrs to shared globals (`CrlManager`, `Metrics`), `Vec` header, `watch::Receiver<u64>` (16 B), `Option<Identity>` (3×`ArcStr` = 24 B), `watch::Sender<bool>` (8 B) |
| `ids: Vec<CertId>` contents | ~135 B (leaf-only) → ~270 B (leaf+IA) | **dominant cost**; each `CertId` = two `Vec<u8>` (48 B) + issuer DER (~50–80 B) + raw serial (~16–20 B) |
| per-tunnel `revoked_tx` watch channel | ~120–150 B | fresh `Shared<bool>` (RwLock + atomics + `Notify`) allocated by `watch::channel(false)` |
| `peer_identity` strings | ~0 marginal | the three `ArcStr` are refcount bumps of live workload identities, not new allocations |

**Total ≈ 0.4 KB/tunnel (leaf-only) to ~0.5–0.6 KB/tunnel (leaf+intermediate)** → ~5 MB @ 10k
tunnels, ~25 MB @ 50k tunnels.

What does **not** scale per-tunnel: `crl_manager`/`metrics` are shared `Arc`s (pointer copies), and
`crl_rx` subscribes to the **single** global `CrlManager` watch channel — a refcount bump plus the
16 inline bytes, no per-tunnel allocation.

Two framing points:

- **It's net-new but not dominant.** There was no per-tunnel revocation object before this
  workstream, and the cost is genuinely linear in open tunnels — but each tunnel's rustls session
  (send buffer up to `max_send_buffer_size`=256 KB, deframer/receive buffers, key material) plus h2
  state is tens of KB, so `ConnectionRevocation` is well under ~2% of per-tunnel state.
- **Per-tunnel (not per-stream) is the efficient choice.** At full multiplexing the amortized cost
  is ~5 bytes/stream; the rejected H2Stream-level design would have been up to ~100× this.

Of the fields, only `ids` is enforcement-critical heap; `peer_identity` exists purely for log
attribution and the `revoked_tx`/`crl_rx` plumbing purely for the revocation signal.

---

## Current status

**Done (inbound + outbound, Strategy A):**

- Shared foundation: CRL change notification + per-connection revocation signal.
- Inbound existing-connection enforcement: on a CRL update, an open connection whose peer (client)
  cert is revoked is abruptly terminated (h2 GOAWAY).
- Outbound existing-connection enforcement: each pooled HBONE tunnel's connection driver
  (`drive_connection`) captures the upstream server chain's `(issuer, serial)` at handshake,
  subscribes to CRL updates, and abruptly tears the tunnel down (drops the client `Connection`,
  resetting in-flight streams) if the server cert is revoked. Covers both the pooled single-HBONE
  path and the double-HBONE inner tunnel, since both route through `h2::client::spawn_connection`.
  Same per-connection self-check pattern as inbound (no central cert cache).
- Observability: a log attributing the termination (with peer identity), a directional CRL
  rejection metric (`reporter=destination` inbound, `reporter=source` outbound), and per-connection
  access-log attribution (`CERT_REVOKED`) in **both** directions via the shared
  `extract_failure_reason` path. The attribution mechanism is unified: each direction **races its
  data future against the shared `await_revocation(rx)` helper**, and the revocation arm resolves to
  `Error::CertificateRevoked`. The race is `biased` with the revocation arm first, which makes
  attribution deterministic — the driver sets the revocation signal *before* tearing the connection
  down (the thing that makes the data future fail with a generic reset), so the revocation arm
  always wins when a teardown is due to revocation. Inbound races inside `handle_connection!` (which
  also races the RBAC drain); outbound races in an inline `select!` at the record site. The
  revocation `watch::Receiver` lives on the tunnel handle (`H2ConnectClient`), surfaced from the
  pool checkout — not on the byte-stream `H2Stream`. Double-HBONE races **both** the outer (E/W
  gateway) and inner (final destination) tunnel signals, so a revocation at either hop is surfaced.
- Two namespaced integration tests (one per direction): establish a connection, do a successful
  request, revoke the relevant cert mid-connection via a CRL file update, assert the connection is
  torn down and the metric increments.
- **Phase-1 benchmarks** (`benches/crl.rs`, criterion): the CPU of revocation re-evaluation —
  `crl_build` (parse + build revoked set, swept over R and M), `crl_evaluate` (re-evaluate N
  tracked connections, swept over N × M, for `leaf` and `ia` revocation), and `crl_check` (single
  `any_revoked`). Sweeps use `Throughput::Elements` so per-element time exposes any super-linear
  behavior; a `RevocationStrategy` trait (baseline = `ScanAll`) is the comparison seam for future
  candidates via `--save-baseline`/`--baseline`. Baseline results confirm **linear** scaling
  (~flat per-connection time across N=1k→100k), the expected leaf-vs-IA (L=1 vs L=2) cost gap, and
  that `any_revoked` is O(chain length), independent of revoked-set size.

- **Phase-2 benchmark** (`benches/crl_reload.rs`, custom async harness): the data-plane impact of a
  reload. `H` busy "healthy" connections generate measured throughput while `V` idle "victim"
  connections park in the (inlined) `wait_for_revocation` loop and all close on reload. Reports
  reload→close latency (p50/p99/max) and healthy-throughput dip, swept over V for `leaf`/`ia`.
  Mechanism-level (in-memory pipes, no TLS/h2/sudo). Baseline findings:
  - **Close-latency tail is linear in V** (no O(n²)): ~p99 48 ms @ 10k, ~226 ms @ 50k victims.
  - **Throughput dip is small (~5–7%) even at 50k victims and fully recovers** afterward — the
    decentralized thundering-herd wakeup is tolerable at these scales.
  - **`leaf` revocation closed slower than `ia`** (e.g. p50 121 ms vs 91 ms @ 50k) because `leaf`
    ships a large CRL (V entries), and `reload_crl_data` used to hold the `inner` **write lock across
    the whole parse+build**, so victims that woke and called `any_revoked` blocked on the read lock
    for the build duration.

- **Phase-2 real-stack validation** (`benches/crl_reload_real.rs`, netns, **root required**): the
  same data-plane questions on the **real encrypted HBONE stack** (built on `throughput.rs`'s
  harness + the namespaced CRL mechanics), because the mechanism-level harness's synthetic
  single-event dip proved too noisy to trust (it reported an impossible negative dip). Healthy
  HBONE connections carry continuous real traffic while **repeated isolated reload events** (with
  recovery between — deliberately *not* continuous churn, which measures an unrealistic workload)
  each revoke a fresh batch of victim workloads. Reports reload→close latency (p50/p99/max + a
  debounce-independent teardown spread) and the healthy-throughput dip **averaged over the events
  (mean ± std)**. Leaf/workload-cert revocation only (harness has no intermediate CAs yet), and
  real-netns scale is far below the mechanism-level sweep — so it's definitive at realistic
  connection counts and complements, rather than replaces, `crl_reload.rs`. **Now parameterized over
  both enforcement code paths and pooling** (`CRL_DIRECTION=inbound|outbound`, `CRL_STREAMS=N`),
  using a symmetric paired topology (each entity = client↔server workload pair; the client opens
  `CRL_STREAMS` connections → one tunnel per entity) so the directions are directly comparable. This
  covers what earlier runs missed: the outbound path (client drops the pooled tunnel vs server
  GOAWAY) and **multiplexing** — one `ConnectionRevocation` per *tunnel* shared by up to 100 streams,
  so `CRL_STREAMS>1` exercises per-tunnel amortization, the teardown **blast radius** (one revocation
  closes all the tunnel's streams), and `CERT_REVOKED` attribution across those streams.

  **Initial results — inbound, single-stream** (8 healthy, 8 events × 5 victims):
  - **Throughput dip is statistically zero** — mean 2.5% ± 6.0% over 8 events, with 3/8 events
    showing *negative* (impossible) dips → the swings are noise; healthy HBONE throughput is
    unaffected by reloads at realistic scale. (The mechanism-level harness couldn't tell us this from
    a single sample; 8 isolated events make the ±6% noise band explicit.)
  - **Close latency is tight and debounce-dominated:** p50/p99/max all 2.29–2.30s (n=40). The ~2s is
    the file-watcher debounce; reload-apply + detect + GOAWAY + client-observes adds only ~290ms and
    is uniform. **The 2s watch debounce is the dominant, tunable latency knob.**
  - **Herd drain trivial at scale:** all 5 victims per batch close within 0.29 ms of each other.
  - Real-stack access logs confirmed the `CERT_REVOKED` inbound attribution end-to-end.

  **Matrix results** (`{inbound, outbound} × {1, 15} streams`, 12 healthy tunnels, 5 events × 1
  victim; the bench self-raises `RLIMIT_NOFILE`):

  | direction | streams | blast radius | close p50/p99/max | teardown spread | dip mean ± std |
  |---|---|---|---|---|---|
  | inbound | 1 | 5/5 | 2.29 / 2.50 / 2.50 s | 0.00 ms | −0.4% ± 2.5% |
  | outbound | 1 | 5/5 | 2.30 / 2.30 / 2.30 s | 0.00 ms | −1.0% ± 0.6% |
  | inbound | 15 | 75/75 | 2.30 / 2.30 / 2.30 s | 0.25 ms | 6.2% ± 2.1% |
  | outbound | 15 | 75/75 | 2.29 / 2.35 / 2.35 s | 1.58 ms | 7.1% ± 1.7% |

  - **Blast radius = streams-per-tunnel, exactly** (5/5, 75/75): one `ConnectionRevocation` per
    *tunnel* handles all multiplexed streams; enforcement amortizes, teardown concentrates.
  - **Close latency ~2.3s, debounce-dominated, direction-independent** → outbound (tunnel-drop)
    enforces as promptly as inbound (GOAWAY); multiplexing doesn't slow detection.
  - **Teardown drain tiny** (≤1.6 ms even for 15 simultaneous streams); outbound a hair slower than
    inbound but immaterial.
  - **Throughput dip scales with the multiplexing factor:** at 1 stream/tunnel it's **zero**
    (−1%…−0.4%, within noise); at 15 streams/tunnel it's a **small but statistically real ~6–7%
    transient** (mean 3–4× its std; every cycle shows `before ≈ after > during` — a clean
    dip-and-recover over a ~50 ms window). It's driven by the *absolute burst of simultaneous stream
    resets* (blast radius), not the fraction of streams closed, and recovers immediately.
    Direction-independent (6.2% inbound ≈ 7.1% outbound).
  - **Measured at the near-ceiling** (`CRL_STREAMS=90`, 32 healthy tunnels, 15 events; ztunnel's
    per-tunnel multiplex limit is 100): tearing down a maxed-out 90-stream tunnel closes all **90**
    streams (1350/1350) and causes a **~15% healthy-throughput dip** (inbound 15.0% ± 9.5%, outbound
    16.2% ± 9.5%) over the ~50 ms window, with full recovery (`before ≈ after` every cycle). Close
    latency stays ~2.3 s (debounce-bound); teardown drain grows with blast radius but stays small
    (~6.5 ms inbound, ~14 ms outbound). Single-stream is within noise (−0.2% / 5.2%).
    **So the dip scales with blast radius: ~0% (1 stream) → ~6–7% (15) → ~15% (90).** Even the worst
    case — revoking a ceiling-multiplexed tunnel — is a brief, self-recovering blip during a rare
    event; the design holds at production multiplex scale. (The wide ±9.5% std reflects netns timing
    noise: the effect's existence and blast-radius scaling are firm, its precise magnitude less so.)
    Scale knobs are env-driven (`CRL_HEALTHY`, `CRL_CYCLES`, `CRL_STREAMS`, `CRL_DIRECTION`).

  **Fuller stream sweep** (`{inbound, outbound} × {30, 60, 90}` streams, 32 healthy tunnels, 15
  events × 1 victim) — samples the gap between the 15- and 90-stream points densely enough to show
  the dip scales **monotonically** with blast radius rather than in steps:

  | direction | streams | blast radius | close p50/p99/max | teardown spread | dip mean ± std |
  |---|---|---|---|---|---|
  | inbound | 30 | 420/450\* | 2.29 / 2.31 / 2.31 s | 0.30 ms | 6.6% ± 4.8% |
  | inbound | 60 | 900/900 | 2.30 / 2.37 / 2.37 s | 2.85 ms | 10.3% ± 6.9% |
  | inbound | 90 | 1350/1350 | 2.29 / 2.35 / 2.35 s | 6.55 ms | 15.0% ± 9.5% |
  | outbound | 30 | 450/450 | 2.29 / 2.30 / 2.30 s | 3.15 ms | 4.6% ± 3.5% |
  | outbound | 60 | 900/900 | 2.29 / 2.35 / 2.35 s | 9.35 ms | 12.8% ± 6.0% |
  | outbound | 90 | 1350/1350 | 2.29 / 2.30 / 2.31 s | 13.98 ms | 16.2% ± 9.5% |

  \* One inbound-30 cycle saw no closes (reload not applied — a file-watch/debounce miss), so
  420/450 and dip averaged over 14 cycles; the other five rows closed 100% of expected connections.

  - **Dip grows monotonically with streams/tunnel (blast radius):** ~5–7% @ 30 → ~10–13% @ 60 →
    ~15–16% @ 90, roughly linear in the per-tunnel stream count and consistent across both
    directions. Same effect the 1/15/90 matrix showed, now sampled densely enough to read as a
    smooth curve. The 90-stream row reproduces the near-ceiling numbers above (15.0% / 16.2%) exactly.
  - **Teardown spread also grows with blast radius but stays small** (≤14 ms even at 90 simultaneous
    stream resets); outbound (tunnel-drop) drains consistently a few ms slower than inbound (GOAWAY),
    immaterial next to the ~2.3 s debounce.
  - **Close latency stays ~2.3 s, debounce-dominated and direction-independent** across the sweep.
  - Recovery is immediate every cycle (`before ≈ after > during`) — a brief, self-recovering blip
    during a rare event even when revoking a near-ceiling-multiplexed tunnel.

**Not yet done:**

- **Strategy B** wiring, so A vs B can be benchmarked.
- **Analytical memory/space estimate** for Strategy B (Strategy A is done — see
  [Memory footprint](#memory-footprint-per-tunnel-strategy-a) above; ~0.4–0.6 KB/tunnel).
- **Other candidate structures** under the Phase-1 benches (IA-bucketed, cuckoo, full webpki
  re-validation) once built.
- **Phase-2 extensions**: intermediate-CA (IA) revocation validation once the harness issues
  root→IA→leaf chains; higher real-stack connection counts if feasible.
- **Intermediate-CA test scenarios** (workload-cert revoked by its signing IA; IA revoked by the
  root). These require extending the test harness to issue root→IA→leaf chains, which it does not
  do today.

---

## Roadmap

1. Inbound, Strategy A — **done**.
2. Outbound existing-connection teardown + attribution, Strategy A — **done**. Both directions now
   share a consistent pattern: capture minimal `(issuer, serial)` at handshake → subscribe to CRL →
   self-check in the per-connection driver's `select!` loop → abrupt close on revocation →
   directional `crl_rejection` metric → `CERT_REVOKED` access-log attribution.
3. Wire Strategy B and run the A-vs-B benchmark; benchmark the find-which-connections data
   structures (scan-all vs IA-bucketed vs cuckoo) under synthetic load.
4. Extend the harness for intermediate-CA chains and add the IA/root revocation scenarios.
5. Commit to the benchmarked winner; remove the also-rans.
