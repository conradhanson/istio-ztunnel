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
memory/CPU trade-offs that only measurement will settle. The plan was therefore:

> Build a shared foundation, implement each candidate behind it, and **benchmark them head-to-head**
> (memory + CPU, watching for any O(n²) behavior) so we can pick the most performant approach with
> data rather than intuition.

**Update:** axis 1 below (Strategy A vs B) was ultimately settled directly rather than via the
planned head-to-head benchmark — reusing the exact webpki validation flow already used for new
connections was judged more valuable than the CPU savings of a bespoke membership check, so
**Strategy B is now the sole, committed implementation** and Strategy A's code (the separate
`x509_parser`-based `(issuer, serial)` membership set) has been removed. Axis 2 (which connections
to re-evaluate on a CRL update) is unaffected by this and remains an open, benchmarked question.

### The decision axes

**1. How a flagged connection is finally judged (and therefore what we cache per connection):**

- **Strategy A — minimal `(issuer, serial)` membership check.** Retain only each chain cert's
  issuer + serial (tens of bytes/conn). On a CRL update, check membership against a CRL's revoked
  `(issuer, serial)` set built by a separate `x509_parser` pass over the CRL. Cheapest option, but
  duplicates revocation-matching logic outside of webpki (a second parser, a second definition of
  "revoked") instead of reusing the handshake-time verifier. **(Implemented, then removed in favor
  of Strategy B — see status below.)**
- **Strategy B — full webpki re-validation.** Cache the peer's chain (leaf + intermediates, DER
  bytes) and re-run the shared [`verify_cert_chain`](../src/tls/verifier.rs) path — the same
  function inbound/outbound handshakes use — against it on every CRL update, treating only a
  `CertificateError::Revoked` result as revocation. Higher per-check CPU cost (full chain
  path-building + signature verification vs. a hashmap lookup) and higher per-connection memory
  (the DER-encoded chain vs. two short byte vectors), but there is exactly one implementation of
  "is this chain valid, including revocation" in the codebase — no risk of the two parsers
  disagreeing. **(Implemented — this is now production. See status below.)**

A practical constraint shaped both: once the TLS stream is consumed by the h2 handshake, the live
peer chain is no longer retrievable, so *something* must be captured at handshake time. Strategy B
captures the DER-encoded chain (`Vec<CertificateDer<'static>>`) instead of Strategy A's derived
`(issuer, serial)` pairs.

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

- **Existing-connection re-checks verify at the connection's *handshake time*, not the wall clock.**
  `ConnectionRevocation` captures `established: UnixTime` (≈ handshake time) and passes it as the
  verification "now" to `verify_cert_chain` on every re-check, rather than `UnixTime::now()`. The
  chain was already proven valid at handshake, so the only thing a later CRL reload can newly change
  is revocation status — pinning to handshake time makes that literally true, and `is_revoked_at`
  treats *only* `CertificateError::Revoked` as a teardown trigger. This is not just a nicety: an
  HBONE session can outlive its peer's cert lifetime (the TLS session persists across the workload's
  cert rotation), so a wall-clock re-check of a now-expired chain returns `CertExpired` — masking any
  revocation and letting a **revoked-but-expired** cert escape existing-connection enforcement
  entirely. Strategy A's `(issuer, serial)` membership check had no validity dependency, so it never
  had this gap; Strategy B has to pin the time to match that behavior. (Surfaced concretely by
  `benches/crl_reload_real.rs`: the namespaced harness issues **10-second** certs, so every reload
  cycle after the first ~10s re-checked an expired chain and observed zero closes until this fix.)
  Guarded by a regression assertion in the `revocation` unit tests.
- **Gotcha: webpki checks the *first* authoritative CRL per issuer, not a union of same-issuer
  CRLs.** `rustls-webpki`'s `RevocationOptions::check` does
  `self.crls.iter().find(|crl| crl.authoritative(path))` — if multiple `CertRevocationList`s in the
  list are authoritative for the same issuer, only the first one is ever consulted; the others are
  silently ignored for that issuer. This differs from Strategy A's old `CrlManager::any_revoked`,
  which manually unioned every same-issuer block's revoked-serial set. It's a non-issue for real CRL
  distribution (an issuer publishes one current, cumulative CRL, replaced wholesale on update — not
  several simultaneous partial CRLs), but it bit `benches/crl_reload_real.rs`'s `run_cycles`, which
  used to build each reload's CRL file by concatenating a fresh single-entry CRL per revoked victim
  (relying on Strategy A's union behavior); under Strategy B only the first cycle's block was ever
  checked, so later cycles silently stopped closing connections. Fixed by generating one cumulative
  CRL per reload (`tls::mock::crl_pem_revoking_certs`) instead. Any future test/benchmark that
  revokes multiple same-issuer certs across separate reloads needs the same cumulative-CRL approach.
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

## Memory & CPU footprint (per-tunnel, Strategy B)

Each open HBONE tunnel — inbound or outbound — carries exactly one `ConnectionRevocation`
(a `Box<Self>`), so the memory this workstream adds is **O(open tunnels)**, not O(streams): one
tunnel multiplexes up to `pool_max_streams_per_conn`=100 streams behind a *single* revocation
object. Per-tunnel breakdown (x86-64, struct sizes **measured** via `size_of`, DER length measured
from a generated ECDSA P-256 SPIFFE workload leaf):

| Component | Cost | Notes |
|---|---|---|
| `Box<ConnectionRevocation>` inline | **128 B** (one heap alloc) | 3 `Arc` ptrs (`CrlManager`, `Metrics`, `RootCertStore`) = 24 B, `Vec` header for `chain` = 24 B, `KeyUsage` = 24 B, `watch::Receiver<u64>` = 16 B, `Option<Identity>` = 24 B (niche-packed 3×`ArcStr`), `watch::Sender<bool>` = 8 B, `UnixTime` (`established`) = 8 B |
| `chain: Vec<CertificateDer<'static>>` contents | **~640 B** (leaf-only) → **~1.4 KB** (leaf+intermediate) | **dominant cost, and the main change from Strategy A**: the full DER-encoded peer chain, not derived `(issuer, serial)` pairs. One measured leaf = **615 B** DER + 24 B `Vec` slot; a leaf+IA chain adds a second ~700 B CA cert. Re-verification needs the actual chain to re-run `verify_cert_chain` |
| per-tunnel `revoked_tx` watch channel | ~120–150 B | fresh `Shared<bool>` (RwLock + atomics + `Notify`) allocated by `watch::channel(false)` |
| `peer_identity` strings | ~50–90 B | three `ArcStr` (trust domain / namespace / service account) **freshly parsed** from the peer's SAN by `identity_from_connection` — small owned allocations, retained only for log attribution (not interned refcount bumps) |

**Total ≈ 0.9–1.0 KB/tunnel (leaf-only) to ~1.7 KB/tunnel (leaf+intermediate)** → ~9–10 MB @
10k tunnels, ~48 MB @ 50k tunnels (leaf-only); ~17 MB / ~85 MB (leaf+intermediate). This is roughly
**2–3× Strategy A's ~0.4–0.6 KB/tunnel**, driven almost entirely by caching real DER bytes
(615 B/leaf) instead of derived `(issuer, serial)` identifiers — an accepted tradeoff for reusing the
exact webpki path rather than a second, bespoke revocation check.

CPU cost per re-evaluation also went up: a wakeup now re-runs `verify_cert_chain` (webpki path
building + one signature verification per cert in the chain) instead of a hashmap lookup, i.e. from
O(chain length) hash lookups to O(chain length) cryptographic operations. `benches/crl.rs`
(`crl_evaluate`/`crl_check`) measures this directly with real, chain-buildable certificates; its N
sweep was scaled down from Strategy A's (1k–100k) to (100–5k) because the per-call cost is now
orders of magnitude higher, and `crl_build`'s CRL-parsing cost is unaffected (there's no longer a
second, `x509_parser`-based membership set to build alongside it, so reload is actually cheaper than
under Strategy A).

What does **not** scale per-tunnel: `crl_manager`/`metrics`/`roots` are shared `Arc`s (pointer
copies), and `crl_rx` subscribes to the **single** global `CrlManager` watch channel — a refcount
bump plus the 16 inline bytes, no per-tunnel allocation.

Two framing points:

- **It's net-new but not dominant.** There was no per-tunnel revocation object before this
  workstream, and the cost is genuinely linear in open tunnels — but each tunnel's rustls session
  (send buffer up to `max_send_buffer_size`=256 KB, deframer/receive buffers, key material) plus h2
  state is tens of KB, so `ConnectionRevocation` is well under ~10% of per-tunnel state even at the
  higher Strategy B cost.
- **Per-tunnel (not per-stream) is the efficient choice.** At full multiplexing the amortized cost
  is a few tens of bytes/stream; the rejected H2Stream-level design would have been up to ~100×
  this.

Of the fields, only `chain` is enforcement-critical heap; `peer_identity` exists purely for log
attribution and the `revoked_tx`/`crl_rx` plumbing purely for the revocation signal.

---

## Current status

**Done (inbound + outbound, Strategy B):**

- Shared foundation: CRL change notification + per-connection revocation signal.
- Inbound existing-connection enforcement: on a CRL update, an open connection whose peer (client)
  cert is revoked is abruptly terminated (h2 GOAWAY).
- Outbound existing-connection enforcement: each pooled HBONE tunnel's connection driver
  (`drive_connection`) captures the upstream server's DER-encoded chain at handshake, subscribes to
  CRL updates, and abruptly tears the tunnel down (drops the client `Connection`, resetting
  in-flight streams) if the server cert is revoked. Covers both the pooled single-HBONE path and the
  double-HBONE inner tunnel, since both route through `h2::client::spawn_connection`. Same
  per-connection self-check pattern as inbound (no central cert cache).
- **Existing-connection re-checks now reuse the exact webpki validation flow used at handshake
  time** (`verifier::verify_cert_chain`), instead of a separate `(issuer, serial)` membership check.
  `ConnectionRevocation` caches the peer's DER-encoded chain plus the trust anchors (`RootCertStore`)
  and `KeyUsage` (`client_auth` inbound, `server_auth` outbound) the handshake-time verifier used for
  this peer, and re-runs the shared verifier on every CRL update, treating only a
  `CertificateError::Revoked` result as revocation (other errors, e.g. the chain aging past expiry
  while the connection stayed open, are out of scope for this check — same policy as before). The
  call sites (`inbound.rs`, `pool.rs`, `outbound.rs`) pass the local workload's trust anchors
  (`WorkloadCertificate::root_store()`), reusing the already-fetched certificate at the two outbound
  sites and fetching it once more (cheap: cached, no network round trip in the steady state) at the
  inbound site where it wasn't otherwise in scope. The prior `(issuer, serial)` membership machinery
  (`CertId`, `chain_cert_ids`, `CrlManager::any_revoked`, and the separate `x509_parser`-based
  revoked-set built alongside the webpki `CertRevocationList`s in `reload_crl_data`) has been
  removed — there is now exactly one code path that decides "is this chain valid, including
  revocation," used by both new and existing connections.
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
  `crl_build` (parse a CRL and construct the pre-parsed webpki `CertRevocationList`s, swept over R
  and M), `crl_evaluate` (re-verify N tracked connections' cached chains against a freshly loaded
  CRL, swept over N, for `leaf` and `ia` revocation), and `crl_check` (a single re-verification
  call for `leaf`/`ia` shapes). Sweeps use `Throughput::Elements` so per-element time exposes any
  super-linear behavior. Originally written against Strategy A (`any_revoked`, a
  `RevocationStrategy`/`ScanAll` comparison seam, N swept 1k→100k) and rewritten for Strategy B once
  it became the sole implementation: real, chain-buildable certificates instead of synthetic
  issuer/serial bytes, and a smaller N sweep (100–5k) since a full chain verification costs orders
  of magnitude more per call than the old hashmap lookup did.

  **Measured Strategy B results (confirm linear scaling, no super-linearity):**
  - `crl_evaluate` — **linear in N (open connections), flat per-connection**: `leaf` ~32.6 µs/conn
    across N=100 (3.25 ms) → 1k (32.7 ms) → 5k (163 ms), throughput pinned at ~30.7 Kelem/s. `ia`
    (chain length 2) ~33.2 µs/conn, equally flat. **Issuer count barely matters**: `ia_m8` ≈ `ia_m1`
    (33.4 vs 33.2 µs/conn) — webpki's O(M) "find authoritative CRL" scan is cheap byte comparisons
    dwarfed by the signature verify at these M.
  - `crl_check` — per check ~**32–33 µs, dominated by the ECDSA chain signature verification** and
    **independent of revoked-set size**: `leaf_hit` (32.7 µs) ≈ `leaf_miss` (32.6 µs) against a
    **10k-entry** revoked set, because the per-cert serial lookup is webpki's `BTreeMap::get`
    (O(log R)) and is invisible next to the crypto. The intermediate adds only ~0.7 µs (`ia_hit`
    33.3 µs).
  - `crl_build` — **linear in total revoked entries** (1k→159 µs, 10k→1.6 ms, 100k→16.5 ms, flat
    ~6.2 Melem/s) and **linear in issuer count** (64→256 issuers is 4×→4×).
  - **Scaling classes:** re-evaluate-all-on-reload is **O(N)** connections × ~constant per check;
    the per-check inner cost is constant crypto + O(log R) serial lookup (negligible) + O(M)
    authoritative-CRL scan (weak); build is O(R×M). Same **linear class** as Strategy A but with a
    ~1000× larger constant (32 µs signature-verify vs a ~tens-of-ns hashmap lookup) — and the O(N)
    CPU fans out across the decentralized per-connection tasks rather than serializing, which is why
    Phase-2's wall-clock latency stays debounce-dominated. The weak-but-real O(M) per-check scan is
    what axis-2 IA-bucketing would target once issuer cardinality reaches the hundreds–thousands a
    cross-cluster mesh can hit.

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

  **Note:** all Phase-2 numbers above were captured while Strategy A was production. The teardown
  *mechanism* they measure (racing self-check, GOAWAY/tunnel-drop, blast radius = streams/tunnel) is
  unchanged by the move to Strategy B — only how a single check is judged changed, from a hashmap
  lookup to a full webpki chain verification. Since close latency was shown to be dominated by the
  ~2.3 s file-watch debounce (not the check itself), these conclusions should still hold, but they
  have not been re-measured under Strategy B; see **Not yet done** below.

**Not yet done:**

- **Re-run the Phase-2 real-stack benchmark under Strategy B** to confirm the debounce-dominated
  close-latency conclusion still holds now that each wakeup's check is a full chain verification
  rather than a hashmap lookup (expected to be negligible next to the ~2.3 s debounce, but not
  re-measured).
- **Other candidate structures for axis 2** (which connections to re-evaluate): scan-all is still
  what's implemented; IA-bucketed and cuckoo-filter pre-filtering remain unbenchmarked candidates,
  valuable specifically because of the multi-cluster, many-IA reality (see axis 2 above). Axis 1
  (Strategy A vs B) is closed, so `benches/crl.rs` no longer carries a `RevocationStrategy`
  comparison seam — it now benchmarks the single committed Strategy B implementation directly (real,
  chain-buildable certificates instead of synthetic issuer/serial bytes); a seam for axis-2
  candidates would need to be (re)built alongside whichever data structure is prototyped first.
- **Phase-2 extensions**: intermediate-CA (IA) revocation validation once the harness issues
  root→IA→leaf chains; higher real-stack connection counts if feasible.
- **Intermediate-CA test scenarios** (workload-cert revoked by its signing IA; IA revoked by the
  root). These require extending the test harness to issue root→IA→leaf chains, which it does not
  do today.

---

## Roadmap

1. Inbound, Strategy A — **done, then superseded by Strategy B (step 3).**
2. Outbound existing-connection teardown + attribution, Strategy A — **done, then superseded by
   Strategy B (step 3).** Both directions share a consistent pattern: capture chain/identity at
   handshake → subscribe to CRL → self-check in the per-connection driver's `select!` loop → abrupt
   close on revocation → directional `crl_rejection` metric → `CERT_REVOKED` access-log attribution.
3. **Done.** Commit to Strategy B directly (reuse the shared `verify_cert_chain` webpki path for
   existing-connection re-checks, same as new connections) and remove Strategy A's code
   (`CertId`/`chain_cert_ids`/`CrlManager::any_revoked`/the separate `x509_parser` revoked-set).
   `benches/crl.rs` was rewritten to measure the committed implementation (real certificate chains)
   rather than compare candidates.
4. Extend the harness for intermediate-CA chains and add the IA/root revocation scenarios.
5. Benchmark axis-2 candidates (scan-all vs IA-bucketed vs cuckoo) for finding which connections to
   re-evaluate on a CRL update, and commit to the winner.
