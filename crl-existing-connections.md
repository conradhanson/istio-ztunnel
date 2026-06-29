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

**Not yet done:**

- **Strategy B** wiring, so A vs B can be benchmarked.
- **The benchmarks themselves** (synthetic connection load; memory + CPU; scan-all vs IA-bucketed
  vs cuckoo).
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
