# Benchmarks

This folder provides Rust benchmarks.

## Running

```shell
$ cargo bench # Just run benchmarks
$ cargo bench -- --quick # Just run benchmarks, with less samples
$ cargo bench -- --profile-time 10 # run benchmarks with cpu profile; results will be in out/rust/criterion/<group>/<test>/profile/profile.pb
$ # Compare to a baseline
$ cargo bench -- --save-baseline <name> # save baseline
$ # ...change something...
$ cargo bench -- --baseline <name> # compare against it
```

### CRL revocation re-evaluation (`crl`)

[`crl.rs`](./crl.rs) benchmarks the CPU of re-evaluating existing connections when a CRL is
(re)loaded — building the revoked set, scanning N tracked connections (swept over connection count
N and issuer count M, for both leaf- and IA-cert revocation), and a single membership check. The
sweep groups report **time per element** (`Throughput::Elements`), so a flat per-element time across
the sweep means linear scaling and a rising one flags super-linear (O(n²)) behavior.

```shell
$ cargo bench --bench crl                      # full run
$ cargo bench --bench crl -- --quick           # fast pass
$ cargo bench --bench crl -- --save-baseline scan-all   # freeze the current impl as the baseline
$ # ...implement an alternative strategy...
$ cargo bench --bench crl -- --baseline scan-all        # compare a candidate against it
```

The `RevocationStrategy` trait in `crl.rs` is the comparison seam: alternative designs (IA-bucketed,
cuckoo, full webpki re-validation) implement it and run the identical sweeps.

### CRL revocation data-plane impact (`crl_reload`)

[`crl_reload.rs`](./crl_reload.rs) is a custom async harness (not criterion — it measures
distributions and a throughput time-series, not a repeated scalar) for the *systemic* behavior when
a CRL reload fires: the thundering-herd wakeup of every watcher, the latency until revoked
connections close, and whether that storm starves active traffic. It runs mechanism-level (in-memory
duplex pipes, no TLS/h2/sudo): `H` busy "healthy" connections generate measured throughput while `V`
idle "victim" connections park in the (inlined) `wait_for_revocation` loop and all close on reload.

```shell
$ cargo bench --bench crl_reload   # prints a report table; no arguments
```

Each row reports, per scenario × V: close latency `p50/p99/max` across the victims, and healthy
throughput before/during/after the reload with the `dip%`. It fires `load_crl()` directly (skipping
the 2s file-watch debounce). Numbers are single-run and indicative — expect a few % run-to-run
variance on the dip.

### CRL reload data-plane impact, real stack (`crl_reload_real`)

[`crl_reload_real.rs`](./crl_reload_real.rs) validates `crl_reload`'s findings against the **real
encrypted HBONE data plane** in network namespaces (like `throughput.rs` and the namespaced CRL
tests) — because the mechanism-level harness's synthetic single-event dip is too noisy to trust
(it once reported an impossible *negative* dip). **Requires root**, like the other namespaced tests.

Symmetric paired topology: each *entity* is a client workload ↔ server workload pair; the client
opens `CRL_STREAMS` connections to its server (→ one HBONE tunnel per entity). `HEALTHY_TUNNELS`
entities are never revoked and drive continuous real round-trips (measured throughput); over
`RELOAD_CYCLES` **isolated** reload events (recovery between them — not continuous churn), each event
revokes a fresh `VICTIMS_PER_CYCLE` batch of entities. It reports reload→close latency
(`p50/p99/max` + debounce-independent teardown spread), the observed **blast radius** (connections
closed per revoked identity), and the healthy-throughput dip **averaged over the events (mean ± std)**.

Two axes, selected per run via env vars, cover both enforcement code paths and pooling:
- `CRL_DIRECTION=inbound` (default) — server ztunnel holds the CRL, revokes client certs, tears down
  via server GOAWAY. `outbound` — client ztunnel holds the CRL, revokes server certs, drops the
  pooled client tunnel.
- `CRL_STREAMS=N` (default 1) — connections multiplexed per tunnel. `>1` exercises per-tunnel
  enforcement amortized over many streams, the teardown blast radius, and `CERT_REVOKED` attribution
  across streams (ztunnel pools same-`(src_id,dst_id,dst,src)` connections over one tunnel, up to
  `pool_max_streams_per_conn`=100, with one `ConnectionRevocation` per tunnel).

Every line this bench prints is tagged `[crl-bench]`, so results are greppable even when captured
interleaved with ztunnel's telemetry. The bench raises its own `RLIMIT_NOFILE` at startup (a shell
`ulimit -n` does **not** survive `sudo`), and prints the effective limit — no manual `ulimit` needed.

Scale knobs are runtime env vars (no recompile): `CRL_DIRECTION` (`inbound`/`outbound`),
`CRL_STREAMS` (streams/tunnel, near 100 = the real ceiling), `CRL_HEALTHY` (measured tunnels), and
`CRL_CYCLES` (reload events = dip samples). Entity count (`CRL_HEALTHY` + `CRL_CYCLES`) is the
expensive axis — raise it as far as the machine sustains for statistical relevance.

```shell
# Sweep the matrix near ztunnel's real multiplex ceiling (1 vs ~90 streams/tunnel), with a large
# healthy baseline and many reload events. Tune CRL_HEALTHY/CRL_CYCLES down if resources bite.
$ for dir in inbound outbound; do for s in 1 90; do \
    sudo -E CRL_DIRECTION=$dir CRL_STREAMS=$s CRL_HEALTHY=32 CRL_CYCLES=15 env "PATH=$PATH" \
      cargo bench --bench crl_reload_real 2>&1 | grep '\[crl-bench\]'; done; done
```

If the printed `RLIMIT_NOFILE` limit is still low (the hard-limit raise can be blocked by
`/proc/sys/fs/nr_open`), raise that ceiling once: `sudo sysctl -w fs.nr_open=1048576`.

Leaf/workload-cert revocation only (no intermediate CAs in the harness yet), and real-netns scale is
far below `crl_reload`'s sweep — so this is **definitive at realistic connection counts** and
complements, rather than replaces, the mechanism-level large-N exploration.

## Performance

Ztunnel performance largely falls into throughput and latency.
While these are sometimes at odds with each other, as Ztunnel is a generic proxy, we aim to make it perform well on both metrics.

### Request flows

The primary responsibility of the proxy is copying bits between peers.
Currently, this is always either `TCP<-->TCP` or `TCP<-->HBONE`.

#### `TCP` to `TCP`

This is the simplest case, and common amongst many proxies.
[`copy.rs`](../src/copy.rs) does the bulk of the work, essentially just bi-directionally copying bytes between the two sockets.

Typical bi-di copies are using a fixed buffer.
To adapt to various workloads, we use dynamically sized buffers, that can grow from 1kb -> 16kb -> 256kb when enough traffic is received.
This allows high throughput workloads to perform well, without excessive memory costs for low-bandwidth services.

#### `TCP` to `HBONE`

This case ends up being much more complex, as we flow through HTTP2 and TLS.
The full flow looks as such (pseudocode):

```raw
copy_bidi():
    loop {
        data = tcp_in.read(up to 256k) # based on dynamic buffer size
        h2.write(data)
    }
h2::write(data):
    Buffer data as a DATA frame, up to a max of `max_send_buffer_size`. We configure this to 256k.
    Asyncronously, the connection driver will pick up this data and call `rustls.write_vectored([256bytes, rest of data])`.
rustls::write(data):
    data=encrypt(data)
    # TLS records are at most 16k
    # In practice I have observed at most 4 chunks; unclear where this is configured.
    tcp_out.write_vectored([chunks of 16k])
```

From an `iperf` load, this ends up looking something like this in `strace`:

```raw
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 55.21    0.841290           5    140711           writev
 44.78    0.682359          17     38481           recvfrom
 ```

This will be from `writev([16kb * 4])` calls and `recvfrom(256kb)`.

#### `HBONE` to `TCP`

This flow is substantially different from the inverse direction.
The receive flow is driven by `h2`. Under the hood this uses a [`LengthDelimitedCodec`](https://docs.rs/tokio-util/latest/tokio_util/codec/length_delimited/struct.LengthDelimitedCodec.html).
`h2` will attempt to decode 1 frame at a time, using an internal buffer.
This buffer starts at [`8kb`](https://github.com/tokio-rs/tokio/blob/ed4ddf443d93c3e14ae23699a5a2f81902ad1e66/tokio-util/src/codec/framed_impl.rs#L26) but will grow to meet the size of frames.
We allow up to a max of `1mb` frame sizes (`config.frame_size`).

Ultimately, this will call `rustls.read(buf)`.
This goes through a few indirections, but ultimately ends up in `rustls.deframer_buffer`.
This is what calls `read()` on the underlying IO, in our case the TCP connection.
This buffer is configured to do [`4kb`](https://github.com/rustls/rustls/blob/8a8023addb9ae311f66b16e272e85654c9588eeb/rustls/src/msgs/deframer.rs#L724) reads generally.

Upon reading the frame from the wire, these get [buffered up by `h2`](https://github.com/hyperium/h2/blob/4617f49b266d560a773372a90be283ba8b2400a9/src/proto/streams/stream.rs#L100).
We read these in [`recv_stream.poll_data`](../src/proxy/h2.rs), trigger by the `copy_bidirectional`.
Ultimately, this will write out 1 DATA frame worth of data to the upstream TCP connection

From an `iperf` load, this ends up looking something like this in `strace`:

```raw
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 61.08    1.253541          50     24703           sendto
 38.19    0.783733           2    360707         8 recvfrom
```

This will be from `sendto(256kb)` calls, with many `recvfrom()` calls ranging from 4k to 16k.

#### Comparison to Envoy

Under an `iperf` load, Envoy client:

```raw
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 68.24    1.363149           3    440440         1 sendto
 31.72    0.633584          11     55114        31 readv
```

This is from many `sendto(16k)` calls, and `readv([16k]*8)`.

Envoy Server:

```raw
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 65.24    1.199264           1    757275         8 recvfrom
 34.73    0.638315          26     23670           writev
```

This is from many calls of `recvfrom(5); recvfrom(16k)`, and `writev([16k]*16)`.

(All strace commands are looking at `-e trace=write,writev,read,recvfrom,sendto,readv`).
