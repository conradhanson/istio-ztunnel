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

//! Benchmarks for CRL enforcement on existing connections.
//!
//! Existing-connection revocation re-runs the same shared webpki chain-validation path used at
//! handshake time (`verify_cert_chain`) against each connection's cached peer chain whenever the
//! CRL reloads — see `ConnectionRevocation::is_revoked` in `src/proxy/h2/revocation.rs`. Unlike a
//! plain `(issuer, serial)` membership lookup, this cost is dominated by webpki path-building and
//! signature verification, so these benchmarks use real, chain-buildable certificates throughout
//! rather than synthetic issuer/serial bytes.
//!
//! - `crl_build` — parse a CRL file and build the pre-parsed webpki `CertRevocationList`s, swept
//!   over revoked-entry count R and issuer count M. This is now the *entire* reload cost (there is
//!   no separate membership-set build anymore).
//! - `crl_evaluate` — re-verify N tracked connections' cached chains against a freshly loaded CRL,
//!   swept over N, for a `leaf` revocation (chain length 1) and an `ia` revocation (chain length 2:
//!   leaf + issuing CA, M issuing CAs, one revoked).
//! - `crl_check` — a single re-verification call for `leaf` and `ia` chain shapes, to see the fixed
//!   per-call cost independent of N.
//!
//! O(n²) detection: sweep groups use `Throughput::Elements`, so criterion reports time per element;
//! flat ⇒ linear, rising ⇒ super-linear. Compare candidate implementations with `--save-baseline` /
//! `--baseline` (see benches/README.md).

mod profiler;

use std::io::Write;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use profiler::{Output, PProfProfiler};
use rcgen::{
    CertificateRevocationListParams, DistinguishedName, DnType, Issuer, KeyIdMethod, KeyPair,
    PKCS_ECDSA_P256_SHA256, RevocationReason, RevokedCertParams, SerialNumber,
};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::{CertificateError, RootCertStore};
use tempfile::NamedTempFile;
use time::{Duration as TimeDuration, OffsetDateTime};
use webpki::KeyUsage;
use ztunnel::identity::Identity;
use ztunnel::tls::WorkloadCertificate;
use ztunnel::tls::crl::CrlManager;
use ztunnel::tls::mock::{
    TEST_ROOT, TEST_ROOT_KEY, TestIdentity, crl_pem_revoking_cert, generate_intermediate_ca,
    generate_test_certs_with_root, verify_cert_chain,
};

/// Re-runs the exact check `ConnectionRevocation::is_revoked` uses: a full webpki chain
/// verification, classifying only `CertificateError::Revoked` as "revoked".
fn is_revoked(chain: &[CertificateDer<'static>], roots: &RootCertStore, crl: &CrlManager) -> bool {
    let Some((end_entity, intermediates)) = chain.split_first() else {
        return false;
    };
    matches!(
        verify_cert_chain(
            end_entity,
            intermediates,
            roots,
            UnixTime::now(),
            KeyUsage::server_auth(),
            Some(crl),
        ),
        Err(rustls::Error::InvalidCertificate(CertificateError::Revoked))
    )
}

// ---------------------------------------------------------------------------
// CRL / workload generation.
// ---------------------------------------------------------------------------

fn test_id() -> Identity {
    Identity::from_str("spiffe://td/ns/n/sa/a").unwrap()
}

/// A workload cert (with its trust anchors) signed by `signing_key`, valid for an hour.
fn workload_signed_by(signing_key: &[u8], extra_chain: &[&[u8]]) -> WorkloadCertificate {
    let (key, cert) = generate_test_certs_with_root(
        &TestIdentity::Identity(test_id()),
        SystemTime::now(),
        SystemTime::now() + Duration::from_secs(3600),
        None,
        signing_key,
    );
    let mut chain: Vec<&[u8]> = extra_chain.to_vec();
    chain.push(TEST_ROOT);
    WorkloadCertificate::new(key.as_bytes(), cert.as_bytes(), chain).unwrap()
}

/// The DER-encoded chain (leaf + intermediates, excluding the root) — the shape
/// `ConnectionRevocation` captures from a peer's `CommonState::peer_certificates()`.
fn chain_der(wl: &WorkloadCertificate) -> Vec<CertificateDer<'static>> {
    wl.cert_and_intermediates()
        .into_iter()
        .map(|c| c.der)
        .collect()
}

/// Writes `pem` to a fresh temp file and loads it into a `CrlManager`.
fn crl_manager_for(pem: &str) -> (CrlManager, NamedTempFile) {
    let mut file = NamedTempFile::new().expect("temp file");
    file.write_all(pem.as_bytes()).expect("write CRL");
    file.flush().expect("flush CRL");
    let mgr = CrlManager::new(file.path().to_path_buf()).expect("load CRL");
    (mgr, file)
}

/// `leaf` revocation: N chains of a single (root-signed) leaf cert, all identical except one,
/// which is revoked. Chain length 1 — the cheapest real webpki verification shape.
fn leaf_scenario(n: usize) -> (Vec<Vec<CertificateDer<'static>>>, RootCertStore, CrlManager, NamedTempFile) {
    let revoked = workload_signed_by(TEST_ROOT_KEY, &[]);
    let ok = workload_signed_by(TEST_ROOT_KEY, &[]);
    let (crl, file) = crl_manager_for(&crl_pem_revoking_cert(&revoked.cert.serial_bytes()));
    let roots = ok.root_store().as_ref().clone();
    let chains = (0..n)
        .map(|i| {
            if i == 0 {
                chain_der(&revoked)
            } else {
                chain_der(&ok)
            }
        })
        .collect();
    (chains, roots, crl, file)
}

/// `ia` revocation: N chains of length 2 (leaf + issuing CA) spread across `m` issuing CAs; the
/// first issuing CA is revoked, so the ~N/m connections under it are hit.
fn ia_scenario(
    n: usize,
    m: usize,
) -> (
    Vec<Vec<CertificateDer<'static>>>,
    RootCertStore,
    CrlManager,
    NamedTempFile,
) {
    let ias: Vec<(String, String, Vec<u8>)> = (0..m)
        .map(|_| generate_intermediate_ca(TEST_ROOT_KEY))
        .collect();
    let leaves: Vec<WorkloadCertificate> = ias
        .iter()
        .map(|(ia_key, ia_cert, _)| workload_signed_by(ia_key.as_bytes(), &[ia_cert.as_bytes()]))
        .collect();
    let (crl, file) = crl_manager_for(&crl_pem_revoking_cert(&ias[0].2));
    let roots = leaves[0].root_store().as_ref().clone();
    let chains = (0..n)
        .map(|i| chain_der(&leaves[i % m]))
        .collect();
    (chains, roots, crl, file)
}

// ---------------------------------------------------------------------------
// Benchmarks.
// ---------------------------------------------------------------------------

/// Build cost: parse a CRL and construct the pre-parsed webpki `CertRevocationList`s. Swept over R
/// (revoked entries) at M=1, and over M (issuers) at a fixed per-issuer count. Time-per-element
/// should stay flat (linear).
fn crl_build(c: &mut Criterion) {
    let mut g = c.benchmark_group("crl_build");
    g.measurement_time(Duration::from_secs(5));

    fn gen_crl_file(m: usize, revoked_per_issuer: usize) -> NamedTempFile {
        let mut pem = String::new();
        for idx in 0..m {
            let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("ca key");
            let mut params = rcgen::CertificateParams::default();
            let mut dn = DistinguishedName::new();
            dn.push(DnType::OrganizationName, "cluster.local");
            dn.push(DnType::CommonName, format!("ca-{idx}"));
            params.distinguished_name = dn;
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.key_usages = vec![
                rcgen::KeyUsagePurpose::KeyCertSign,
                rcgen::KeyUsagePurpose::CrlSign,
            ];
            let now = OffsetDateTime::now_utc();
            let revoked_certs = (0..revoked_per_issuer)
                .map(|s| RevokedCertParams {
                    serial_number: SerialNumber::from(
                        ((idx as u64) << 32) | (s as u64 + 1),
                    ),
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
            let issuer = Issuer::from_params(&params, &kp);
            pem.push_str(&crl_params.signed_by(&issuer).expect("sign CRL").pem().unwrap());
        }
        let mut file = NamedTempFile::new().expect("temp file");
        file.write_all(pem.as_bytes()).expect("write CRL");
        file.flush().expect("flush CRL");
        file
    }

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

/// Re-evaluation cost: re-verify N tracked connections' chains against a freshly loaded CRL. Swept
/// over N for both scenarios. `Throughput::Elements(N)` ⇒ time-per-connection; flat = linear.
/// N is smaller than the old membership-lookup sweep since a full chain verification (path
/// building + signature checks) costs orders of magnitude more per call than a hashmap lookup.
fn crl_evaluate(c: &mut Criterion) {
    let mut g = c.benchmark_group("crl_evaluate");
    g.measurement_time(Duration::from_secs(5));
    g.sample_size(20);

    for &n in &[100usize, 1_000, 5_000] {
        let (chains, roots, crl, _file) = leaf_scenario(n);
        g.throughput(Throughput::Elements(n as u64));
        g.bench_with_input(BenchmarkId::new("leaf", n), &n, |b, _| {
            b.iter(|| {
                std::hint::black_box(
                    chains
                        .iter()
                        .filter(|chain| is_revoked(chain, &roots, &crl))
                        .count(),
                )
            })
        });
    }

    for &m in &[1usize, 8] {
        for &n in &[100usize, 1_000, 5_000] {
            let (chains, roots, crl, _file) = ia_scenario(n, m);
            g.throughput(Throughput::Elements(n as u64));
            g.bench_with_input(BenchmarkId::new(format!("ia_m{m}"), n), &n, |b, _| {
                b.iter(|| {
                    std::hint::black_box(
                        chains
                            .iter()
                            .filter(|chain| is_revoked(chain, &roots, &crl))
                            .count(),
                    )
                })
            });
        }
    }
    g.finish();
}

/// Single-check cost: the fixed per-call cost of re-verifying one connection's chain, for `leaf`
/// (chain length 1) and `ia` (chain length 2) shapes, both for a hit (revoked) and a miss.
fn crl_check(c: &mut Criterion) {
    let mut g = c.benchmark_group("crl_check");
    g.measurement_time(Duration::from_secs(3));

    let (leaf_chains, leaf_roots, leaf_crl, _leaf_file) = leaf_scenario(2);
    let (ia_chains, ia_roots, ia_crl, _ia_file) = ia_scenario(2, 1);

    g.bench_function("leaf_hit", |b| {
        b.iter(|| std::hint::black_box(is_revoked(&leaf_chains[0], &leaf_roots, &leaf_crl)))
    });
    g.bench_function("leaf_miss", |b| {
        b.iter(|| std::hint::black_box(is_revoked(&leaf_chains[1], &leaf_roots, &leaf_crl)))
    });
    g.bench_function("ia_hit", |b| {
        b.iter(|| std::hint::black_box(is_revoked(&ia_chains[0], &ia_roots, &ia_crl)))
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
