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

use std::sync::Arc;

use rustls::CommonState;
use tokio::sync::watch;

use crate::identity::Identity;
use crate::proxy::Metrics;
use crate::proxy::metrics::Reporter;
use crate::tls::CertId;
use crate::tls::crl::CrlManager;

/// Per-connection CRL revocation enforcement for an HBONE connection, shared by both directions:
///
/// - inbound server ([`super::server::serve_connection`]) checks the peer (client) chain
/// - outbound client connection driver ([`super::client::drive_connection`]) checks the upstream server chain
/// - in both cases, on revocation the connection's serving task tears the connection down abruptly
///   (a security event), attributing the termination as `CERT_REVOKED` in the access log
pub struct ConnectionRevocation {
    crl_manager: Arc<CrlManager>,
    metrics: Arc<Metrics>,
    /// `(issuer, serial)` of each cert in the peer chain — all we keep to enforce revocation.
    ids: Vec<CertId>,
    crl_rx: watch::Receiver<u64>,
    /// Peer identity (client cert inbound, server cert outbound), retained only so a revocation
    /// termination is attributable in logs.
    peer_identity: Option<Identity>,
    /// Flipped to `true` when this connection's cert is revoked, so the per-connection serving
    /// future(s) resolve to `Error::CertificateRevoked` and the access log attributes the
    /// termination. Receivers are obtained via [`Self::subscribe_revoked`].
    revoked_tx: watch::Sender<bool>,
}

impl ConnectionRevocation {
    /// Captures the peer chain's `(issuer, serial)` identities and identity from the established TLS
    /// connection and subscribes to CRL updates. Call before the `TlsStream` is moved into the
    /// connection driver. `conn` is the rustls connection state — `&ServerConnection` (inbound) or
    /// `&ClientConnection` (outbound) both deref-coerce to [`CommonState`].
    pub fn new(
        conn_state: &CommonState,
        crl_manager: Arc<CrlManager>,
        metrics: Arc<Metrics>,
    ) -> Box<Self> {
        let ids = conn_state
            .peer_certificates()
            .map(crate::tls::chain_cert_ids)
            .unwrap_or_default();
        let peer_identity = crate::tls::identity_from_connection(conn_state);
        let crl_rx = crl_manager.subscribe();
        let (revoked_tx, _) = watch::channel(false);
        Box::new(Self {
            crl_manager,
            metrics,
            ids,
            crl_rx,
            peer_identity,
            revoked_tx,
        })
    }

    /// A receiver for this connection's revocation signal
    pub fn subscribe_revoked(&self) -> watch::Receiver<bool> {
        self.revoked_tx.subscribe()
    }

    /// Records the revocation as a security event and returns the peer identity string for logging:
    /// bumps the rejection metric with the caller's reporter direction (`destination` inbound,
    /// `source` outbound) and signals the serving future(s) — done *before* the caller tears the
    /// connection down, so the signal wins the attribution race against the generic teardown error.
    pub fn record_revocation(&self, reporter: Reporter) -> String {
        self.metrics.record_crl_rejection(reporter);
        let _ = self.revoked_tx.send(true);
        self.peer_identity
            .as_ref()
            .map_or_else(|| "<unknown>".to_string(), |id| id.to_string())
    }
}

/// Resolves only when a CRL update actually revokes a cert in this connection's chain.
/// CRL reloads that don't affect this chain are ignored (keep waiting),
/// so the connection is torn down strictly on revocation.
/// With no CRL configured (`None`), or once the watcher's sender is gone, it never resolves —
/// so the corresponding `select!` arm stays dormant rather than busy-looping.
pub async fn wait_for_revocation(state: Option<&mut Box<ConnectionRevocation>>) {
    match state {
        None => std::future::pending().await,
        Some(s) => loop {
            if s.crl_manager.any_revoked(&s.ids) {
                return;
            }
            if s.crl_rx.changed().await.is_err() {
                // Sender dropped (shutdown); never resolve again.
                std::future::pending::<()>().await;
            }
        },
    }
}
