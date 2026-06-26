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

use crate::config;
use crate::drain::DrainWatcher;
use crate::proxy::Error;
use bytes::Bytes;
use futures_util::FutureExt;
use http::Response;
use http::request::Parts;
use std::fmt::Debug;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, watch};
use tracing::{Instrument, debug};

pub struct H2Request {
    request: Parts,
    recv: h2::RecvStream,
    send: h2::server::SendResponse<Bytes>,
}

impl Debug for H2Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Request")
            .field("request", &self.request)
            .finish()
    }
}

impl H2Request {
    pub fn send_error(mut self, resp: Response<()>) -> Result<(), Error> {
        let _ = self.send.send_response(resp, true)?;
        Ok(())
    }

    pub async fn send_response(
        self,
        resp: Response<()>,
    ) -> Result<crate::proxy::h2::H2Stream, Error> {
        let H2Request { recv, mut send, .. } = self;
        let send = send.send_response(resp, false)?;
        let read = crate::proxy::h2::H2StreamReadHalf {
            recv_stream: recv,
            _dropped: None, // We do not need to track on the server
        };
        let write = crate::proxy::h2::H2StreamWriteHalf {
            send_stream: send,
            _dropped: None, // We do not need to track on the server
        };
        let h2 = crate::proxy::h2::H2Stream { read, write };
        Ok(h2)
    }

    pub fn get_request(&self) -> &Parts {
        &self.request
    }

    pub fn headers(&self) -> &http::HeaderMap<http::HeaderValue> {
        self.request.headers()
    }
}

pub trait RequestParts {
    fn uri(&self) -> &http::Uri;
    fn method(&self) -> &http::Method;
    fn headers(&self) -> &http::HeaderMap<http::HeaderValue>;
}

impl RequestParts for Parts {
    fn uri(&self) -> &http::Uri {
        &self.uri
    }

    fn method(&self) -> &http::Method {
        &self.method
    }

    fn headers(&self) -> &http::HeaderMap<http::HeaderValue> {
        &self.headers
    }
}

/// Per-connection CRL revocation enforcement for an inbound HBONE connection.
/// When present, [`serve_connection`] re-checks the peer's certificate identities against the CRL
/// on every CRL update and abruptly shuts the connection down (via GOAWAY) if any cert is revoked.
///
/// Boxed by the caller and held off to the side so it adds only a pointer to the (size-sensitive)
/// `serve_connection` future — it is cold state, touched only on a CRL update.
pub struct ConnectionRevocation {
    crl_manager: Arc<crate::tls::crl::CrlManager>,
    metrics: Arc<crate::proxy::Metrics>,
    /// `(issuer, serial)` of each cert in the peer chain — all we keep to enforce revocation.
    ids: Vec<crate::tls::CertId>,
    crl_rx: watch::Receiver<u64>,
    /// Peer (client) identity, retained only so a revocation termination is attributable in logs.
    peer_identity: Option<crate::identity::Identity>,
    /// Flipped to `true` when this connection's cert is revoked, so the per-stream serving futures
    /// resolve to `Error::CertificateRevoked` and the access log attributes the termination.
    revoked_tx: watch::Sender<bool>,
}

impl ConnectionRevocation {
    /// Captures the peer chain's `(issuer, serial)` identities from the accepted TLS stream and
    /// subscribes to CRL updates. Returns boxed state to keep the serve future small. Call this
    /// before `s` is moved into [`serve_connection`]. `revoked_tx` is shared with this connection's
    /// per-stream futures (its receivers) for access-log attribution.
    pub fn new(
        s: &tokio_rustls::server::TlsStream<TcpStream>,
        crl_manager: Arc<crate::tls::crl::CrlManager>,
        metrics: Arc<crate::proxy::Metrics>,
        peer_identity: Option<crate::identity::Identity>,
        revoked_tx: watch::Sender<bool>,
    ) -> Box<Self> {
        let ids = s
            .get_ref()
            .1
            .peer_certificates()
            .map(crate::tls::chain_cert_ids)
            .unwrap_or_default();
        let crl_rx = crl_manager.subscribe();
        Box::new(Self {
            crl_manager,
            metrics,
            ids,
            crl_rx,
            peer_identity,
            revoked_tx,
        })
    }
}

/// Awaits the next CRL reload. Resolves only when the CRL set was successfully reloaded. With no
/// CRL configured (`None`), or once the watcher's sender is gone, it never resolves — so the
/// corresponding `select!` arm stays dormant rather than busy-looping.
async fn wait_for_crl_change(state: Option<&mut Box<ConnectionRevocation>>) {
    match state {
        Some(s) => {
            if s.crl_rx.changed().await.is_err() {
                // Sender dropped (shutdown); never resolve again.
                std::future::pending::<()>().await
            }
        }
        None => std::future::pending().await,
    }
}

pub async fn serve_connection<F, Fut>(
    cfg: Arc<config::Config>,
    s: tokio_rustls::server::TlsStream<TcpStream>,
    drain: DrainWatcher,
    mut force_shutdown: watch::Receiver<()>,
    mut revocation: Option<Box<ConnectionRevocation>>,
    handler: F,
) -> Result<(), Error>
where
    F: Fn(H2Request) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut builder = h2::server::Builder::new();
    let mut conn = builder
        .initial_window_size(cfg.window_size)
        .initial_connection_window_size(cfg.connection_window_size)
        .max_frame_size(cfg.frame_size)
        // 64KB max; default is 16MB driven from Golang's defaults
        // Since we know we are going to receive a bounded set of headers, more is overkill.
        .max_header_list_size(65536)
        // 400kb, default from hyper
        .max_send_buffer_size(1024 * 400)
        // default from hyper
        .max_concurrent_streams(200)
        .handshake(s)
        .await?;

    let ping_pong = conn
        .ping_pong()
        .expect("new connection should have ping_pong");
    // for ping to inform this fn to drop the connection
    let (ping_drop_tx, mut ping_drop_rx) = oneshot::channel::<()>();
    // for this fn to inform ping to give up when it is already dropped
    let dropped = Arc::new(AtomicBool::new(false));
    tokio::task::spawn(crate::proxy::h2::do_ping_pong(
        ping_pong,
        ping_drop_tx,
        dropped.clone(),
    ));

    let handler = |req| handler(req).map(|_| ());
    loop {
        let drain = drain.clone();
        tokio::select! {
            request = conn.accept() => {
                let Some(request) = request else {
                    // done!
                    // Signal to the ping_pong it should also stop.
                    dropped.store(true, Ordering::Relaxed);
                    return Ok(());
                };
                let (request, send) = request?;
                let (request, recv) = request.into_parts();
                let req = H2Request {
                    request,
                    recv,
                    send,
                };
                let handle = handler(req);
                // Serve the stream in a new task
                tokio::task::spawn(handle.in_current_span());
            }
            _ = &mut ping_drop_rx => {
                // Ideally this would be a warning/error message. However, due to an issue during shutdown,
                // by the time pods with in-pod know to shut down, the network namespace is destroyed.
                // This blocks the ability to send a GOAWAY and gracefully shutdown.
                // See https://github.com/istio/ztunnel/issues/1191.
                debug!("HBONE ping timeout/error, peer may have shutdown");
                conn.abrupt_shutdown(h2::Reason::NO_ERROR);
                break
            }
            _shutdown = drain.wait_for_drain() => {
                debug!("starting graceful drain...");
                conn.graceful_shutdown();
                break;
            }
            // CRL update: revocation is a security event, so if any cert in this connection's peer
            // chain is now revoked we abruptly terminate (GOAWAY) rather than gracefully drain.
            _ = wait_for_crl_change(revocation.as_mut()) => {
                if let Some(rev) = revocation.as_ref()
                    && rev.crl_manager.any_revoked(&rev.ids)
                {
                    let peer = rev
                        .peer_identity
                        .as_ref()
                        .map_or_else(|| "<unknown>".to_string(), |id| id.to_string());
                    debug!(
                        %peer,
                        "terminating inbound connection: peer certificate revoked by CRL update"
                    );
                    rev.metrics
                        .record_crl_rejection(crate::proxy::metrics::Reporter::destination);
                    // Notify the per-stream serving futures first so they resolve to
                    // `CertificateRevoked` (access-log attribution) before the GOAWAY closes them.
                    let _ = rev.revoked_tx.send(true);
                    conn.abrupt_shutdown(h2::Reason::NO_ERROR); // maybe INADEQUATE_SECURITY instead?
                    break;
                }
            }
        }
    }
    // Signal to the ping_pong it should also stop.
    dropped.store(true, Ordering::Relaxed);
    let poll_closed = futures_util::future::poll_fn(move |cx| conn.poll_closed(cx));
    tokio::select! {
        _ = force_shutdown.changed() => {
            return Err(Error::DrainTimeOut)
        }
        _ = poll_closed => {}
    }
    // Mark we are done with the connection
    drop(drain);
    Ok(())
}
