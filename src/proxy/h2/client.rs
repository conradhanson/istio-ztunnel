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

use crate::baggage::{Baggage, parse_baggage_header};
use crate::config;
use crate::identity::Identity;
use crate::proxy::{BAGGAGE_HEADER, Error};
use bytes::{Buf, Bytes};
use h2::SendStream;
use h2::client::{Connection, SendRequest};
use http::Request;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;
use tokio::sync::watch::Receiver;
use tracing::{Instrument, debug, error, info, trace, warn};

#[derive(Debug, Clone)]
// H2ConnectClient is a wrapper abstracting h2
pub struct H2ConnectClient {
    sender: SendRequest<Bytes>,
    pub max_allowed_streams: u16,
    stream_count: Arc<AtomicU16>,
    wl_key: WorkloadKey,
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct WorkloadKey {
    pub src_id: Identity,
    pub dst_id: Vec<Identity>,
    // In theory we can just use src,dst,node. However, the dst has a check that
    // the L3 destination IP matches the HBONE IP. This could be loosened to just assert they are the same identity maybe.
    pub dst: SocketAddr,
    // Because we spoof the source IP, we need to key on this as well. Note: for in-pod its already per-pod
    // pools anyways.
    pub src: IpAddr,
}

impl Display for WorkloadKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})->{}[", self.src, &self.src_id, self.dst,)?;
        for i in &self.dst_id {
            write!(f, "{i}")?;
        }
        write!(f, "]")
    }
}

impl H2ConnectClient {
    pub fn is_for_workload(&self, wl_key: &WorkloadKey) -> Result<(), crate::proxy::Error> {
        if !(self.wl_key == *wl_key) {
            Err(crate::proxy::Error::Generic(
                "connection does not match workload key!".into(),
            ))
        } else {
            Ok(())
        }
    }

    // will_be_at_max_streamcount checks if a stream will be maxed out if we send one more request on it
    pub fn will_be_at_max_streamcount(&self) -> bool {
        let future_count = self.stream_count.load(Ordering::Relaxed) + 1;
        trace!(
            "checking streamcount: {future_count} >= {}",
            self.max_allowed_streams
        );
        future_count >= self.max_allowed_streams
    }

    pub fn ready_to_use(&mut self) -> bool {
        let cx = &mut Context::from_waker(futures::task::noop_waker_ref());
        match self.sender.poll_ready(cx) {
            Poll::Ready(Ok(_)) => true,
            // We may have gotten GoAway, etc
            Poll::Ready(Err(_)) => false,
            Poll::Pending => {
                // Given our current usage, I am not sure this can ever be the case.
                // If it is, though, err on the safe side and do not use the connection
                warn!("checked out connection is Pending, skipping");
                false
            }
        }
    }

    pub async fn send_request(
        &mut self,
        req: http::Request<()>,
    ) -> Result<(crate::proxy::h2::H2Stream, Option<Baggage>), Error> {
        let cur = self.stream_count.fetch_add(1, Ordering::SeqCst);
        trace!(current_streams = cur, "sending request");
        let (send, recv, baggage) = match self.internal_send(req).await {
            Ok(r) => r,
            Err(e) => {
                // Request failed, so drop the stream now
                self.stream_count.fetch_sub(1, Ordering::SeqCst);
                return Err(e);
            }
        };

        let (dropped1, dropped2) = crate::proxy::h2::DropCounter::new(self.stream_count.clone());
        let read = crate::proxy::h2::H2StreamReadHalf {
            recv_stream: recv,
            _dropped: dropped1,
        };
        let write = crate::proxy::h2::H2StreamWriteHalf {
            send_stream: send,
            _dropped: dropped2,
        };
        let h2 = crate::proxy::h2::H2Stream { read, write };
        Ok((h2, baggage))
    }

    // helper to allow us to handle errors once
    async fn internal_send(
        &mut self,
        req: Request<()>,
    ) -> Result<(SendStream<Bytes>, h2::RecvStream, Option<Baggage>), Error> {
        // "This function must return `Ready` before `send_request` is called"
        // We should always be ready though, because we make sure we don't go over the max stream limit out of band.
        futures::future::poll_fn(|cx| self.sender.poll_ready(cx)).await?;
        let (response, stream) = self.sender.send_request(req, false)?;
        let response = response.await?;
        if response.status() != 200 {
            return Err(Error::HttpStatus(response.status()));
        }
        let baggage = parse_baggage_header(response.headers().get_all(BAGGAGE_HEADER)).ok();
        Ok((stream, response.into_body(), baggage))
    }
}

/// Per-connection CRL revocation enforcement for an outbound HBONE tunnel. When present,
/// [`drive_connection`] re-checks the upstream server's certificate identities against the CRL on
/// every CRL update and abruptly tears the tunnel down if any cert is now revoked.
///
/// This mirrors the inbound [`crate::proxy::h2::server::ConnectionRevocation`], minus the
/// per-stream attribution signal: outbound streams are multiplexed over the pool and fanned out
/// from the tunnel, so a revoked tunnel surfaces to each downstream connection as a generic stream
/// reset (the `record_crl_rejection` metric still fires). Boxed so it adds only a pointer to the
/// connection driver's state.
pub struct OutboundConnectionRevocation {
    crl_manager: Arc<crate::tls::crl::CrlManager>,
    metrics: Arc<crate::proxy::Metrics>,
    /// `(issuer, serial)` of each cert in the upstream server chain — all we keep to enforce revocation.
    ids: Vec<crate::tls::CertId>,
    crl_rx: Receiver<u64>,
    /// Upstream (server) identity, retained only so a revocation teardown is attributable in logs.
    peer_identity: Option<Identity>,
}

impl OutboundConnectionRevocation {
    /// Captures the upstream server chain's `(issuer, serial)` identities from the established TLS
    /// stream and subscribes to CRL updates. Call before `s` is moved into [`spawn_connection`].
    /// Generic over the inner IO so it serves both the pooled tunnel (`TlsStream<TcpStream>`) and
    /// the double-HBONE inner tunnel (`TlsStream<TokioH2Stream>`).
    pub fn new<IO>(
        s: &tokio_rustls::client::TlsStream<IO>,
        crl_manager: Arc<crate::tls::crl::CrlManager>,
        metrics: Arc<crate::proxy::Metrics>,
    ) -> Box<Self> {
        let (_, conn) = s.get_ref();
        let ids = conn
            .peer_certificates()
            .map(crate::tls::chain_cert_ids)
            .unwrap_or_default();
        let peer_identity = crate::tls::identity_from_connection(conn);
        let crl_rx = crl_manager.subscribe();
        Box::new(Self {
            crl_manager,
            metrics,
            ids,
            crl_rx,
            peer_identity,
        })
    }
}

/// Resolves only when a CRL update actually revokes a cert in this tunnel's upstream chain. CRL
/// reloads that don't affect this chain are ignored (we keep waiting), so the tunnel is torn down
/// strictly on revocation. With no CRL configured (`None`), or once the watcher's sender is gone,
/// it never resolves — the corresponding `select!` arm stays dormant rather than busy-looping.
async fn wait_for_crl_revocation(state: Option<&mut Box<OutboundConnectionRevocation>>) {
    match state {
        Some(s) => loop {
            if s.crl_rx.changed().await.is_err() {
                // Sender dropped (shutdown); never resolve again.
                std::future::pending::<()>().await;
            }
            if s.crl_manager.any_revoked(&s.ids) {
                return;
            }
        },
        None => std::future::pending().await,
    }
}

pub async fn spawn_connection(
    cfg: Arc<config::Config>,
    s: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    driver_drain: Receiver<bool>,
    wl_key: WorkloadKey,
    revocation: Option<Box<OutboundConnectionRevocation>>,
) -> Result<H2ConnectClient, Error> {
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(cfg.window_size)
        .initial_connection_window_size(cfg.connection_window_size)
        .max_frame_size(cfg.frame_size)
        .initial_max_send_streams(cfg.pool_max_streams_per_conn as usize)
        .max_header_list_size(1024 * 16)
        // 4mb. Aligned with window_size such that we can fill up the buffer, then flush it all in one go, without buffering up too much.
        .max_send_buffer_size(cfg.window_size as usize)
        .enable_push(false);

    let (send_req, connection) = builder
        .handshake::<_, Bytes>(s)
        .await
        .map_err(Error::Http2Handshake)?;

    // We store max as u16, so if they report above that max size we just cap at u16::MAX
    let max_allowed_streams = std::cmp::min(
        cfg.pool_max_streams_per_conn,
        connection
            .max_concurrent_send_streams()
            .try_into()
            .unwrap_or(u16::MAX),
    );
    // spawn a task to poll the connection and drive the HTTP state
    // if we got a drain for that connection, respect it in a race
    // it is important to have a drain here, or this connection will never terminate
    tokio::spawn(
        async move {
            drive_connection(connection, driver_drain, revocation).await;
        }
        .in_current_span(),
    );

    let c = H2ConnectClient {
        sender: send_req,
        stream_count: Arc::new(AtomicU16::new(0)),
        max_allowed_streams,
        wl_key,
    };
    Ok(c)
}

async fn drive_connection<S, B>(
    mut conn: Connection<S, B>,
    mut driver_drain: Receiver<bool>,
    mut revocation: Option<Box<OutboundConnectionRevocation>>,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin,
    B: Buf,
{
    let ping_pong = conn
        .ping_pong()
        .expect("ping_pong should only be called once");
    // for ping to inform this fn to drop the connection
    let (ping_drop_tx, ping_drop_rx) = oneshot::channel::<()>();
    // for this fn to inform ping to give up when it is already dropped
    let dropped = Arc::new(AtomicBool::new(false));
    tokio::task::spawn(
        super::do_ping_pong(ping_pong, ping_drop_tx, dropped.clone()).in_current_span(),
    );

    tokio::select! {
        _ = driver_drain.changed() => {
            debug!("draining outer HBONE connection");
        }
        _ = ping_drop_rx => {
            warn!("HBONE ping timeout/error");
        }
        // CRL update: revocation is a security event. When a cert in this connection's upstream cert chain is now revoked,
        //  we tear the tunnel down abruptly so any in-flight streams multiplexed over this tunnel are reset.
        _ = wait_for_crl_revocation(revocation.as_mut()) => {
            if let Some(rev) = revocation.as_ref() {
                let peer = rev
                    .peer_identity
                    .as_ref()
                    .map_or_else(|| "<unknown>".to_string(), |id| id.to_string());
                info!(
                    %peer,
                    "terminating outbound connection: upstream certificate revoked by CRL update"
                );
                rev.metrics
                    .record_crl_rejection(crate::proxy::metrics::Reporter::source);
            }
        }
        res = conn => {
            match res {
                Err(e) => {
                    error!("Error in HBONE connection handshake: {:?}", e);
                }
                Ok(_) => {
                    debug!("done with HBONE connection handshake: {:?}", res);
                }
            }
        }
    }
    // Signal to the ping_pong it should also stop.
    dropped.store(true, Ordering::Relaxed);
}
