//! HTTP/HTTPS listener: serves the router over plain TCP or TLS with HTTP/1.1 and HTTP/2.

use std::{sync::Arc, time::Duration};

use axum::{Extension, Router};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::{api::PeerAddr, net::HANDSHAKE_TIMEOUT};

/// Time a client gets to send its request headers; bounds slow-header (slowloris) attacks.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);
/// Connections one listener holds at once, and from one network (an address, an IPv6 /64).
/// At the limit a newcomer takes the oldest slot of the network group holding the most (see
/// [`crate::slots`]), so that a few networks opening idle connections cannot lock everyone out.
const MAX_CONNECTIONS: usize = 512;
const MAX_CONNECTIONS_PER_NETWORK: usize = 128;

pub async fn serve(listener: TcpListener, router: Router, tls: Option<Arc<ServerConfig>>, trusted_proxies: Vec<ipnet::IpNet>) {
    let acceptor = tls.map(TlsAcceptor::from);
    // Each listener has slots of its own: a flood on one port does not close the other
    // (port 80 also answers ACME challenges).
    let slots = crate::slots::Slots::new(MAX_CONNECTIONS, MAX_CONNECTIONS_PER_NETWORK);
    loop {
        let (tcp, mut peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::warn!(%err, "failed to accept HTTP connection");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        // On a dual-stack socket IPv4 clients appear as ::ffff:a.b.c.d.
        peer.set_ip(peer.ip().to_canonical());
        let shared = peer.ip().is_loopback() || trusted_proxies.iter().any(|net| net.contains(&peer.ip()));
        let Some(slot) = slots.take(peer.ip(), shared) else { drop(tcp); continue };
        let service = TowerToHyperService::new(router.clone().layer(Extension(PeerAddr(peer))));
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            // An evicted connection is simply dropped, mid-request or idle.
            slot.guard(async move {
                let _ = tcp.set_nodelay(true);
                let mut builder = Builder::new(TokioExecutor::new());
                builder.http1().timer(TokioTimer::new()).header_read_timeout(HEADER_READ_TIMEOUT);
                builder.http2().timer(TokioTimer::new()).keep_alive_interval(Some(Duration::from_secs(30))).max_concurrent_streams(32);
                let result = match acceptor {
                    Some(acceptor) => match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                        Ok(Ok(stream)) => builder.serve_connection_with_upgrades(TokioIo::new(stream), service).await,
                        Ok(Err(err)) => {
                            tracing::debug!(%err, %peer, "TLS handshake failed");
                            return;
                        }
                        Err(_) => return,
                    },
                    None => builder.serve_connection_with_upgrades(TokioIo::new(tcp), service).await,
                };
                if let Err(err) = result {
                    tracing::debug!(%err, %peer, "HTTP connection ended with an error");
                }
            }).await;
        });
    }
}
