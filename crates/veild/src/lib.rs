//! The VEIL server.
//!
//! Terminates QUIC connections, authenticates each peer against the store,
//! assigns tunnel addresses, and moves packets between its sessions and `tun0`.
//! Orchestration only: the privileged work lives in `veil-net`.
//!
//! Currently the control plane only. There is no tun device and no forwarding
//! yet, so this needs no capabilities.
//!
//! Exposed as a library so `veil-ctl serve` can run the server in-process; the
//! `veild` binary is a thin wrapper over [`run`].

#![forbid(unsafe_code)]

mod control;
mod session;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, ServerConfig};
use veil_common::Error;
use veil_config::{PeerFile, ServerSettings};
use veil_crypto::StaticKeypair;

use session::SessionTable;

/// Drops a peer that has gone silent. QUIC keepalives from the client hold an
/// idle session open well inside this.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Runs the server until its endpoint closes or `SIGINT` arrives.
///
/// Does not install a tracing subscriber: that belongs to whoever owns the
/// process, since `init_tracing` may only be called once.
pub async fn run(settings: ServerSettings) -> veil_common::Result<()> {
    let keypair = StaticKeypair::from_file(&settings.private_key)
        .map_err(|e| Error::Config(format!("{}: {e}", settings.private_key.display())))?;

    let peers =
        Arc::new(PeerFile::load(&settings.peers).map_err(|e| Error::Config(e.to_string()))?);

    // Printed so it can be copied straight into a client's --server-key.
    tracing::info!(
        public_key = %keypair.public(),
        peers = peers.len(),
        path = %settings.peers.display(),
        "identity and whitelist loaded"
    );

    let endpoint = bind(&keypair, Arc::clone(&peers), settings.listen)?;
    tracing::info!(addr = %settings.listen, "listening for QUIC connections");

    let table = Arc::new(SessionTable::new());

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    tracing::info!("endpoint closed");
                    break;
                };

                // Spawn before awaiting anything, so a slow or hostile peer
                // cannot hold up the listener. See plan.md §6.5.
                tokio::spawn(session::handle(
                    incoming,
                    Arc::clone(&peers),
                    Arc::clone(&table),
                ));
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                endpoint.close(0u32.into(), b"server shutting down");
                break;
            }
        }
    }

    endpoint.wait_idle().await;
    Ok(())
}

/// Builds the QUIC endpoint that authenticates against `peers`.
fn bind(
    keypair: &StaticKeypair,
    peers: Arc<PeerFile>,
    addr: SocketAddr,
) -> veil_common::Result<Endpoint> {
    let tls = veil_crypto::server_config(keypair, peers, veil_crypto::provider())
        .map_err(|e| Error::Config(format!("tls configuration: {e}")))?;

    let quic = QuicServerConfig::try_from(tls)
        .map_err(|e| Error::Config(format!("quic configuration: {e}")))?;

    let mut config = ServerConfig::with_crypto(Arc::new(quic));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        IDLE_TIMEOUT
            .try_into()
            .map_err(|_| Error::Config("idle timeout is out of range for QUIC".into()))?,
    ));
    config.transport_config(Arc::new(transport));

    Endpoint::server(config, addr)
        .map_err(|e| Error::Transport(format!("could not bind {addr}: {e}")))
}
