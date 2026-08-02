//! The VEIL server daemon.
//!
//! Terminates QUIC connections, authenticates each peer against the store,
//! assigns tunnel addresses, and moves packets between its sessions and `tun0`.
//! Orchestration only: the privileged work lives in `veil-net`.
//!
//! Currently the control plane only. There is no tun device and no forwarding
//! yet, so this needs no capabilities.

#![forbid(unsafe_code)]

mod control;
mod session;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, ServerConfig};
use veil_common::Error;
use veil_config::PeerFile;
use veil_crypto::StaticKeypair;

use session::SessionTable;

/// Drops a peer that has gone silent. QUIC keepalives from the client hold an
/// idle session open well inside this.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The VEIL server daemon.
#[derive(Debug, Parser)]
#[command(name = "veild", version, about)]
struct Cli {
    /// The server's private key. Must be mode 0600.
    #[arg(long, value_name = "PATH", default_value = "/etc/veil/private.key")]
    key: PathBuf,

    /// The peer whitelist.
    #[arg(long, value_name = "PATH", default_value = "/etc/veil/peers.toml")]
    peers: PathBuf,

    /// UDP address to listen on. QUIC is UDP: open the port accordingly.
    #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:51820")]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> veil_common::Result<()> {
    // `expect` is permitted here: startup, before anything is running.
    #[allow(clippy::expect_used)]
    veil_common::init_tracing("info").expect("tracing is initialised exactly once, at startup");

    let cli = Cli::parse();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "veild starting");

    run(cli).await
}

async fn run(cli: Cli) -> veil_common::Result<()> {
    let keypair = StaticKeypair::from_file(&cli.key)
        .map_err(|e| Error::Config(format!("{}: {e}", cli.key.display())))?;

    let peers = Arc::new(PeerFile::load(&cli.peers).map_err(|e| Error::Config(e.to_string()))?);

    // Printed so it can be copied straight into a client's --server-key.
    tracing::info!(
        public_key = %keypair.public(),
        peers = peers.len(),
        path = %cli.peers.display(),
        "identity and whitelist loaded"
    );

    let endpoint = bind(&keypair, Arc::clone(&peers), cli.listen)?;
    tracing::info!(addr = %cli.listen, "listening for QUIC connections");

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
