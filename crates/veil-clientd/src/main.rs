//! The VEIL client daemon.
//!
//! Holds the QUIC connection to the server, owns the local tun device, the
//! fail-closed killswitch and the DNS stub resolver, and serves the device web
//! UI on loopback.
//!
//! Currently the control plane only. There is no tun device, no killswitch and
//! no resolver yet, so this needs no capabilities.

#![forbid(unsafe_code)]

mod client;
mod control;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint};
use veil_common::Error;
use veil_crypto::{PublicKey, StaticKeypair};

/// How often to send a QUIC keepalive, comfortably inside the idle timeout.
const KEEPALIVE: Duration = Duration::from_secs(5);

/// Drops the session if the server goes silent for this long.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The VEIL client daemon.
#[derive(Debug, Parser)]
#[command(name = "veil-clientd", version, about)]
struct Cli {
    /// This device's private key. Must be mode 0600.
    #[arg(long, value_name = "PATH", default_value = "/etc/veil/private.key")]
    key: PathBuf,

    /// The server's UDP address.
    #[arg(long, value_name = "ADDR")]
    server: SocketAddr,

    /// The server's public key, as printed by `veil-ctl keygen` on the server.
    #[arg(long, value_name = "ed25519:BASE64")]
    server_key: PublicKey,
}

#[tokio::main]
async fn main() -> veil_common::Result<()> {
    // `expect` is permitted here: startup, before anything is running.
    #[allow(clippy::expect_used)]
    veil_common::init_tracing("info").expect("tracing is initialised exactly once, at startup");

    let cli = Cli::parse();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "veil-clientd starting");

    run(cli).await
}

async fn run(cli: Cli) -> veil_common::Result<()> {
    let keypair = StaticKeypair::from_file(&cli.key)
        .map_err(|e| Error::Config(format!("{}: {e}", cli.key.display())))?;

    tracing::info!(
        public_key = %keypair.public(),
        server = %cli.server,
        server_key = %cli.server_key,
        "identity loaded"
    );

    let endpoint = bind(&keypair, cli.server_key, cli.server)?;

    // One attempt: jittered exponential backoff and reconnection are M10.
    tokio::select! {
        result = client::run(&endpoint, cli.server, cli.server_key, &keypair) => {
            if let Err(e) = result {
                return Err(Error::Transport(e));
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
        }
    }

    endpoint.close(0u32.into(), b"client shutting down");
    endpoint.wait_idle().await;
    Ok(())
}

/// Builds the QUIC endpoint pinned to `server_key`.
fn bind(
    keypair: &StaticKeypair,
    server_key: PublicKey,
    server: SocketAddr,
) -> veil_common::Result<Endpoint> {
    let tls = veil_crypto::client_config(keypair, server_key, veil_crypto::provider())
        .map_err(|e| Error::Config(format!("tls configuration: {e}")))?;

    let quic = QuicClientConfig::try_from(tls)
        .map_err(|e| Error::Config(format!("quic configuration: {e}")))?;

    let mut config = ClientConfig::new(Arc::new(quic));

    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(KEEPALIVE));
    transport.max_idle_timeout(Some(IDLE_TIMEOUT.try_into().map_err(|_| {
        Error::Config("idle timeout is out of range for QUIC".into())
    })?));
    config.transport_config(Arc::new(transport));

    // Bind the address family the server needs; the port is ephemeral. QUIC
    // connection migration means changing networks does not need a new socket.
    let local = if server.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };

    let mut endpoint =
        Endpoint::client(local).map_err(|e| Error::Transport(format!("could not bind {local}: {e}")))?;
    endpoint.set_default_client_config(config);

    Ok(endpoint)
}
