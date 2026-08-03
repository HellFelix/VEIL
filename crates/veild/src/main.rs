//! The `veild` binary: argument parsing over [`veild::run`].
//!
//! Kept as a standalone binary because M14's systemd unit calls it directly.
//! `veil-ctl serve` reaches the same code through the library.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use veil_config::{DEFAULT_LISTEN, DEFAULT_PEERS, DEFAULT_PRIVATE_KEY, ServerSettings};

/// The VEIL server daemon.
#[derive(Debug, Parser)]
#[command(name = "veild", version, about)]
struct Cli {
    /// The server's private key. Must be mode 0600.
    #[arg(long, value_name = "PATH", default_value = DEFAULT_PRIVATE_KEY)]
    key: PathBuf,

    /// The peer whitelist.
    #[arg(long, value_name = "PATH", default_value = DEFAULT_PEERS)]
    peers: PathBuf,

    /// UDP address to listen on. QUIC is UDP: open the port accordingly.
    #[arg(long, value_name = "ADDR", default_value = DEFAULT_LISTEN)]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> veil_common::Result<()> {
    // `expect` is permitted here: startup, before anything is running.
    #[allow(clippy::expect_used)]
    veil_common::init_tracing("info").expect("tracing is initialised exactly once, at startup");

    let cli = Cli::parse();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "veild starting");

    veild::run(ServerSettings {
        listen: cli.listen,
        private_key: cli.key,
        peers: cli.peers,
    })
    .await
}
