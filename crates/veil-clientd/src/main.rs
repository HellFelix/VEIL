//! The `veil-clientd` binary: argument parsing over [`veil_clientd::run`].
//!
//! Kept as a standalone binary because M14's systemd unit calls it directly.
//! `veil-ctl connect` reaches the same code through the library.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use veil_config::{ClientSettings, DEFAULT_PRIVATE_KEY};
use veil_crypto::PublicKey;

/// The VEIL client daemon.
#[derive(Debug, Parser)]
#[command(name = "veil-clientd", version, about)]
struct Cli {
    /// This device's private key. Must be mode 0600.
    #[arg(long, value_name = "PATH", default_value = DEFAULT_PRIVATE_KEY)]
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

    veil_clientd::run(ClientSettings {
        server: cli.server,
        server_key: cli.server_key,
        private_key: cli.key,
    })
    .await
}
