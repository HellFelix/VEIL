//! The VEIL client daemon.
//!
//! Holds the QUIC connection to the server, owns the local tun device, the
//! fail-closed killswitch and the DNS stub resolver, and serves the device web
//! UI on loopback.

#![forbid(unsafe_code)]

fn main() -> veil_common::Result<()> {
    // `expect` is permitted here: startup, before anything is running.
    #[allow(clippy::expect_used)]
    veil_common::init_tracing("info").expect("tracing is initialised exactly once, at startup");

    tracing::info!(version = env!("CARGO_PKG_VERSION"), "veil-clientd starting");
    tracing::warn!("no client functionality yet; see plan.md M4");

    Ok(())
}
