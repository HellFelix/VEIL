//! The VEIL server daemon.
//!
//! Terminates QUIC connections, authenticates each peer against the store,
//! assigns tunnel addresses, and moves packets between its sessions and `tun0`.
//! Orchestration only: the privileged work lives in `veil-net`.

#![forbid(unsafe_code)]

fn main() -> veil_common::Result<()> {
    // `expect` is permitted here: startup, before anything is running.
    #[allow(clippy::expect_used)]
    veil_common::init_tracing("info").expect("tracing is initialised exactly once, at startup");

    tracing::info!(version = env!("CARGO_PKG_VERSION"), "veild starting");
    tracing::warn!("no server functionality yet; see plan.md M4");

    Ok(())
}
