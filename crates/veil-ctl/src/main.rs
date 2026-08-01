//! The VEIL command line tool.
//!
//! Generates the local keypair, edits `peers.toml` and reloads the server, and
//! queries a running daemon for status. Enrolment is one-way: the client
//! generates its own keypair and never transmits the private half.

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};

/// Command line interface for a VEIL deployment.
#[derive(Debug, Parser)]
#[command(name = "veil-ctl", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Write a new private key and print the corresponding public key.
    Keygen,
    /// Report the state of the local daemon.
    Status,
}

fn main() -> veil_common::Result<()> {
    // `expect` is permitted here: startup, before anything is running.
    #[allow(clippy::expect_used)]
    veil_common::init_tracing("warn").expect("tracing is initialised exactly once, at startup");

    match Cli::parse().command {
        Command::Keygen => tracing::warn!("keygen is not implemented yet; see plan.md M1"),
        Command::Status => tracing::warn!("status is not implemented yet; see plan.md M9"),
    }

    Ok(())
}
