//! The VEIL command line tool.
//!
//! Generates the local keypair, edits `peers.toml` and reloads the server, and
//! queries a running daemon for status. Enrolment is one-way: the client
//! generates its own keypair and never transmits the private half.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use veil_common::Error;
use veil_crypto::StaticKeypair;

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
    Keygen {
        /// Where to write the private key. Created with mode 0600.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,

        /// Overwrite an existing key file.
        #[arg(long)]
        force: bool,
    },
    /// Report the state of the local daemon.
    Status,
}

fn main() -> veil_common::Result<()> {
    // `expect` is permitted here: startup, before anything is running.
    #[allow(clippy::expect_used)]
    veil_common::init_tracing("warn").expect("tracing is initialised exactly once, at startup");

    match Cli::parse().command {
        Command::Keygen { out, force } => keygen(&out, force),
        Command::Status => {
            tracing::warn!("status is not implemented yet; see plan.md M9");
            Ok(())
        }
    }
}

/// Generates a keypair, writes the private half, and prints the public half.
///
/// The public key goes to stdout on its own line so it can be piped straight
/// into `peers.toml`; everything else goes through `tracing` to stderr.
fn keygen(out: &Path, force: bool) -> veil_common::Result<()> {
    // `save` truncates, so without this an accidental second `keygen` destroys
    // the identity every peer was configured with, silently and unrecoverably.
    if out.exists() && !force {
        return Err(Error::Config(format!(
            "{} already exists; pass --force to replace it",
            out.display()
        )));
    }

    let keypair = StaticKeypair::generate().map_err(|e| Error::Config(e.to_string()))?;

    keypair
        .save(out)
        .map_err(|e| Error::Config(format!("could not write {}: {e}", out.display())))?;

    tracing::info!(path = %out.display(), "wrote private key with mode 0600");
    println!("{}", keypair.public());

    Ok(())
}
