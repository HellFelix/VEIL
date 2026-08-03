//! The VEIL command line tool.
//!
//! Generates the local keypair, edits `peers.toml`, and runs either daemon.
//! Enrolment is one-way: a device generates its own keypair and never transmits
//! the private half, so only the public key is ever copied between machines.

#![forbid(unsafe_code)]

mod peer;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use veil_common::Error;
use veil_config::{
    DEFAULT_CLIENT_CONFIG, DEFAULT_PRIVATE_KEY, DEFAULT_SERVER_CONFIG, PartialClientSettings,
    PartialServerSettings,
};
use veil_crypto::{PublicKey, StaticKeypair};

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
        #[arg(long, value_name = "PATH", default_value = DEFAULT_PRIVATE_KEY)]
        out: PathBuf,

        /// Replace an existing key.
        #[arg(long)]
        force: bool,
    },

    /// Print this machine's public key.
    Pubkey {
        /// The private key to read.
        #[arg(long, value_name = "PATH", default_value = DEFAULT_PRIVATE_KEY)]
        key: PathBuf,
    },

    /// Run the VEIL server.
    Serve {
        /// Server configuration. Missing is not an error if the flags suffice.
        #[arg(long, value_name = "PATH", default_value = DEFAULT_SERVER_CONFIG)]
        config: PathBuf,

        /// UDP address to listen on, overriding the config file.
        #[arg(long, value_name = "ADDR")]
        listen: Option<SocketAddr>,

        /// The server's private key, overriding the config file.
        #[arg(long, value_name = "PATH")]
        key: Option<PathBuf>,

        /// The peer whitelist, overriding the config file.
        #[arg(long, value_name = "PATH")]
        peers: Option<PathBuf>,
    },

    /// Connect to a VEIL server.
    Connect {
        /// Client configuration. Missing is not an error if the flags suffice.
        #[arg(long, value_name = "PATH", default_value = DEFAULT_CLIENT_CONFIG)]
        config: PathBuf,

        /// The server's UDP address, overriding the config file.
        #[arg(long, value_name = "ADDR")]
        server: Option<SocketAddr>,

        /// The server's public key, overriding the config file.
        #[arg(long, value_name = "ed25519:BASE64")]
        server_key: Option<PublicKey>,

        /// This device's private key, overriding the config file.
        #[arg(long, value_name = "PATH")]
        key: Option<PathBuf>,
    },

    /// Manage the peer whitelist.
    Peer {
        #[command(subcommand)]
        command: peer::Command,
    },

    /// Report the state of the local daemon.
    Status,
}

impl Command {
    /// Default tracing filter for this command.
    ///
    /// The daemons narrate what they are doing; the one-shot commands should
    /// print their result and nothing else.
    fn log_level(&self) -> &'static str {
        match self {
            Self::Serve { .. } | Self::Connect { .. } => "info",
            _ => "warn",
        }
    }
}

#[tokio::main]
async fn main() -> veil_common::Result<()> {
    let cli = Cli::parse();

    // `expect` is permitted here: startup, before anything is running.
    #[allow(clippy::expect_used)]
    veil_common::init_tracing(cli.command.log_level())
        .expect("tracing is initialised exactly once, at startup");

    match cli.command {
        Command::Keygen { out, force } => keygen(&out, force),
        Command::Pubkey { key } => pubkey(&key),

        Command::Serve {
            config,
            listen,
            key,
            peers,
        } => {
            let settings = PartialServerSettings::load_or_default(&config)
                .map_err(|e| Error::Config(e.to_string()))?
                .overlay(PartialServerSettings {
                    listen,
                    private_key: key,
                    peers,
                })
                .finish();

            veild::run(settings).await
        }

        Command::Connect {
            config,
            server,
            server_key,
            key,
        } => {
            let settings = PartialClientSettings::load_or_default(&config)
                .map_err(|e| Error::Config(e.to_string()))?
                .overlay(PartialClientSettings {
                    server,
                    server_key,
                    private_key: key,
                })
                .finish(&config)
                .map_err(|e| Error::Config(e.to_string()))?;

            veil_clientd::run(settings).await
        }

        Command::Peer { command } => peer::run(command),

        Command::Status => {
            tracing::warn!("status is not implemented yet; see plan.md M9");
            Ok(())
        }
    }
}

/// Generates a keypair, writes the private half, and prints the public half.
///
/// The public key goes to stdout on its own line so it can be piped straight
/// into `veil-ctl peer add`; everything else goes through `tracing` to stderr.
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

/// Prints the public half of an existing private key.
fn pubkey(key: &Path) -> veil_common::Result<()> {
    let keypair = StaticKeypair::from_file(key)
        .map_err(|e| Error::Config(format!("{}: {e}", key.display())))?;

    println!("{}", keypair.public());
    Ok(())
}
