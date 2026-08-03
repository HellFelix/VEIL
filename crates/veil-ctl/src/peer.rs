//! `veil-ctl peer`: managing the server's whitelist.
//!
//! Every mutating command edits `peers.toml` and nothing else. `veild` reads
//! the file once at startup, so a change takes effect on restart; `SIGHUP`
//! reload arrives at M3.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use ipnet::IpNet;
use veil_common::Error;
use veil_config::{DEFAULT_PEERS, Peer, PeerChange, PeerEditor};
use veil_crypto::PublicKey;

/// Managing the peer whitelist.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Add a peer to the whitelist.
    Add {
        /// Operator-facing name, unique within the file.
        name: String,

        /// The peer's public key, as printed by `veil-ctl pubkey`.
        public_key: PublicKey,

        #[command(flatten)]
        location: Location,

        /// Grant access to the admin UI.
        #[arg(long)]
        admin: bool,

        /// Add the peer without allowing it to connect.
        #[arg(long)]
        disabled: bool,

        #[command(flatten)]
        peers: PeersPath,
    },

    /// Change fields on an existing peer.
    ///
    /// Only the fields given are touched. To unset one, remove the peer and
    /// add it again.
    Set {
        /// The peer to change.
        name: String,

        /// Rename the peer.
        #[arg(long = "name", value_name = "NEW")]
        new_name: Option<String>,

        /// Replace the peer's public key.
        #[arg(long, value_name = "ed25519:BASE64")]
        key: Option<PublicKey>,

        #[command(flatten)]
        location: Location,

        /// Grant or revoke admin access.
        #[arg(long, value_name = "BOOL")]
        admin: Option<bool>,

        /// Allow or forbid the peer to hold a session.
        #[arg(long, value_name = "BOOL")]
        enabled: Option<bool>,

        #[command(flatten)]
        peers: PeersPath,
    },

    /// Delete a peer from the whitelist.
    Remove {
        /// The peer to delete.
        name: String,

        #[command(flatten)]
        peers: PeersPath,
    },

    /// Show the whitelist.
    List {
        #[command(flatten)]
        peers: PeersPath,
    },
}

/// Addressing options shared by `add` and `set`.
#[derive(Debug, Args)]
pub struct Location {
    /// Static IPv4 assignment.
    #[arg(long, value_name = "ADDR")]
    ipv4: Option<Ipv4Addr>,

    /// Static IPv6 assignment.
    #[arg(long, value_name = "ADDR")]
    ipv6: Option<Ipv6Addr>,

    /// Comma-separated prefixes this peer may reach.
    #[arg(long, value_name = "CIDR", value_delimiter = ',')]
    allowed: Option<Vec<IpNet>>,
}

/// Where the whitelist lives.
#[derive(Debug, Args)]
pub struct PeersPath {
    /// The peer whitelist to edit.
    #[arg(long = "peers", value_name = "PATH", default_value = DEFAULT_PEERS)]
    path: PathBuf,
}

/// Runs a `peer` subcommand.
pub fn run(command: Command) -> veil_common::Result<()> {
    match command {
        Command::List { peers } => {
            let editor = open(&peers.path)?;
            list(&editor);
            Ok(())
        }

        Command::Add {
            name,
            public_key,
            location,
            admin,
            disabled,
            peers,
        } => {
            let mut editor = open(&peers.path)?;

            editor
                .add(&Peer {
                    name: name.clone(),
                    public_key,
                    ipv4: location.ipv4,
                    ipv6: location.ipv6,
                    allowed: location.allowed.unwrap_or_default(),
                    enabled: !disabled,
                    admin,
                })
                .map_err(config)?;

            editor.save().map_err(config)?;
            tracing::info!(peer = %name, %public_key, path = %peers.path.display(), "peer added");
            restart_notice();
            Ok(())
        }

        Command::Set {
            name,
            new_name,
            key,
            location,
            admin,
            enabled,
            peers,
        } => {
            let change = PeerChange {
                name: new_name,
                public_key: key,
                ipv4: location.ipv4,
                ipv6: location.ipv6,
                allowed: location.allowed,
                enabled,
                admin,
            };

            // Saying nothing is a mistake worth naming, not a silent no-op that
            // still reports success.
            if change.is_empty() {
                return Err(Error::Config(format!(
                    "nothing to change for {name}; give at least one field"
                )));
            }

            let mut editor = open(&peers.path)?;
            editor.set(&name, &change).map_err(config)?;
            editor.save().map_err(config)?;

            tracing::info!(peer = %name, path = %peers.path.display(), "peer updated");
            restart_notice();
            Ok(())
        }

        Command::Remove { name, peers } => {
            let mut editor = open(&peers.path)?;
            editor.remove(&name).map_err(config)?;
            editor.save().map_err(config)?;

            tracing::info!(peer = %name, path = %peers.path.display(), "peer removed");
            restart_notice();
            Ok(())
        }
    }
}

/// Opens the whitelist for reading or editing.
fn open(path: &Path) -> veil_common::Result<PeerEditor> {
    PeerEditor::open(path).map_err(config)
}

/// The server holds its whitelist from startup, so an edit is not yet live.
fn restart_notice() {
    tracing::warn!("restart veild for this to take effect (SIGHUP reload lands at M3)");
}

/// Prints the whitelist as an aligned table.
fn list(editor: &PeerEditor) {
    let peers = editor.peers();
    if peers.is_empty() {
        println!("no peers");
        return;
    }

    let width = peers.iter().map(|p| p.name.len()).max().unwrap_or(4).max(4);

    println!(
        "{:<width$}  {:<8}  {:<24}  KEY",
        "NAME", "STATE", "ADDRESSES"
    );

    for peer in peers {
        let state = match (peer.enabled, peer.admin) {
            (false, _) => "disabled",
            (true, true) => "admin",
            (true, false) => "enabled",
        };

        let addresses = match (peer.ipv4, peer.ipv6) {
            (None, None) => "-".to_string(),
            (Some(v4), None) => v4.to_string(),
            (None, Some(v6)) => v6.to_string(),
            (Some(v4), Some(v6)) => format!("{v4}, {v6}"),
        };

        println!(
            "{:<width$}  {state:<8}  {addresses:<24}  {}",
            peer.name, peer.public_key
        );
    }
}

/// Config errors from `veil-config` reach the daemon boundary as `Config`.
fn config(e: veil_config::Error) -> Error {
    Error::Config(e.to_string())
}
