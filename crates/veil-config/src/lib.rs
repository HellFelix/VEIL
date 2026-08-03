//! VEIL configuration and peer store.
//!
//! Currently the parse-only half: [`PeerFile`] reads `/etc/veil/peers.toml`
//! once at startup and implements [`veil_crypto::KeyWhitelist`], which is the
//! seam `veil-crypto`'s store documents. Daemon configuration, `SIGHUP` reload
//! and the session diffing that makes revocation take effect on a live
//! connection arrive at M3.

#![forbid(unsafe_code)]

mod edit;
mod error;
mod peers;
mod settings;

pub use edit::{PeerChange, PeerEditor};
pub use error::Error;
pub use peers::{Peer, PeerFile};
pub use settings::{
    ClientSettings, DEFAULT_CLIENT_CONFIG, DEFAULT_LISTEN, DEFAULT_PEERS, DEFAULT_PRIVATE_KEY,
    DEFAULT_SERVER_CONFIG, PartialClientSettings, PartialServerSettings, ServerSettings,
};
