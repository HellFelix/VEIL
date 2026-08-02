//! VEIL configuration and peer store.
//!
//! Currently the parse-only half: [`PeerFile`] reads `/etc/veil/peers.toml`
//! once at startup and implements [`veil_crypto::KeyWhitelist`], which is the
//! seam `veil-crypto`'s store documents. Daemon configuration, `SIGHUP` reload
//! and the session diffing that makes revocation take effect on a live
//! connection arrive at M3.

#![forbid(unsafe_code)]

mod error;
mod peers;

pub use error::Error;
pub use peers::{Peer, PeerFile};
