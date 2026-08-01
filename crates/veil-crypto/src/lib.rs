//! VEIL identity and TLS plumbing.
//!
//! Ed25519 static keypairs and the rustls verifiers that check a presented raw
//! public key ([RFC 7250](https://www.rfc-editor.org/rfc/rfc7250)) against the
//! peer whitelist. Both directions are key-pinned, so there are no trust
//! anchors, no certificate authority, and no expiry anywhere: revocation is
//! deletion from the whitelist.

#![forbid(unsafe_code)]

mod config;
mod error;
mod key;
mod store;
mod verify;

pub use config::{client_config, peer_public_key, provider, server_config};
pub use error::Error;
pub use key::{PublicKey, StaticKeypair};
pub use store::{KeyWhitelist, StaticWhitelist, VerifiedPeer};
pub use verify::{PinnedServerVerifier, WhitelistClientVerifier};
