//! VEIL configuration and peer store.
//!
//! Daemon configuration plus the `PeerStore` trait and its TOML implementation
//! over `/etc/veil/peers.toml`, including `SIGHUP` reload and the session
//! diffing that makes revocation take effect on a live connection.
//!
//! Populated at M3.

#![forbid(unsafe_code)]
