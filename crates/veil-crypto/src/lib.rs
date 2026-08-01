//! VEIL identity and TLS plumbing.
//!
//! Ed25519 static keypairs and the rustls verifiers that check a presented raw
//! public key ([RFC 7250](https://www.rfc-editor.org/rfc/rfc7250)) against the
//! peer whitelist. Both directions are key-pinned, so there are no trust
//! anchors anywhere.
//!
//! Populated at M1.

#![forbid(unsafe_code)]
