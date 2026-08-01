use std::io;

/// Failures in key handling and peer verification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A key could not be decoded from its text, SPKI or PKCS#8 form.
    #[error("malformed key: {0}")]
    MalformedKey(String),

    /// A private key file is readable or writable by someone other than its
    /// owner. Refused rather than warned about; see invariant 10.
    #[error("private key {path} has mode {mode:o}, expected 0600")]
    KeyPermissions {
        /// The offending file.
        path: String,
        /// The permission bits found.
        mode: u32,
    },

    /// The peer presented a well-formed key that is not on the whitelist.
    ///
    /// Distinct from every other variant so that a rejected peer is
    /// distinguishable from a transport failure, which is what `plan.md` §8
    /// requires of M1.
    #[error("public key {0} is not whitelisted")]
    UnknownPeer(crate::PublicKey),

    /// The operating system could not supply entropy for key generation.
    #[error("could not read entropy: {0}")]
    Entropy(String),

    /// rustls rejected the configuration or the handshake.
    #[error("tls error: {0}")]
    Tls(#[from] rustls::Error),

    /// Reading or writing key material failed.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
}
