use std::io;

/// Failures in reading or validating VEIL's configuration files.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A configuration file could not be read.
    #[error("could not read {path}: {source}")]
    Read {
        /// The file that could not be read.
        path: String,
        /// The underlying failure.
        source: io::Error,
    },

    /// A configuration file was not valid TOML, or had the wrong shape.
    #[error("malformed configuration: {0}")]
    Toml(#[from] toml::de::Error),

    /// A peer's `public_key` could not be parsed.
    ///
    /// Names the peer so the operator is told which entry to fix.
    #[error("peer {peer}: {source}")]
    PeerKey {
        /// The peer whose key is malformed.
        peer: String,
        /// Why the key was rejected.
        source: veil_crypto::Error,
    },

    /// A prefix in a peer's `allowed` list is not a valid CIDR block.
    #[error("peer {peer}: {prefix} is not a valid prefix")]
    PeerPrefix {
        /// The peer whose prefix is malformed.
        peer: String,
        /// The offending prefix, as written.
        prefix: String,
    },

    /// Two peers share one public key, which would make attribution ambiguous.
    #[error("peers {first} and {second} share the public key {key}")]
    DuplicateKey {
        /// The shared key.
        key: String,
        /// The first peer to claim it.
        first: String,
        /// The second peer to claim it.
        second: String,
    },

    /// Two peers share one name, which would make the logs ambiguous.
    #[error("peer name {0} is used more than once")]
    DuplicateName(String),
}
