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

    /// A configuration file could not be written.
    #[error("could not write {path}: {source}")]
    Write {
        /// The file that could not be written.
        path: String,
        /// The underlying failure.
        source: io::Error,
    },

    /// A setting with no default was given neither in the file nor on the
    /// command line.
    ///
    /// Names the field so the operator is told what to fill in rather than
    /// which type failed to build.
    #[error("{field} is not set; give it in {path} or on the command line")]
    Missing {
        /// The setting that is missing.
        field: &'static str,
        /// The file it was expected in.
        path: String,
    },

    /// A `server_key` in a settings file could not be parsed.
    #[error("{path}: server_key: {source}")]
    SettingsKey {
        /// The file holding the malformed key.
        path: String,
        /// Why the key was rejected.
        source: veil_crypto::Error,
    },

    /// An operation named a peer that is not in the file.
    #[error("no peer named {0}")]
    UnknownPeer(String),

    /// A file being edited was not valid TOML.
    ///
    /// Distinct from [`Error::Toml`]: that one comes from deserializing into
    /// our types, this one from parsing the document we are about to modify.
    #[error("could not parse {path} for editing: {source}")]
    Edit {
        /// The file that could not be parsed.
        path: String,
        /// The underlying parse failure.
        source: toml_edit::TomlError,
    },

    /// `peer` exists in the file but is not an array of tables.
    ///
    /// Means someone wrote `peer = "..."` where `[[peer]]` belongs. Refused
    /// rather than overwritten, since the file is hand-editable.
    #[error("{0}: `peer` is not a [[peer]] array")]
    NotPeerArray(String),
}
