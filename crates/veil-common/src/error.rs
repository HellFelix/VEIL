use std::io;

/// The workspace-wide error type, produced at daemon boundaries.
///
/// Variants are added as the milestones that need them land. Domain errors stay
/// in their own crate and convert into this type rather than replacing it.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An operating system call failed.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    /// Configuration was missing, malformed or internally inconsistent.
    #[error("configuration error: {0}")]
    Config(String),

    /// The QUIC endpoint could not be established, bound or connected.
    ///
    /// Kept distinct from [`Error::Config`] so that an unreachable server reads
    /// differently from a server that was reached and refused us.
    #[error("transport error: {0}")]
    Transport(String),
}

/// [`Result`](std::result::Result) specialised to [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;
