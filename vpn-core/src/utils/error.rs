use std::{error::Error as ErrType, fmt::Display, io, result};

#[derive(Debug)]
pub enum ErrorKind {
    IO,
    Internal,
    InvalidData,
    InvalidInput,

    Dropped,

    // Handshake
    AddressClaimed,
    Rejection,
    MaxRetry,

    Depleted,
    AlreadyExists,
    UnsupportedAction,
    UnsupportedProtocol,

    Other,
}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    inner: Box<dyn ErrType + Send + Sync>,
}
impl Error {
    pub fn new(kind: ErrorKind, inner: impl Into<Box<dyn ErrType + Send + Sync>>) -> Self {
        Self {
            kind,
            inner: inner.into(),
        }
    }
}
impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Encountered error of type {:?}: {}",
            self.kind, self.inner
        )
    }
}

impl ErrType for Error {}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self {
            kind: ErrorKind::IO,
            inner: Box::new(value),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;
