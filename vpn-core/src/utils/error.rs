use std::{error::Error as ErrTrait, fmt::Display, io, net, ops::Not, result};

#[derive(Debug)]
pub enum ErrorKind {
    IO,
    Internal,
    InvalidData,
    InvalidInput,

    // Handshake
    AddressClaimed,
    Rejection,
    MaxRetry,

    Depleted,
    AlreadyExists,
    UnsupportedAction,
    UnsupportedProtocol,

    Parse,
    Other,
}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    inner: Box<dyn ErrTrait>,
}
impl Error {
    pub fn new(kind: ErrorKind, inner: impl Into<Box<dyn ErrTrait>>) -> Self {
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

impl ErrTrait for Error {}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self {
            kind: ErrorKind::IO,
            inner: Box::new(value),
        }
    }
}
impl From<net::AddrParseError> for Error {
    fn from(value: net::AddrParseError) -> Self {
        Self {
            kind: ErrorKind::Parse,
            inner: Box::new(value),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;
