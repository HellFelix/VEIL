//! Shared error type and logging setup.
//!
//! Every other crate defines its own domain error and converts into [`Error`]
//! at the daemon boundary, so a binary has exactly one error type to report.

#![forbid(unsafe_code)]

mod error;
mod logging;

pub use error::{Error, Result};
pub use logging::{TracingAlreadyInitialised, init_tracing};
