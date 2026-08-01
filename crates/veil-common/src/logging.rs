use tracing_subscriber::{EnvFilter, fmt};

/// Installs the process-wide `tracing` subscriber.
///
/// The filter is read from `RUST_LOG`, falling back to `default` when unset.
/// Calling this more than once in a process is an error and is reported as one.
///
/// Packet payloads are never logged at any level; see `plan.md` §7.
pub fn init_tracing(default: &str) -> Result<(), TracingAlreadyInitialised> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));

    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .try_init()
        .map_err(|_| TracingAlreadyInitialised)
}

/// Returned when [`init_tracing`] is called after a subscriber is already set.
#[derive(Debug, thiserror::Error)]
#[error("a tracing subscriber is already installed for this process")]
pub struct TracingAlreadyInitialised;
