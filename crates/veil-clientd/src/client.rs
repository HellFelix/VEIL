//! The connection state machine.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use quinn::{Connection, Endpoint};
use veil_crypto::{PublicKey, StaticKeypair, peer_public_key};

use crate::control;

/// How long the server has to answer on the control stream.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);

/// The TLS alert a server sends when a key is not whitelisted.
///
/// QUIC carries TLS alerts as transport error `0x100 + alert`, and
/// `access_denied` is alert 49. See
/// [RFC 8446 §6.2](https://www.rfc-editor.org/rfc/rfc8446#section-6.2).
const ACCESS_DENIED: u8 = 49;

/// Where the client is in `plan.md` §6.6's state machine.
///
/// Only the states that exist without a tun device are modelled. `Resolving`
/// arrives with hostname support and `Backoff` at M10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// No connection, and none being attempted.
    Disconnected,
    /// The QUIC and TLS handshake is in flight.
    Handshaking,
    /// The handshake completed, but the server has not yet accepted us.
    Configuring,
    /// The server has spoken. This is the first state that proves authorization.
    Connected,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Disconnected => "disconnected",
            Self::Handshaking => "handshaking",
            Self::Configuring => "configuring",
            Self::Connected => "connected",
        };
        f.write_str(name)
    }
}

/// Logs a state transition, so the sequence is visible in the output.
fn enter(from: State, to: State) -> State {
    tracing::info!(%from, %to, "state");
    to
}

/// Connects, completes the control exchange, and holds the session open.
pub async fn run(
    endpoint: &Endpoint,
    server: SocketAddr,
    server_key: PublicKey,
    keypair: &StaticKeypair,
) -> Result<(), String> {
    let mut state = enter(State::Disconnected, State::Handshaking);

    let conn = endpoint
        .connect(server, "veil")
        .map_err(|e| format!("could not start connecting to {server}: {e}"))?
        .await
        .map_err(|e| describe(&e))?;

    // A completed handshake is NOT authorization. In TLS 1.3 the server checks
    // the client certificate after sending its own Finished, so this resolves
    // to Ok even when the server is about to refuse us. Only the server's first
    // control message proves we were let in, so the state machine stops here.
    state = enter(state, State::Configuring);

    tracing::debug!(
        remote = %conn.remote_address(),
        rtt = ?conn.rtt(),
        "handshake complete, waiting for the server to accept us"
    );

    // `PinnedServerVerifier` has already enforced this, so a mismatch here is
    // impossible today. It is checked anyway because the cost is one
    // comparison and the failure it guards against, a refactor that quietly
    // stops pinning, is exactly the kind that leaves no other trace.
    match server_identity(&conn) {
        Some(key) if key == server_key => {
            tracing::debug!(server = %key, "server identity confirmed");
        }
        found => {
            conn.close(1u32.into(), b"unexpected server identity");
            return Err(format!(
                "server presented {}, expected {server_key}",
                found.map_or_else(|| "no raw public key".into(), |key| key.to_string())
            ));
        }
    }

    let welcome = match exchange(&conn, keypair).await {
        Ok(welcome) => welcome,
        Err(e) => {
            // The server closing mid-exchange is the usual rejection path, and
            // its close reason is more informative than the stream error.
            if let Some(reason) = conn.close_reason() {
                return Err(describe(&reason));
            }
            return Err(e);
        }
    };

    let _ = enter(state, State::Connected);
    tracing::info!(%welcome, "authorized by the server");

    let reason = conn.closed().await;
    let _ = enter(State::Connected, State::Disconnected);

    Err(describe(&reason))
}

/// Recovers the server's key from the completed handshake.
///
/// Synchronous because `peer_identity` yields a `Box<dyn Any>`, which is not
/// `Send` and so must not stay alive across an await.
fn server_identity(conn: &Connection) -> Option<PublicKey> {
    peer_public_key(conn.peer_identity()?.as_ref())
}

/// Opens the control stream, says hello, and waits to be answered.
///
/// M4 replaces the placeholder frames with `ClientMsg::Hello` and
/// `ServerMsg::Config`, which is where the address assignment will arrive.
async fn exchange(conn: &Connection, keypair: &StaticKeypair) -> Result<String, String> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;

    let hello = format!("veil: hello from {}", keypair.public());
    control::write_frame(&mut send, &hello).await?;
    tracing::debug!("control hello sent");

    tokio::time::timeout(CONTROL_TIMEOUT, control::read_frame(&mut recv))
        .await
        .map_err(|_| "the server accepted the handshake but never answered".to_string())?
}

/// Turns a connection error into something an operator can act on.
///
/// The distinction that matters: being refused by the whitelist looks like a
/// transport error unless the `access_denied` alert is decoded, and telling a
/// revoked peer that the network is broken would send them debugging the wrong
/// thing entirely.
fn describe(error: &quinn::ConnectionError) -> String {
    if let quinn::ConnectionError::ConnectionClosed(close) = error
        && close.error_code == quinn::TransportErrorCode::crypto(ACCESS_DENIED)
    {
        return "rejected by the server: this public key is not whitelisted".into();
    }

    if matches!(error, quinn::ConnectionError::TimedOut) {
        return "timed out: check the server is running and UDP reaches it".into();
    }

    error.to_string()
}
