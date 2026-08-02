//! Live sessions and the per-connection task.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use quinn::Connection;
use veil_config::PeerFile;
use veil_crypto::{KeyWhitelist as _, PublicKey, peer_public_key};

use crate::control;

/// How long a peer has to complete the TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a peer has to open its control stream and say hello.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a connection was closed, for the session-replacement path.
const REPLACED: &[u8] = b"replaced by a newer connection from the same key";

/// One authenticated peer holding a live connection.
///
/// `plan.md` §6.5 gives this an address assignment, an `AllowedSet` and
/// counters at M4 onwards. What matters already is that `peer` came out of the
/// completed handshake: v1 discarded it, which made anti-spoofing and
/// attribution structurally impossible.
#[derive(Debug)]
pub struct Session {
    /// The authenticated identity.
    pub key: PublicKey,
    /// The operator-facing name from `peers.toml`.
    pub name: String,
    /// The connection this peer holds.
    pub conn: Connection,
}

/// Every live session, keyed by public key.
///
/// One connection per peer: a new handshake from a key that already holds a
/// session **replaces** it, which is how a client that rebooted or roamed gets
/// back in without waiting for the old connection to time out.
#[derive(Debug, Default)]
pub struct SessionTable {
    sessions: Mutex<HashMap<PublicKey, Session>>,
}

impl SessionTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts `session`, returning any session it displaces.
    fn insert(&self, session: Session) -> Option<Session> {
        let mut sessions = self.sessions.lock().ok()?;
        sessions.insert(session.key, session)
    }

    /// Removes the session for `key`, but only if `conn` is still the live one.
    ///
    /// The guard matters: a replaced connection's task also runs this on its
    /// way out, and without the check it would evict the connection that
    /// replaced it.
    fn remove_if_current(&self, key: &PublicKey, conn: &Connection) {
        if let Ok(mut sessions) = self.sessions.lock()
            && sessions
                .get(key)
                .is_some_and(|live| live.conn.stable_id() == conn.stable_id())
        {
            sessions.remove(key);
        }
    }

    /// Number of live sessions.
    pub fn len(&self) -> usize {
        self.sessions.lock().map(|s| s.len()).unwrap_or(0)
    }
}

/// Handles one incoming connection from accept to close.
///
/// Returns nothing and propagates nothing: `plan.md` §6.5 requires that no
/// error escapes into the listener. v1 `?`-propagated a failed TLS handshake
/// out of its accept loop and killed the process.
pub async fn handle(incoming: quinn::Incoming, peers: Arc<PeerFile>, table: Arc<SessionTable>) {
    let remote = incoming.remote_address();

    // The handshake runs under a timeout inside this task, never on the accept
    // path. v1 held two global mutexes across it, so one silent client blocked
    // every new connection.
    let conn = match tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => {
            // A whitelist miss lands here: rustls has already sent the
            // access_denied alert by the time the error surfaces.
            tracing::info!(%remote, error = %e, "handshake failed");
            return;
        }
        Err(_) => {
            tracing::info!(%remote, "handshake timed out");
            return;
        }
    };

    // Identity comes out of what TLS actually verified, never from anything the
    // client asserted alongside it.
    let key = match identity_of(&conn) {
        Ok(key) => key,
        Err(why) => {
            tracing::warn!(%remote, why, "rejecting a connection with no usable identity");
            conn.close(1u32.into(), why.as_bytes());
            return;
        }
    };

    // The verifier already accepted this key, so a miss here means the file
    // changed underneath us. Fail closed rather than admit an unnamed peer.
    let Some(peer) = peers.lookup(&key) else {
        tracing::warn!(%remote, %key, "authenticated key is no longer whitelisted");
        conn.close(1u32.into(), b"not whitelisted");
        return;
    };

    tracing::info!(
        %remote,
        peer = %peer.name,
        %key,
        "session established"
    );

    if let Some(displaced) = table.insert(Session {
        key,
        name: peer.name.clone(),
        conn: conn.clone(),
    }) {
        tracing::info!(
            peer = %peer.name,
            previous = %displaced.name,
            remote = %displaced.conn.remote_address(),
            "replacing the previous session for this key"
        );
        displaced.conn.close(0u32.into(), REPLACED);
    }

    if let Err(e) = serve_control(&conn, &peer.name).await {
        tracing::warn!(peer = %peer.name, error = %e, "control stream failed");
    }

    let reason = conn.closed().await;
    table.remove_if_current(&key, &conn);

    tracing::info!(
        peer = %peer.name,
        %reason,
        sessions = table.len(),
        "session closed"
    );
}

/// Recovers the peer's key from the completed handshake.
///
/// Deliberately synchronous: `peer_identity` hands back a `Box<dyn Any>`, which
/// is not `Send`, so it must not be alive across an await inside a spawned task.
///
/// Neither failure should be reachable once the verifier has accepted a peer,
/// but both are handled rather than asserted, because invariant 7 forbids a
/// panic reachable from a handshake.
fn identity_of(conn: &Connection) -> Result<PublicKey, &'static str> {
    let identity = conn.peer_identity().ok_or("no peer identity")?;

    peer_public_key(identity.as_ref()).ok_or("peer identity is not an ed25519 raw public key")
}

/// Waits for the peer's control stream and answers it.
///
/// M4 replaces the placeholder exchange with `ClientMsg::Hello` and
/// `ServerMsg::Config`, carrying the peer's address assignment.
async fn serve_control(conn: &Connection, name: &str) -> Result<(), String> {
    let (mut send, mut recv) = tokio::time::timeout(CONTROL_TIMEOUT, conn.accept_bi())
        .await
        .map_err(|_| "peer never opened a control stream".to_string())?
        .map_err(|e| e.to_string())?;

    let hello = control::read_frame(&mut recv).await?;
    tracing::debug!(peer = %name, %hello, "control hello received");

    // This is the message that tells the client it is authorized. Until it
    // arrives the client has a completed handshake and nothing more.
    control::write_frame(&mut send, &format!("veil: welcome, {name}")).await?;

    tracing::debug!(peer = %name, "control reply sent");
    Ok(())
}
