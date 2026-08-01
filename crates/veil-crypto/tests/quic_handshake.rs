//! M1 acceptance test: RFC 7250 raw public keys over a real QUIC connection.
//!
//! `plan.md` §8 requires that a whitelisted key connects, that an unknown key
//! is rejected with a distinguishable error, and that both are asserted. This
//! runs over loopback with no privileges, so it is CI-able.

// `clippy.toml` relaxes the deny-list inside `#[cfg(test)]` modules, but an
// integration test is its own crate and is not covered by that. A test that
// fails loudly on a broken precondition is the desired behaviour here, so the
// relaxation is stated explicitly rather than silently inherited.
#![allow(clippy::expect_used, clippy::panic)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use veil_crypto::{PublicKey, StaticKeypair, StaticWhitelist, peer_public_key, provider};

/// A running server endpoint plus the key it presents.
struct Server {
    endpoint: Endpoint,
    addr: SocketAddr,
    key: PublicKey,
}

/// Starts a server on an ephemeral loopback port accepting `whitelist`.
fn start_server(keypair: &StaticKeypair, whitelist: StaticWhitelist) -> Server {
    let tls = veil_crypto::server_config(keypair, Arc::new(whitelist), provider())
        .expect("server tls config");
    let quic = QuicServerConfig::try_from(tls).expect("quic server config");

    let endpoint = Endpoint::server(
        ServerConfig::with_crypto(Arc::new(quic)),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .expect("bind server");

    let addr = endpoint.local_addr().expect("local addr");
    Server {
        endpoint,
        addr,
        key: keypair.public(),
    }
}

/// Waits for a connection the server refused, and returns why.
///
/// **This is the shape of client authentication in TLS 1.3, and it is not
/// optional.** The server validates the client's certificate *after* it has
/// sent its own Finished, so `connect().await` resolves to `Ok` on the client
/// even when the server is about to reject it. A client may therefore never
/// treat a completed handshake as proof that it was authorized; it has to wait
/// for the server to speak. `veil-clientd` reflects this at M4 by staying in
/// `Handshaking` until the first `ServerMsg` arrives.
///
/// The timeout is what makes this an assertion rather than a hang: a
/// connection that is never closed is a failure, not a passing test.
async fn rejection_reason(conn: quinn::Connection) -> quinn::ConnectionError {
    tokio::time::timeout(std::time::Duration::from_secs(10), conn.closed())
        .await
        .expect("the server must close the connection rather than leave it open")
}

/// Builds a client that presents `keypair` and expects `server_key`.
fn client_for(keypair: &StaticKeypair, server_key: PublicKey) -> Endpoint {
    let tls = veil_crypto::client_config(keypair, server_key, provider()).expect("client tls");
    let quic = QuicClientConfig::try_from(tls).expect("quic client config");

    let mut endpoint =
        Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind client");
    endpoint.set_default_client_config(ClientConfig::new(Arc::new(quic)));
    endpoint
}

#[tokio::test]
async fn whitelisted_key_connects_and_its_identity_is_recovered() {
    let server_key = StaticKeypair::generate().expect("keygen");
    let client_key = StaticKeypair::generate().expect("keygen");

    let mut whitelist = StaticWhitelist::new();
    whitelist.insert(client_key.public(), "laptop");
    let server = start_server(&server_key, whitelist);

    let accept = tokio::spawn({
        let endpoint = server.endpoint.clone();
        async move {
            let incoming = endpoint.accept().await.expect("an incoming connection");
            incoming.await.expect("handshake completes")
        }
    });

    let client = client_for(&client_key, server.key);
    let conn = client
        .connect(server.addr, "veil")
        .expect("connect starts")
        .await
        .expect("client handshake succeeds");

    let accepted = accept.await.expect("accept task");

    // The whole point of M1: the server can name who connected, and the name
    // comes out of the handshake rather than from anything the client asserted.
    let identity = accepted.peer_identity().expect("client authenticated");
    assert_eq!(
        peer_public_key(identity.as_ref()),
        Some(client_key.public()),
        "server must recover the client's key"
    );

    // And the client authenticated the server in the same way.
    let identity = conn.peer_identity().expect("server authenticated");
    assert_eq!(
        peer_public_key(identity.as_ref()),
        Some(server_key.public()),
        "client must recover the server's key"
    );

    // Proves the RFC 7250 path is genuinely in use: an X.509 fallback would
    // put a parseable certificate here, not a bare 44-byte SPKI.
    let chain = identity
        .downcast_ref::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .expect("a certificate chain");
    assert_eq!(chain.len(), 1, "raw public keys are never a chain");
    assert_eq!(chain[0].as_ref().len(), 44, "an Ed25519 SPKI is 44 bytes");
}

#[tokio::test]
async fn unknown_key_is_rejected_distinguishably() {
    let server_key = StaticKeypair::generate().expect("keygen");
    let stranger = StaticKeypair::generate().expect("keygen");

    // Empty whitelist: nobody is allowed in.
    let server = start_server(&server_key, StaticWhitelist::new());

    tokio::spawn({
        let endpoint = server.endpoint.clone();
        async move {
            if let Some(incoming) = endpoint.accept().await {
                let _ = incoming.await;
            }
        }
    });

    let client = client_for(&stranger, server.key);
    let conn = client
        .connect(server.addr, "veil")
        .expect("connect starts")
        .await
        // Not a bug: see `rejection_reason`. The client's handshake completes
        // before the server has judged it.
        .expect("client-side handshake completes");

    let err = rejection_reason(conn).await;

    // Distinguishable means matched on the alert, not on a timeout and not on
    // a substring of a message.
    match err {
        quinn::ConnectionError::ConnectionClosed(close) => {
            // QUIC carries TLS alerts as transport error 0x100 + alert value.
            // `access_denied` is alert 49, which is what a whitelist miss maps
            // to; a malformed key or a transport fault would give a different
            // code, which is what makes this rejection distinguishable.
            const ACCESS_DENIED: u8 = 49;
            assert_eq!(
                close.error_code,
                quinn::TransportErrorCode::crypto(ACCESS_DENIED),
                "expected an access_denied alert, got {close:?}"
            );
        }
        other => panic!("expected a TLS alert close, got {other:?}"),
    }
}

#[tokio::test]
async fn client_refuses_a_server_presenting_the_wrong_key() {
    let server_key = StaticKeypair::generate().expect("keygen");
    let client_key = StaticKeypair::generate().expect("keygen");
    let impostor = StaticKeypair::generate().expect("keygen");

    let mut whitelist = StaticWhitelist::new();
    whitelist.insert(client_key.public(), "laptop");
    let server = start_server(&server_key, whitelist);

    tokio::spawn({
        let endpoint = server.endpoint.clone();
        async move {
            if let Some(incoming) = endpoint.accept().await {
                let _ = incoming.await;
            }
        }
    });

    // The client expects the impostor's key but the server presents its own.
    let client = client_for(&client_key, impostor.public());
    let err = client
        .connect(server.addr, "veil")
        .expect("connect starts")
        .await
        .expect_err("a server with an unexpected key must be refused");

    assert!(
        !matches!(err, quinn::ConnectionError::TimedOut),
        "must fail by rejection, not by timeout: {err:?}"
    );
}

#[tokio::test]
async fn revoking_a_key_refuses_the_next_connection() {
    // The seed of the revocation behaviour §6.4 needs at M3: the same endpoint
    // accepts, then refuses, the same key.
    let server_key = StaticKeypair::generate().expect("keygen");
    let client_key = StaticKeypair::generate().expect("keygen");

    let mut whitelist = StaticWhitelist::new();
    whitelist.insert(client_key.public(), "laptop");
    let allowed = start_server(&server_key, whitelist);

    tokio::spawn({
        let endpoint = allowed.endpoint.clone();
        async move {
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let _ = incoming.await;
                });
            }
        }
    });

    let client = client_for(&client_key, allowed.key);
    assert!(
        client
            .connect(allowed.addr, "veil")
            .expect("connect starts")
            .await
            .is_ok(),
        "whitelisted key must connect"
    );

    // Now the same key against a server that has revoked it.
    let revoked = start_server(&server_key, StaticWhitelist::new());
    tokio::spawn({
        let endpoint = revoked.endpoint.clone();
        async move {
            if let Some(incoming) = endpoint.accept().await {
                let _ = incoming.await;
            }
        }
    });

    let conn = client
        .connect(revoked.addr, "veil")
        .expect("connect starts")
        .await
        .expect("client-side handshake completes");

    const ACCESS_DENIED: u8 = 49;
    match rejection_reason(conn).await {
        quinn::ConnectionError::ConnectionClosed(close) => assert_eq!(
            close.error_code,
            quinn::TransportErrorCode::crypto(ACCESS_DENIED),
            "a revoked key must be refused with access_denied, got {close:?}"
        ),
        other => panic!("expected a TLS alert close, got {other:?}"),
    }
}
