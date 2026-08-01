//! rustls verifiers for [RFC 7250](https://www.rfc-editor.org/rfc/rfc7250)
//! raw public keys.
//!
//! Both directions are pinned. The server checks the client's key against a
//! [`KeyWhitelist`]; the client checks the server's key against the single key
//! in its config. Neither consults a trust anchor, because there is none.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls13_signature_with_raw_key};
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};

use crate::{KeyWhitelist, PublicKey};

/// The only signature scheme VEIL accepts.
const SCHEMES: &[SignatureScheme] = &[SignatureScheme::ED25519];

/// Reads a peer's [`PublicKey`] out of the end-entity "certificate".
///
/// Under RFC 7250 the Certificate message carries a bare
/// `SubjectPublicKeyInfo` rather than an X.509 certificate, so this is a
/// [`PublicKey::from_spki`] on attacker-controlled bytes: total, bounds
/// checked, and never panicking.
fn peer_key(end_entity: &CertificateDer<'_>) -> Result<PublicKey, rustls::Error> {
    PublicKey::from_spki(end_entity.as_ref()).ok_or(rustls::Error::InvalidCertificate(
        rustls::CertificateError::BadEncoding,
    ))
}

/// Rejects TLS 1.2, which VEIL never negotiates.
///
/// Returns an error rather than `unreachable!()`: invariant 7 forbids a panic
/// reachable from a handshake, and the `tls12` rustls feature is off anyway, so
/// this is belt and braces rather than a live path.
fn no_tls12() -> Result<HandshakeSignatureValid, rustls::Error> {
    Err(rustls::Error::PeerIncompatible(
        rustls::PeerIncompatible::Tls12NotOffered,
    ))
}

/// Server-side verifier: accepts a client only if its key is whitelisted.
///
/// This is where authentication becomes identity. The accepted key is
/// recoverable afterwards from `quinn::Connection::peer_identity`, so the
/// daemon never has to trust a value the client sent alongside it. v1's
/// equivalent discarded the identity entirely.
#[derive(Debug)]
pub struct WhitelistClientVerifier {
    whitelist: Arc<dyn KeyWhitelist>,
    provider: Arc<CryptoProvider>,
}

impl WhitelistClientVerifier {
    /// Builds a verifier over `whitelist`.
    pub fn new(whitelist: Arc<dyn KeyWhitelist>, provider: Arc<CryptoProvider>) -> Self {
        Self {
            whitelist,
            provider,
        }
    }
}

impl ClientCertVerifier for WhitelistClientVerifier {
    fn requires_raw_public_keys(&self) -> bool {
        true
    }

    /// No certificate authorities exist to hint at.
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let key = peer_key(end_entity)?;

        match self.whitelist.lookup(&key) {
            Some(_) => Ok(ClientCertVerified::assertion()),
            // `AccessDenied` is distinguishable on the wire from a decode
            // failure or a transport error, which is what M1 requires.
            None => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        no_tls12()
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SCHEMES.to_vec()
    }
}

/// Client-side verifier: accepts exactly one server key.
///
/// There is no hostname check because there is no name to check: the identity
/// is the key. This deliberately makes a misdirected connection fail closed.
#[derive(Debug)]
pub struct PinnedServerVerifier {
    expected: PublicKey,
    provider: Arc<CryptoProvider>,
}

impl PinnedServerVerifier {
    /// Pins `expected` as the only acceptable server identity.
    pub fn new(expected: PublicKey, provider: Arc<CryptoProvider>) -> Self {
        Self { expected, provider }
    }
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn requires_raw_public_keys(&self) -> bool {
        true
    }

    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let key = peer_key(end_entity)?;

        if key == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        no_tls12()
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SCHEMES.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{StaticKeypair, StaticWhitelist, provider};

    fn now() -> UnixTime {
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_754_000_000))
    }

    #[test]
    fn whitelisted_client_key_is_accepted_and_unknown_is_denied() {
        let known = StaticKeypair::generate().expect("keygen").public();
        let unknown = StaticKeypair::generate().expect("keygen").public();

        let mut store = StaticWhitelist::new();
        store.insert(known, "laptop");
        let verifier = WhitelistClientVerifier::new(Arc::new(store), provider());

        assert!(
            verifier
                .verify_client_cert(&CertificateDer::from(known.to_spki().to_vec()), &[], now())
                .is_ok()
        );

        let err = verifier
            .verify_client_cert(
                &CertificateDer::from(unknown.to_spki().to_vec()),
                &[],
                now(),
            )
            .expect_err("unknown key must be denied");

        assert!(
            matches!(
                err,
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure
                )
            ),
            "expected AccessDenied, got {err:?}"
        );
    }

    #[test]
    fn malformed_client_spki_is_a_decode_error_not_a_denial() {
        // The two failures must stay distinguishable: one is a broken peer,
        // the other is a peer that is simply not allowed in.
        let verifier = WhitelistClientVerifier::new(Arc::new(StaticWhitelist::new()), provider());

        for bad in [vec![], vec![0u8; 10], vec![0xffu8; 44]] {
            let err = verifier
                .verify_client_cert(&CertificateDer::from(bad.clone()), &[], now())
                .expect_err("must fail");

            assert!(
                matches!(
                    err,
                    rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
                ),
                "{bad:?} gave {err:?}"
            );
        }
    }

    #[test]
    fn pinned_server_key_accepts_only_itself() {
        let expected = StaticKeypair::generate().expect("keygen").public();
        let other = StaticKeypair::generate().expect("keygen").public();
        let verifier = PinnedServerVerifier::new(expected, provider());

        let name = ServerName::try_from("veil").expect("name");

        assert!(
            verifier
                .verify_server_cert(
                    &CertificateDer::from(expected.to_spki().to_vec()),
                    &[],
                    &name,
                    &[],
                    now()
                )
                .is_ok()
        );

        assert!(
            verifier
                .verify_server_cert(
                    &CertificateDer::from(other.to_spki().to_vec()),
                    &[],
                    &name,
                    &[],
                    now()
                )
                .is_err()
        );
    }

    #[test]
    fn both_verifiers_require_raw_public_keys() {
        // If either of these ever returns false, rustls silently falls back to
        // X.509 and the whole RFC 7250 path stops being exercised.
        let client = WhitelistClientVerifier::new(Arc::new(StaticWhitelist::new()), provider());
        let server = PinnedServerVerifier::new(
            StaticKeypair::generate().expect("keygen").public(),
            provider(),
        );

        assert!(ClientCertVerifier::requires_raw_public_keys(&client));
        assert!(ServerCertVerifier::requires_raw_public_keys(&server));
    }
}
