//! Assembling rustls configurations that speak raw public keys.

use std::any::Any;
use std::sync::Arc;

use rustls::client::AlwaysResolvesClientRawPublicKeys;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::server::AlwaysResolvesServerRawPublicKeys;
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ServerConfig};

use crate::{
    Error, KeyWhitelist, PinnedServerVerifier, PublicKey, StaticKeypair, WhitelistClientVerifier,
};

/// The crypto provider VEIL uses everywhere.
///
/// Chosen at M1: `aws-lc-rs` is rustls' own default, and both candidate
/// providers supported Ed25519 equally.
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// Packages a keypair as the raw public key this end will present.
fn certified_key(keypair: &StaticKeypair) -> Result<Arc<CertifiedKey>, Error> {
    let der = PrivatePkcs8KeyDer::from(keypair.to_pkcs8().to_vec());

    let signing = rustls::crypto::aws_lc_rs::sign::any_eddsa_type(&der)
        .map_err(|e| Error::MalformedKey(format!("provider rejected the Ed25519 key: {e}")))?;

    // Under RFC 7250 the "certificate chain" is a single SubjectPublicKeyInfo.
    let spki = CertificateDer::from(keypair.public().to_spki().to_vec());

    Ok(Arc::new(CertifiedKey::new(vec![spki], signing)))
}

/// Builds the server's TLS configuration.
///
/// The server presents `keypair` as a raw public key and accepts only clients
/// whose key is in `whitelist`. Client authentication is mandatory: there is no
/// anonymous path into a VEIL server.
pub fn server_config(
    keypair: &StaticKeypair,
    whitelist: Arc<dyn KeyWhitelist>,
    provider: Arc<CryptoProvider>,
) -> Result<ServerConfig, Error> {
    let key = certified_key(keypair)?;
    let verifier = Arc::new(WhitelistClientVerifier::new(whitelist, provider.clone()));

    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(key)));

    // QUIC permits only 0 or u32::MAX here; see quinn's QuicServerConfig.
    config.max_early_data_size = u32::MAX;
    Ok(config)
}

/// Builds the client's TLS configuration.
///
/// The client presents `keypair` and accepts only `server` as the peer.
pub fn client_config(
    keypair: &StaticKeypair,
    server: PublicKey,
    provider: Arc<CryptoProvider>,
) -> Result<ClientConfig, Error> {
    let key = certified_key(keypair)?;
    let verifier = Arc::new(PinnedServerVerifier::new(server, provider.clone()));

    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(key)));

    Ok(config)
}

/// Recovers the peer's key from `quinn::Connection::peer_identity`.
///
/// This is how identity reaches the session table: it comes back out of the
/// completed handshake, so it cannot disagree with what TLS actually verified.
/// v1 assigned an address and then threw the identity away, which is why
/// anti-spoofing and attribution were structurally impossible.
///
/// Returns `None` if the connection was not authenticated or did not use a raw
/// public key.
pub fn peer_public_key(identity: &dyn Any) -> Option<PublicKey> {
    let chain = identity.downcast_ref::<Vec<CertificateDer<'static>>>()?;
    PublicKey::from_spki(chain.first()?.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StaticWhitelist;

    #[test]
    fn provider_accepts_our_ed25519_keys() {
        // The M1 risk in one assertion: if aws-lc-rs cannot parse the PKCS#8
        // we produce, everything downstream is theoretical.
        let keypair = StaticKeypair::generate().expect("keygen");
        assert!(certified_key(&keypair).is_ok());
    }

    #[test]
    fn certified_key_presents_the_matching_public_key() {
        let keypair = StaticKeypair::generate().expect("keygen");
        let key = certified_key(&keypair).expect("certified key");

        let presented = PublicKey::from_spki(key.cert.first().expect("one entry").as_ref());
        assert_eq!(presented, Some(keypair.public()));
    }

    #[test]
    fn both_configs_build() {
        let server_key = StaticKeypair::generate().expect("keygen");
        let client_key = StaticKeypair::generate().expect("keygen");

        let mut store = StaticWhitelist::new();
        store.insert(client_key.public(), "laptop");

        assert!(server_config(&server_key, Arc::new(store), provider()).is_ok());
        assert!(client_config(&client_key, server_key.public(), provider()).is_ok());
    }
}
