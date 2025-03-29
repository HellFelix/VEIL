use std::{io, sync::Arc};

use rustls::{server::WebPkiClientVerifier, version::TLS13, ServerConfig};

use vpn_core::utils::tls::*;

pub fn get_tls_config() -> io::Result<ServerConfig> {
    let server_cert = load_certs("../certs/server.crt")?;
    let server_key = load_private_key("../certs/server.key")?;
    let client_auth_roots = load_root_cert_store("../certs/clientCA.pem")?;

    let verifier = WebPkiClientVerifier::builder(Arc::new(client_auth_roots))
        .build()
        .unwrap();

    Ok(ServerConfig::builder_with_protocol_versions(&[&TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_cert, server_key)
        .unwrap())
}
