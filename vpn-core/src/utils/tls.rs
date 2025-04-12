use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    RootCertStore,
};
use rustls_pemfile::pkcs8_private_keys;
use std::fs::File;
use std::io::{self, BufReader};

use crate::Result;

pub fn load_certs(path: &str) -> Result<Vec<CertificateDer>> {
    Ok(CertificateDer::pem_file_iter(path)
        .unwrap()
        .map(|c| c.unwrap())
        .collect())
}

pub fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut keys = pkcs8_private_keys(&mut reader);
    Ok(PrivateKeyDer::Pkcs8(keys.next().unwrap().unwrap()))
}

/// Root cert store is misleading. We're referring to the CA that signed the peer certificate
pub fn load_root_cert_store(path: &str) -> Result<RootCertStore> {
    let certs = load_certs(path)?;
    let mut store = RootCertStore::empty();
    for cert in certs {
        store.add(cert).unwrap();
    }
    Ok(store)
}
