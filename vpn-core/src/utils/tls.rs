use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    RootCertStore, StreamOwned,
};
use rustls_pemfile::pkcs8_private_keys;
use std::io::{self, BufReader};
use std::{fs::File, net::TcpStream};

pub fn load_certs(path: &str) -> io::Result<Vec<CertificateDer>> {
    Ok(CertificateDer::pem_file_iter(path)
        .unwrap()
        .map(|c| c.unwrap())
        .collect())
}

pub fn load_private_key(path: &str) -> io::Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut keys = pkcs8_private_keys(&mut reader);
    Ok(PrivateKeyDer::Pkcs8(keys.next().unwrap().unwrap()))
}

pub fn load_root_cert_store(path: &str) -> io::Result<RootCertStore> {
    let certs = load_certs(path)?;
    let mut store = RootCertStore::empty();
    for cert in certs {
        store.add(cert).unwrap();
    }
    Ok(store)
}
