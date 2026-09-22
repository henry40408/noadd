use rustls::ServerConfig;
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io;
use std::path::Path;
use std::sync::Arc;

/// Load a TLS configuration from PEM-encoded certificate and private key files.
pub fn load_tls_config(cert_path: &Path, key_path: &Path) -> io::Result<Arc<ServerConfig>> {
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;

    let certs: Vec<_> = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let key = PrivateKeyDer::from_pem_slice(&key_pem).map_err(|e| match e {
        pem::Error::NoItemsFound => io::Error::new(
            io::ErrorKind::InvalidData,
            "no private key found in PEM file",
        ),
        e => io::Error::new(io::ErrorKind::InvalidData, e),
    })?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(Arc::new(config))
}
