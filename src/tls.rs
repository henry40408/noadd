use rustls::ServerConfig;
use std::io;
use std::path::Path;
use std::sync::Arc;

/// Load a TLS configuration from PEM-encoded certificate and private key files.
pub fn load_tls_config(cert_path: &Path, key_path: &Path) -> io::Result<Arc<ServerConfig>> {
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no private key found in PEM file"))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(Arc::new(config))
}
