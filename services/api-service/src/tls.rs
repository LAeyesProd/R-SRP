//! TLS Configuration - mTLS support for Zero-Trust
//!
//! This module provides mutual TLS (mTLS) configuration for service-to-service
//! communication, aligned with SPIFFE-style certificate validation patterns.

use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
    version::TLS13,
    ClientConfig, RootCertStore, ServerConfig,
};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TlsError {
    #[error("Failed to read certificate: {0}")]
    CertificateRead(String),

    #[error("Failed to parse certificate: {0}")]
    CertificateParse(String),

    #[error("Failed to build TLS config: {0}")]
    ConfigBuild(String),
}

/// TLS configuration for the service
#[derive(Clone, Debug)]
pub struct TlsConfig {
    /// Server certificate chain bytes (PEM or DER)
    pub cert_chain: Vec<u8>,
    /// Server private key bytes (PEM or DER)
    pub private_key: Vec<u8>,
    /// CA certificate bytes for peer verification (mTLS roots)
    pub client_ca: Option<Vec<u8>>,
    /// Whether mTLS is enforced
    pub enforce_mtls: bool,
}

impl TlsConfig {
    /// Load TLS configuration from files
    pub fn from_files(
        cert_path: &Path,
        key_path: &Path,
        client_ca_path: Option<&Path>,
    ) -> Result<Self, TlsError> {
        let cert_chain =
            std::fs::read(cert_path).map_err(|e| TlsError::CertificateRead(e.to_string()))?;
        let private_key =
            std::fs::read(key_path).map_err(|e| TlsError::CertificateRead(e.to_string()))?;

        let client_ca = if let Some(ca_path) = client_ca_path {
            Some(std::fs::read(ca_path).map_err(|e| TlsError::CertificateRead(e.to_string()))?)
        } else {
            None
        };

        Ok(TlsConfig {
            cert_chain,
            private_key,
            enforce_mtls: client_ca.is_some(),
            client_ca,
        })
    }

    /// Build server TLS configuration
    pub fn build_server_config(&self) -> Result<ServerConfig, TlsError> {
        let cert_chain = parse_cert_chain(&self.cert_chain)?;
        let private_key = parse_private_key(&self.private_key)?;

        let builder = ServerConfig::builder_with_protocol_versions(&[&TLS13]);
        let builder = if let Some(ca_bytes) = &self.client_ca {
            let roots = load_root_store(ca_bytes)?;
            let verifier_builder = WebPkiClientVerifier::builder(Arc::new(roots));
            let verifier_builder = if self.enforce_mtls {
                verifier_builder
            } else {
                verifier_builder.allow_unauthenticated()
            };
            let verifier = verifier_builder
                .build()
                .map_err(|e| TlsError::ConfigBuild(e.to_string()))?;
            builder.with_client_cert_verifier(verifier)
        } else {
            builder.with_no_client_auth()
        };

        builder
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| TlsError::ConfigBuild(e.to_string()))
    }

    /// Build client TLS configuration for service-to-service calls
    #[allow(dead_code)]
    pub fn build_client_config(&self, _server_name: &str) -> Result<ClientConfig, TlsError> {
        let ca_bytes = self.client_ca.as_ref().ok_or_else(|| {
            TlsError::ConfigBuild(
                "client CA/root certificate is required for client TLS".to_string(),
            )
        })?;

        let root_store = load_root_store(ca_bytes)?;
        let cert_chain = parse_cert_chain(&self.cert_chain)?;
        let private_key = parse_private_key(&self.private_key)?;

        ClientConfig::builder_with_protocol_versions(&[&TLS13])
            .with_root_certificates(Arc::new(root_store))
            .with_client_auth_cert(cert_chain, private_key)
            .map_err(|e| TlsError::ConfigBuild(e.to_string()))
    }
}

fn parse_cert_chain(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    // Prefer PEM when present; fallback to a single DER certificate blob.
    if bytes.starts_with(b"-----BEGIN") {
        let certs = CertificateDer::pem_slice_iter(bytes)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| TlsError::CertificateParse(e.to_string()))?;
        if !certs.is_empty() {
            return Ok(certs);
        }
    }

    Ok(vec![CertificateDer::from(bytes.to_vec())])
}

fn parse_private_key(bytes: &[u8]) -> Result<PrivateKeyDer<'static>, TlsError> {
    if bytes.starts_with(b"-----BEGIN") {
        if let Ok(key) = PrivateKeyDer::from_pem_slice(bytes) {
            return Ok(key);
        }
    }
    PrivateKeyDer::try_from(bytes.to_vec()).map_err(|e| TlsError::CertificateParse(e.to_string()))
}

fn load_root_store(bytes: &[u8]) -> Result<RootCertStore, TlsError> {
    let mut roots = RootCertStore::empty();
    let certs = parse_cert_chain(bytes)?;
    let (added, _ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(TlsError::CertificateParse(
            "no valid CA/root certificates found".to_string(),
        ));
    }
    Ok(roots)
}
