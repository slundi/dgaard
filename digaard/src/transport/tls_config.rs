//! Shared rustls `ClientConfig` construction for DoT and DoH.
//!
//! Handles `--tls-servername`, `--tls-insecure`, and `--tls-ca` from `TlsSettings`.

use std::sync::Arc;

use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};

use super::TlsSettings;
use crate::error::{Error, Result};

/// Build a `ClientConfig` from `TlsSettings` and the requested ALPN protocols.
pub fn build_client_config(settings: &TlsSettings, alpn: &[&[u8]]) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    for pem in &settings.extra_ca_pem {
        add_ca_pem(&mut roots, pem)?;
    }

    let mut cfg = if settings.insecure {
        log::warn!("--tls-insecure: certificate verification is DISABLED");
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };

    if !alpn.is_empty() {
        cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    }

    Ok(Arc::new(cfg))
}

/// Resolve the SNI name for the TLS handshake.
///
/// Uses `--tls-servername` if set, otherwise the server address (which must be
/// a valid DNS name — IPs get rejected by rustls with a clear error).
pub fn server_name<'a>(
    settings: &'a TlsSettings,
    fallback: &'a str,
) -> Result<ServerName<'static>> {
    let raw = settings.servername.as_deref().unwrap_or(fallback);
    ServerName::try_from(raw)
        .map_err(|e| Error::Transport(format!("invalid server name '{raw}': {e}")))
        .map(|n| n.to_owned())
}

fn add_ca_pem(store: &mut RootCertStore, pem: &[u8]) -> Result<()> {
    let mut cursor = std::io::Cursor::new(pem);
    let mut added = 0usize;
    for item in rustls_pemfile::certs(&mut cursor) {
        let cert = item.map_err(|e| Error::Transport(format!("--tls-ca: parse error: {e}")))?;
        store
            .add(cert)
            .map_err(|e| Error::Transport(format!("--tls-ca: add root: {e}")))?;
        added += 1;
    }
    if added == 0 {
        return Err(Error::Transport(
            "--tls-ca: no certificates parsed from file".to_string(),
        ));
    }
    Ok(())
}

/// TLS 1.2 & 1.3 verifier that skips ALL validation. `--tls-insecure`.
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Advertise the rustls default set.
        rustls::crypto::CryptoProvider::get_default()
            .map(|p| p.signature_verification_algorithms.supported_schemes())
            .unwrap_or_default()
    }
}
