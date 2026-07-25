//! Certificate pinning — verify a peer's leaf certificate by SHA-256 and nothing else.
//!
//! Lives here rather than in each client because it is a security primitive, and a codebase should
//! contain exactly one implementation of those. Both the Proxmox link (which pins because the
//! node's cert lists an address it no longer has) and the agent link (which pins because the agent
//! issues its own certificate and there is no CA anywhere) use this same verifier.

use std::sync::Arc;

use anyhow::{bail, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct PinnedCert {
    fingerprint: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl PinnedCert {
    pub fn new(fingerprint: [u8; 32], provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        Self { fingerprint, provider }
    }
}

impl ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if got == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            // Loud on purpose: a rotation and an attack must never look the same.
            Err(rustls::Error::General(format!(
                "certificate pin mismatch: expected {}, got {}",
                hex(&self.fingerprint),
                hex(&got)
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Accepts any structurally valid client certificate, leaving *identity* to the application.
///
/// This is not as lax as it sounds, and the split is deliberate. TLS's job here is to prove the
/// peer holds the private key for the certificate it presented; deciding whether that particular
/// key is allowed in is the agent's allowlist check, which happens before a single keystroke is
/// accepted. Doing it this way keeps the enrolment path (a certificate we have never seen, plus a
/// token) and the steady-state path (a certificate on the allowlist) in one readable place instead
/// of inside a stateful verifier.
#[derive(Debug)]
pub struct AcceptAnyClientCert {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl AcceptAnyClientCert {
    pub fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        Self { provider }
    }
}

impl rustls::server::danger::ClientCertVerifier for AcceptAnyClientCert {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

/// The fingerprint of a DER certificate, hashed exactly as [`PinnedCert`] will hash it.
///
/// Exists so the agent can print the value the panel must pin without either side re-deriving
/// "which bytes, hashed how" — the classic way pinning gets subtly wrong.
pub fn fingerprint_of(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}

/// Parse a `AA:BB:...` SHA-256 fingerprint. Colons optional, case-insensitive.
pub fn parse_fingerprint(s: &str) -> Result<[u8; 32]> {
    let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() != 64 {
        bail!("fingerprint must be 32 hex bytes, got {} hex digits", clean.len());
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_round_trip() {
        let fp = [0xABu8; 32];
        assert_eq!(parse_fingerprint(&hex(&fp)).unwrap(), fp);
        assert_eq!(parse_fingerprint(&"ab".repeat(32)).unwrap(), fp);
    }

    #[test]
    fn wrong_length_is_rejected() {
        assert!(parse_fingerprint("AA:BB").is_err());
    }
}
