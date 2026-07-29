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
        Self {
            fingerprint,
            provider,
        }
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
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Accepts whatever certificate the server presents, and *records* it.
///
/// Used for exactly one thing: the first contact with a machine you are about to pair with, where
/// by definition you do not yet know its certificate. Nothing is trusted as a result — the
/// fingerprint it captures is shown to the user as six digits alongside the same six digits on the
/// other machine, and only a human confirming they match turns it into a pin.
///
/// Kept in this crate next to `PinnedCert` on purpose: a reader looking at how pinning works should
/// see the one case where it is deliberately deferred, rather than find it improvised elsewhere.
#[derive(Debug)]
pub struct TrustOnFirstUse {
    seen: Arc<std::sync::Mutex<Option<[u8; 32]>>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl TrustOnFirstUse {
    pub fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        Self {
            seen: Arc::new(std::sync::Mutex::new(None)),
            provider,
        }
    }

    /// A handle to whatever certificate the server ends up presenting.
    pub fn observed(&self) -> Arc<std::sync::Mutex<Option<[u8; 32]>>> {
        self.seen.clone()
    }
}

impl ServerCertVerifier for TrustOnFirstUse {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.seen.lock().unwrap() = Some(Sha256::digest(end_entity.as_ref()).into());
        Ok(ServerCertVerified::assertion())
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
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
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
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The six digits shown on both machines while pairing.
///
/// **This is the whole security of the approve-on-the-machine flow, so it is worth being precise
/// about why it works.** Neither end has seen the other before, so neither can verify a
/// certificate. What they *can* do is derive a number from **both** certificates and show it to a
/// human on each side.
///
/// Someone sitting in the middle has to terminate two separate TLS connections and therefore
/// presents a different certificate to each end. The two ends then derive different numbers, and
/// the person comparing them sees it. To get away with it an attacker must land on the same six
/// digits by chance: one attempt in a million, with no way to retry silently, because a mismatch is
/// visible and a denial is final.
///
/// Order matters and is fixed — server first, then client — or the two ends would compute
/// different digits from the same pair of certificates and every honest pairing would look like an
/// attack.
pub fn sas(server_fp: &[u8; 32], client_fp: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(b"hublot pairing v1");
    h.update(server_fp);
    h.update(client_fp);
    let digest: [u8; 32] = h.finalize().into();
    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{n:06}")
}

pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
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
        bail!(
            "fingerprint must be 32 hex bytes, got {} hex digits",
            clean.len()
        );
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

    #[test]
    fn sas_is_six_digits_and_stable() {
        let (s, c) = ([1u8; 32], [2u8; 32]);
        let a = sas(&s, &c);
        assert_eq!(a.len(), 6);
        assert!(a.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(a, sas(&s, &c), "both ends must derive the same digits");
    }

    /// The property the whole flow rests on: swap either certificate and the digits change, so a
    /// machine in the middle cannot show the same number to both ends.
    #[test]
    fn sas_changes_if_either_certificate_changes() {
        let base = sas(&[1u8; 32], &[2u8; 32]);
        assert_ne!(base, sas(&[9u8; 32], &[2u8; 32]), "different server cert");
        assert_ne!(base, sas(&[1u8; 32], &[9u8; 32]), "different client cert");
        // And it is not symmetric, or the two ends could disagree about which is which.
        assert_ne!(base, sas(&[2u8; 32], &[1u8; 32]));
    }
}
