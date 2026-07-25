//! What every Hublot agent has in common: an identity, an allowlist, and the rule for letting a
//! panel in.
//!
//! Deliberately says nothing about *what* is being mirrored. A Linux console agent ships a grid of
//! characters and a Windows agent ships rectangles of pixels; they agree completely on who is
//! allowed to ask. Writing that agreement twice is how two copies of a security decision start
//! disagreeing — the same reasoning that put certificate pinning in its own crate.

pub mod audit;

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use protocol::{Auth, ClientMsg, ServerMsg, ALPN, PROTOCOL_VERSION};

pub struct Identity {
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
    pub token: String,
    pub fingerprint: [u8; 32],
    dir: std::path::PathBuf,
    allowed: Mutex<HashSet<String>>,
}

impl Identity {
    /// Load the agent's certificate, key, pairing token and client allowlist, creating whatever is
    /// missing. Call once at startup.
    pub fn load_or_create(dir: impl Into<std::path::PathBuf>) -> Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let (cert_path, key_path, token_path) =
            (dir.join("cert.der"), dir.join("key.der"), dir.join("token"));

        if !cert_path.exists() {
            let ck = rcgen::generate_simple_self_signed(vec!["hublot-agent".to_string()])
                .context("generating certificate")?;
            std::fs::write(&cert_path, ck.cert.der())?;
            std::fs::write(&key_path, ck.key_pair.serialize_der())?;
            restrict(&key_path)?;
        }
        if !token_path.exists() {
            let raw = random_32().context("reading system randomness")?;
            std::fs::write(
                &token_path,
                format!("{}\n", raw.iter().map(|b| format!("{b:02x}")).collect::<String>()),
            )?;
            restrict(&token_path)?;
        }

        let cert = std::fs::read(&cert_path)?;
        let key = std::fs::read(&key_path)?;
        let token = std::fs::read_to_string(&token_path)?.trim().to_string();
        if token.len() < 32 {
            bail!("token in {} looks too short to be the generated one", token_path.display());
        }
        let allowed = std::fs::read_to_string(dir.join("clients"))
            .map(|s| s.lines().map(|l| l.trim().to_uppercase()).filter(|l| !l.is_empty()).collect())
            .unwrap_or_default();

        Ok(Self {
            fingerprint: pinning::fingerprint_of(&cert),
            cert,
            key,
            token,
            dir,
            allowed: Mutex::new(allowed),
        })
    }

    pub fn is_allowed(&self, fp: &str) -> bool {
        self.allowed.lock().unwrap().contains(&fp.to_uppercase())
    }

    pub fn has_enrolled_clients(&self) -> bool {
        !self.allowed.lock().unwrap().is_empty()
    }

    /// Note something that happened, beside the identity it happened to.
    pub fn audit(&self, event: &str) {
        audit::record(&self.dir, event);
    }

    pub fn enrol(&self, fp: &str) -> Result<()> {
        let path = self.dir.join("clients");
        let mut set = self.allowed.lock().unwrap();
        set.insert(fp.to_uppercase());
        std::fs::write(&path, format!("{}\n", set.iter().cloned().collect::<Vec<_>>().join("\n")))?;
        restrict(&path)?;
        Ok(())
    }
}

/// 32 bytes from the system CSPRNG — `getrandom` on Linux, `BCryptGenRandom` on Windows.
///
/// This is the pairing token, so it gets the real thing rather than anything improvised.
fn random_32() -> Result<[u8; 32]> {
    let mut raw = [0u8; 32];
    // getrandom's error type predates std::error::Error, so map it rather than `?` it.
    getrandom::getrandom(&mut raw).map_err(|e| anyhow::anyhow!("system randomness: {e}"))?;
    Ok(raw)
}

#[cfg(unix)]
fn restrict(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict(_path: &std::path::Path) -> Result<()> {
    // Windows inherits the user profile's ACL, which already excludes other users.
    Ok(())
}

pub fn server_config(id: &Identity) -> Result<quinn::ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("tls versions")?
        .with_client_cert_verifier(Arc::new(pinning::AcceptAnyClientCert::new(provider)))
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(id.cert.clone())],
            rustls::pki_types::PrivatePkcs8KeyDer::from(id.key.clone()).into(),
        )
        .context("server tls config")?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    Ok(quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).context("quic tls")?,
    )))
}

/// Compare without an early return on the first differing byte.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The fingerprint of the certificate the peer proved it holds the key for.
pub fn peer_fingerprint(conn: &quinn::Connection) -> Option<String> {
    let identity = conn.peer_identity()?;
    let chain = identity.downcast::<Vec<rustls::pki_types::CertificateDer>>().ok()?;
    Some(pinning::hex(&pinning::fingerprint_of(chain.first()?)))
}

/// Read the client's `Hello` and decide whether to let it in.
///
/// The token authorises **enrolment only**, once, and only while pairing is open. Sessions are
/// authorised by the client certificate the TLS handshake already proved possession of.
pub async fn authenticate(
    conn: &quinn::Connection,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    id: &Identity,
    pairing_open: bool,
) -> Result<String> {
    let peer = conn.remote_address();
    let Some(fingerprint) = peer_fingerprint(conn) else {
        id.audit(&format!("{peer} REFUSED no client certificate"));
        bail!("{peer}: client presented no certificate");
    };

    // Capped hard: at this point the peer is anyone who can complete a TLS handshake, because
    // enrolment must accept a certificate we have never seen. See `read_msg_capped`.
    let ClientMsg::Hello { version, auth } =
        protocol::read_msg_capped(recv, protocol::MAX_HELLO).await?
    else {
        id.audit(&format!("{peer} {fingerprint} REFUSED first message was not Hello"));
        bail!("{peer}: first message was not Hello");
    };
    if version != PROTOCOL_VERSION {
        let _ = protocol::write_msg(
            send,
            &ServerMsg::Error(format!("protocol {version} unsupported, want {PROTOCOL_VERSION}")),
        )
        .await;
        id.audit(&format!("{peer} {fingerprint} REFUSED protocol {version}"));
        bail!("{peer}: protocol mismatch");
    }

    match auth {
        Auth::Certificate if id.is_allowed(&fingerprint) => {}
        Auth::Certificate => {
            let _ =
                protocol::write_msg(send, &ServerMsg::Error("certificate not enrolled".into())).await;
            id.audit(&format!("{peer} {fingerprint} REFUSED unenrolled certificate"));
            bail!("{peer}: unenrolled certificate {fingerprint}");
        }
        Auth::Enrol { token } => {
            if !pairing_open {
                let _ = protocol::write_msg(
                    send,
                    &ServerMsg::Error("pairing is closed; restart the agent with --pair".into()),
                )
                .await;
                id.audit(&format!("{peer} {fingerprint} REFUSED enrolment while pairing closed"));
                bail!("{peer}: enrolment attempted while pairing closed");
            }
            if !constant_time_eq(&token, &id.token) {
                let _ = protocol::write_msg(send, &ServerMsg::Error("bad token".into())).await;
                // The token itself is never logged, right or wrong: a near-miss in a log file is a
                // gift to whoever reads the log.
                id.audit(&format!("{peer} {fingerprint} REFUSED bad pairing token"));
                bail!("{peer}: enrolment rejected — bad token");
            }
            id.enrol(&fingerprint)?;
            id.audit(&format!("{peer} {fingerprint} ENROLLED"));
            protocol::write_msg(send, &ServerMsg::Enrolled).await?;
        }
    }
    id.audit(&format!("{peer} {fingerprint} ACCEPTED"));
    Ok(fingerprint)
}
