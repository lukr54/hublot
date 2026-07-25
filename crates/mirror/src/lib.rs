//! Client side of the agent link.
//!
//! Reassembles the agent's diffs into a whole screen and hands the *complete* grid to the caller
//! every time. The wire is diffed because the network deserves it; consumers are not, because a UI
//! that has to apply patches is a UI with a desync bug in its future.
//!
//! From Phase 3 the link is mutually authenticated: this client holds its own certificate, and the
//! agent recognises it by fingerprint. The pairing token is used exactly once, to get that
//! fingerprint onto the agent's allowlist.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use protocol::{Auth, ClientMsg, Screen, ServerMsg, ALPN, PROTOCOL_VERSION};
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub enum Event {
    Connected,
    /// The agent is asking the person at that machine whether to allow us. These six digits are
    /// showing on its screen too, and the user compares them.
    Confirm { sas: String },
    /// Our certificate was just added to the agent's allowlist.
    ///
    /// Carries the fingerprint we observed, because for an approval pairing this is the moment the
    /// caller learns which certificate to pin from now on — a first contact has nothing to pin
    /// until a human has confirmed it.
    Enrolled { fingerprint: String },
    /// Whether this session may inject keys, and why not if it may not.
    Input { enabled: bool, reason: String },
    Screen(Screen),
    /// This agent mirrors a graphical desktop rather than a text console.
    ScreenInfo { w: u16, h: u16 },
    /// A changed rectangle of that desktop, already compressed.
    Raster { x: u16, y: u16, w: u16, h: u16, mime: &'static str, data: Vec<u8> },
    /// Where the remote pointer is, and what it looks like — both arrive outside the frames.
    Pointer { x: i16, y: i16, visible: bool },
    PointerShape { w: u16, h: u16, hot_x: u16, hot_y: u16, png: Vec<u8> },
    /// Text copied on the remote machine.
    Clipboard(String),
    Closed(String),
}

/// This panel's own certificate. Generated once, then reused — its fingerprint *is* our identity
/// as far as the agent is concerned, so losing it means re-pairing.
#[derive(Clone)]
pub struct ClientIdentity {
    cert: Vec<u8>,
    key: Vec<u8>,
    pub fingerprint: String,
}

impl ClientIdentity {
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let (cert_path, key_path) = (dir.join("client-cert.der"), dir.join("client-key.der"));
        if !cert_path.exists() || !key_path.exists() {
            let ck = rcgen::generate_simple_self_signed(vec!["hublot-panel".to_string()])
                .context("generating client certificate")?;
            std::fs::write(&cert_path, ck.cert.der())?;
            std::fs::write(&key_path, ck.key_pair.serialize_der())?;
        }
        let cert = std::fs::read(&cert_path)?;
        let key = std::fs::read(&key_path)?;
        Ok(Self {
            fingerprint: protocol::pin::hex(&protocol::pin::fingerprint_of(&cert)),
            cert,
            key,
        })
    }
}

/// What we know about the machine we are dialling, which on a first contact is nothing.
type Observed = Arc<std::sync::Mutex<Option<[u8; 32]>>>;

fn client_config(
    server_fingerprint: Option<[u8; 32]>,
    id: &ClientIdentity,
) -> Result<(quinn::ClientConfig, Option<Observed>)> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    // Pin when we know what to pin to. On a first contact we do not, so the certificate is merely
    // *recorded* — it becomes trusted only once a human has compared six digits on both machines,
    // and from the next connection onwards this branch is never taken again for that machine.
    let (verifier, observed): (Arc<dyn rustls::client::danger::ServerCertVerifier>, _) =
        match server_fingerprint {
            Some(fp) => (Arc::new(protocol::pin::PinnedCert::new(fp, provider.clone())), None),
            None => {
                let tofu = protocol::pin::TrustOnFirstUse::new(provider.clone());
                let seen = tofu.observed();
                (Arc::new(tofu), Some(seen))
            }
        };
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("tls versions")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(
            vec![rustls::pki_types::CertificateDer::from(id.cert.clone())],
            rustls::pki_types::PrivatePkcs8KeyDer::from(id.key.clone()).into(),
        )
        .context("client auth cert")?;
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let mut cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).context("quic tls")?,
    ));

    // **Keepalive is mandatory here, not a nicety.** The agent is event-driven: an idle console
    // produces no frames at all, by design. Without PINGs the connection meets QUIC's idle timeout
    // and dies after ~30 s — and an idle console is the normal case, since a login prompt sitting
    // untouched is exactly when you glance at the mirror. Found by watching a real link for 75 s;
    // a short test cannot see this.
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    transport.max_idle_timeout(Some(
        std::time::Duration::from_secs(30).try_into().context("idle timeout")?,
    ));
    cfg.transport_config(Arc::new(transport));
    Ok((cfg, observed))
}

/// Connect and stream until the link drops.
///
/// `outbound` carries key events toward the agent. It is a separate task from the screen loop
/// because the two directions are independent: a burst of console output must never delay a key
/// release, and a `read` cancelled mid-message would desynchronise the stream.
pub async fn stream(
    addr: SocketAddr,
    server_fingerprint: Option<[u8; 32]>,
    identity: ClientIdentity,
    auth: Auth,
    tx: mpsc::Sender<Event>,
    mut outbound: mpsc::Receiver<ClientMsg>,
) -> Result<()> {
    let mut endpoint =
        quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).context("binding client endpoint")?;
    let (cfg, observed) = client_config(server_fingerprint, &identity)?;
    endpoint.set_default_client_config(cfg);

    let conn = endpoint
        .connect(addr, "hublot-agent")
        .context("connect")?
        .await
        .context("handshake")?;

    let (mut send, mut recv) = conn.open_bi().await.context("opening stream")?;
    protocol::write_msg(&mut send, &ClientMsg::Hello { version: PROTOCOL_VERSION, auth }).await?;
    let _ = tx.send(Event::Connected).await;

    // One writer owns the send half.
    let writer = tokio::spawn(async move {
        while let Some(msg) = outbound.recv().await {
            if protocol::write_msg(&mut send, &msg).await.is_err() {
                return;
            }
        }
    });

    let result = read_loop(&mut recv, &tx, observed).await;
    writer.abort();
    result
}

async fn read_loop(
    recv: &mut quinn::RecvStream,
    tx: &mpsc::Sender<Event>,
    observed: Option<Observed>,
) -> Result<()> {
    let mut screen: Option<Screen> = None;
    loop {
        let msg: ServerMsg = match protocol::read_msg(recv).await {
            Ok(m) => m,
            Err(e) => {
                let _ = tx.send(Event::Closed(format!("{e:#}"))).await;
                return Ok(());
            }
        };

        match msg {
            ServerMsg::Full(s) => screen = Some(s),
            ServerMsg::Diff { vt, cursor, runs } => {
                let Some(current) = screen.as_mut() else {
                    bail!("agent sent a diff before any full frame");
                };
                // A diff for a VT we aren't holding means we missed a switch: refuse to paint
                // rather than smear one console's text over another's.
                if current.vt != vt || !protocol::apply(current, &runs) {
                    let _ = tx.send(Event::Closed("desynchronised from the agent".into())).await;
                    return Ok(());
                }
                current.cursor = cursor;
            }
            ServerMsg::Confirm { sas } => {
                let _ = tx.send(Event::Confirm { sas }).await;
                continue;
            }
            ServerMsg::Enrolled => {
                // On an approval pairing this is the first moment the certificate means anything:
                // a human has just said the digits matched, so the fingerprint we recorded during
                // the handshake is now the one to pin forever after.
                let fingerprint = observed
                    .as_ref()
                    .and_then(|o| *o.lock().unwrap())
                    .map(|fp| protocol::pin::hex(&fp))
                    .unwrap_or_default();
                let _ = tx.send(Event::Enrolled { fingerprint }).await;
                continue;
            }
            ServerMsg::Input { enabled, reason } => {
                let _ = tx.send(Event::Input { enabled, reason }).await;
                continue;
            }
            ServerMsg::ScreenInfo { w, h } => {
                let _ = tx.send(Event::ScreenInfo { w, h }).await;
                continue;
            }
            ServerMsg::Raster { x, y, w, h, format, data } => {
                let _ = tx
                    .send(Event::Raster { x, y, w, h, mime: format.mime(), data })
                    .await;
                continue;
            }
            ServerMsg::Clipboard { text } => {
                let _ = tx.send(Event::Clipboard(text)).await;
                continue;
            }
            ServerMsg::Pointer { x, y, visible } => {
                let _ = tx.send(Event::Pointer { x, y, visible }).await;
                continue;
            }
            ServerMsg::PointerShape { w, h, hot_x, hot_y, png } => {
                let _ = tx.send(Event::PointerShape { w, h, hot_x, hot_y, png }).await;
                continue;
            }
            ServerMsg::Error(e) => {
                let _ = tx.send(Event::Closed(format!("agent refused us: {e}"))).await;
                return Ok(());
            }
        }

        if let Some(s) = screen.as_ref() {
            if tx.send(Event::Screen(s.clone())).await.is_err() {
                return Ok(()); // consumer went away
            }
        }
    }
}
