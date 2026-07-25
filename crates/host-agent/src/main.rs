//! Hublot host agent — Phases 2 and 3.
//!
//! Watches the active text console, streams it to the panel, and (Phase 3) injects the keys the
//! panel sends back. Everything it needs is group `tty` for `/dev/vcs*` and access to
//! `/dev/uinput`. Not root. See THREAT-MODEL.md §5 and R1.
//!
//! **This binary can type at a root prompt.** Two structural things keep that honest:
//!
//! * Identity is a client certificate proven at the TLS handshake and checked against an
//!   allowlist. The printed token authorises *enrolling* a certificate, once — never a session.
//! * The virtual keyboard belongs to a connection, not to the process, so no held key can outlive
//!   the session that pressed it (see `uinput.rs`).

mod uinput;
mod vcs;

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use protocol::{Auth, ClientMsg, ServerMsg, ALPN, PROTOCOL_VERSION};
use tokio::sync::broadcast;

const DEFAULT_LISTEN: &str = "0.0.0.0:7842";

fn state_dir() -> std::path::PathBuf {
    std::env::var("HUBLOT_STATE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/var/lib/hublot"))
}

struct Identity {
    cert: Vec<u8>,
    key: Vec<u8>,
    token: String,
    fingerprint: [u8; 32],
    /// Client certificate fingerprints permitted to connect.
    allowed: Mutex<HashSet<String>>,
}

impl Identity {
    fn allowlist_path() -> std::path::PathBuf {
        state_dir().join("clients")
    }

    fn load_or_create() -> Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        let dir = state_dir();
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let (cert_path, key_path, token_path) =
            (dir.join("cert.der"), dir.join("key.der"), dir.join("token"));

        if !cert_path.exists() {
            let ck = rcgen::generate_simple_self_signed(vec!["hublot-agent".to_string()])
                .context("generating certificate")?;
            std::fs::write(&cert_path, ck.cert.der())?;
            std::fs::write(&key_path, ck.key_pair.serialize_der())?;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        }
        if !token_path.exists() {
            // Exactly 32 bytes — /dev/urandom never returns EOF, so read-to-end would never stop.
            use std::io::{Read, Write};
            let mut raw = [0u8; 32];
            std::fs::File::open("/dev/urandom")
                .context("opening /dev/urandom")?
                .read_exact(&mut raw)
                .context("reading /dev/urandom")?;
            let mut f = std::fs::File::create(&token_path)?;
            writeln!(f, "{}", raw.iter().map(|b| format!("{b:02x}")).collect::<String>())?;
            std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))?;
        }

        let cert = std::fs::read(&cert_path)?;
        let key = std::fs::read(&key_path)?;
        let token = std::fs::read_to_string(&token_path)?.trim().to_string();
        if token.len() < 32 {
            bail!("token in {} looks too short to be the generated one", token_path.display());
        }
        let allowed = std::fs::read_to_string(Self::allowlist_path())
            .map(|s| s.lines().map(|l| l.trim().to_uppercase()).filter(|l| !l.is_empty()).collect())
            .unwrap_or_default();

        Ok(Self {
            fingerprint: protocol::pin::fingerprint_of(&cert),
            cert,
            key,
            token,
            allowed: Mutex::new(allowed),
        })
    }

    fn is_allowed(&self, fp: &str) -> bool {
        self.allowed.lock().unwrap().contains(&fp.to_uppercase())
    }

    fn enrol(&self, fp: &str) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let mut set = self.allowed.lock().unwrap();
        set.insert(fp.to_uppercase());
        let body = set.iter().cloned().collect::<Vec<_>>().join("\n");
        std::fs::write(Self::allowlist_path(), format!("{body}\n"))?;
        std::fs::set_permissions(Self::allowlist_path(), std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    fn has_enrolled_clients(&self) -> bool {
        !self.allowed.lock().unwrap().is_empty()
    }
}

fn watcher(tx: broadcast::Sender<protocol::Screen>) -> Result<()> {
    let mut vt = vcs::Console::active_vt()?;
    let mut console = vcs::Console::open(vt)?;
    let mut previous: Option<protocol::Screen> = None;

    loop {
        console.wait(2000)?;
        let now = vcs::Console::active_vt()?;
        if now != vt {
            vt = now;
            console = vcs::Console::open(vt)?;
            previous = None;
        }
        let Ok(screen) = console.read() else { continue };
        if previous.as_ref() != Some(&screen) {
            let _ = tx.send(screen.clone());
            previous = Some(screen);
        }
    }
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
fn peer_fingerprint(conn: &quinn::Connection) -> Option<String> {
    let identity = conn.peer_identity()?;
    let chain = identity.downcast::<Vec<rustls::pki_types::CertificateDer>>().ok()?;
    let leaf = chain.first()?;
    Some(protocol::pin::hex(&protocol::pin::fingerprint_of(leaf)))
}

/// Read keys from the panel and press them. Owns the virtual keyboard: when this future is
/// dropped — client gone, connection lost, task aborted — the device dies and the kernel releases
/// anything still held.
async fn input_loop(mut recv: quinn::RecvStream, mut kb: uinput::VirtualKeyboard) {
    eprintln!("[hublot] input loop ready");
    // Counts only — never which keys. THREAT-MODEL §10: this process must not become a keylogger
    // with a log file.
    let mut received = 0u64;
    let mut injected = 0u64;
    loop {
        match protocol::read_msg::<ClientMsg>(&mut recv).await {
            Ok(ClientMsg::Key { code, down }) => {
                received += 1;
                match kb.key(code, down) {
                    Ok(true) => injected += 1,
                    Ok(false) => {}
                    Err(e) => {
                        eprintln!("[hublot] injection failed after {injected} events: {e}");
                        return;
                    }
                }
                if received % 8 == 0 {
                    eprintln!("[hublot] input: {received} received, {injected} injected");
                }
            }
            Ok(ClientMsg::ReleaseAll) => {
                let _ = kb.release_all();
            }
            Ok(ClientMsg::SwitchVt { vt }) => {
                // Let go before leaving: a key held down on the console we are departing has no
                // one to release it afterwards.
                let _ = kb.release_all();
                match vcs::Console::switch_to(vt) {
                    Ok(()) => eprintln!("[hublot] switched to tty{vt} by ioctl"),
                    Err(e) => eprintln!("[hublot] could not switch to tty{vt}: {e}"),
                }
            }
            // Every exit below used to be silent, which is exactly why a dead input loop was
            // indistinguishable from a working one that received nothing.
            Ok(ClientMsg::Hello { .. }) => {
                eprintln!("[hublot] input loop stopping: unexpected second Hello");
                return;
            }
            Err(e) => {
                eprintln!(
                    "[hublot] input loop stopping after {received} received / {injected} injected: {e:#}"
                );
                return;
            }
        }
    }
}

async fn serve_connection(
    incoming: quinn::Incoming,
    id: Arc<Identity>,
    pairing_open: bool,
    tx: broadcast::Sender<protocol::Screen>,
) -> Result<()> {
    let conn = incoming.await.context("handshake")?;
    let peer = conn.remote_address();
    let fingerprint = peer_fingerprint(&conn).context("client presented no certificate")?;
    let (mut send, mut recv) = conn.accept_bi().await.context("accepting stream")?;

    let hello: ClientMsg = protocol::read_msg(&mut recv).await?;
    let ClientMsg::Hello { version, auth } = hello else {
        bail!("{peer}: first message was not Hello");
    };
    if version != PROTOCOL_VERSION {
        let _ = protocol::write_msg(
            &mut send,
            &ServerMsg::Error(format!("protocol {version} unsupported, want {PROTOCOL_VERSION}")),
        )
        .await;
        bail!("{peer}: protocol mismatch");
    }

    match auth {
        Auth::Certificate if id.is_allowed(&fingerprint) => {}
        Auth::Certificate => {
            let _ = protocol::write_msg(&mut send, &ServerMsg::Error("certificate not enrolled".into())).await;
            bail!("{peer}: unenrolled certificate {fingerprint}");
        }
        Auth::Enrol { token } => {
            if !pairing_open {
                let _ = protocol::write_msg(
                    &mut send,
                    &ServerMsg::Error("pairing is closed; restart the agent with --pair".into()),
                )
                .await;
                bail!("{peer}: enrolment attempted while pairing closed");
            }
            if !constant_time_eq(&token, &id.token) {
                let _ = protocol::write_msg(&mut send, &ServerMsg::Error("bad token".into())).await;
                bail!("{peer}: enrolment rejected — bad token");
            }
            id.enrol(&fingerprint)?;
            eprintln!("[hublot] enrolled client {fingerprint}");
            protocol::write_msg(&mut send, &ServerMsg::Enrolled).await?;
        }
    }
    eprintln!("[hublot] {peer} authenticated as {fingerprint}");

    // Injection is optional: an agent that cannot open /dev/uinput still mirrors perfectly well,
    // and saying so beats swallowing keystrokes in silence.
    let keyboard = tokio::task::spawn_blocking(uinput::VirtualKeyboard::create)
        .await
        .context("spawning uinput setup")?;
    let uinput_ok = keyboard.is_ok();
    let input_task = match keyboard {
        Ok(kb) => Some(tokio::spawn(input_loop(recv, kb))),
        Err(e) => {
            eprintln!("[hublot] input disabled: {e}");
            None
        }
    };
    report_injectability(&mut send, uinput_ok).await?;

    let result = stream_screens(&mut send, tx, uinput_ok).await;
    // Ends the input task, which drops the keyboard, which releases every held key.
    if let Some(t) = input_task {
        t.abort();
    }
    result
}

/// Tell the panel whether keys will actually do anything on the console it is looking at.
///
/// "We wrote the event" and "the machine acted on it" are different claims, and conflating them is
/// what made D13 take an afternoon. This reports the second one honestly.
async fn report_injectability(
    send: &mut quinn::SendStream,
    uinput_ok: bool,
) -> Result<()> {
    let (enabled, reason) = if !uinput_ok {
        (false, "/dev/uinput unavailable".to_string())
    } else {
        match vcs::Console::keyboard_accepts_input() {
            Ok((_, true)) => (true, String::new()),
            Ok((mode, false)) => (
                false,
                format!("this console is in {}", vcs::Console::describe_kbd_mode(mode)),
            ),
            Err(e) => (false, format!("cannot read console keyboard mode: {e}")),
        }
    };
    protocol::write_msg(send, &ServerMsg::Input { enabled, reason }).await
}

async fn stream_screens(
    send: &mut quinn::SendStream,
    tx: broadcast::Sender<protocol::Screen>,
    uinput_ok: bool,
) -> Result<()> {
    let mut rx = tx.subscribe();
    let mut last: Option<protocol::Screen> = None;

    // Whatever is on screen right now, before waiting for it to change.
    if let Ok(vt) = vcs::Console::active_vt() {
        if let Ok(mut c) = vcs::Console::open(vt) {
            if let Ok(screen) = c.read() {
                protocol::write_msg(send, &ServerMsg::Full(screen.clone())).await?;
                last = Some(screen);
            }
        }
    }

    loop {
        let screen = match rx.recv().await {
            Ok(s) => s,
            Err(broadcast::error::RecvError::Lagged(_)) => {
                last = None; // resynchronise with a full frame
                continue;
            }
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        };
        // A VT change means the answer to "will keys land here?" may have changed with it.
        let switched = last.as_ref().is_none_or(|prev| prev.vt != screen.vt);
        let msg = match last.as_ref().and_then(|prev| protocol::diff(prev, &screen)) {
            Some(runs) => ServerMsg::Diff { vt: screen.vt, cursor: screen.cursor, runs },
            None => ServerMsg::Full(screen.clone()),
        };
        protocol::write_msg(send, &msg).await?;
        if switched {
            report_injectability(send, uinput_ok).await?;
        }
        last = Some(screen);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let id = Arc::new(Identity::load_or_create()?);
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--pairing") {
        println!("fingerprint: {}", protocol::pin::hex(&id.fingerprint));
        println!("token:       {}", id.token);
        return Ok(());
    }

    // Enrolment is open when explicitly asked for, or when nobody is enrolled yet — otherwise a
    // leaked token is a permanent way in rather than a one-time one.
    let pairing_open = args.iter().any(|a| a == "--pair") || !id.has_enrolled_clients();

    let listen: std::net::SocketAddr = std::env::var("HUBLOT_LISTEN")
        .unwrap_or_else(|_| DEFAULT_LISTEN.to_string())
        .parse()
        .context("HUBLOT_LISTEN")?;

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

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).context("quic tls")?,
    ));
    let endpoint = quinn::Endpoint::server(server_config, listen).context("binding endpoint")?;

    let (tx, _) = broadcast::channel(8);
    {
        let tx = tx.clone();
        std::thread::Builder::new().name("console".into()).spawn(move || {
            if let Err(e) = watcher(tx) {
                eprintln!("[hublot] console watcher stopped: {e:#}");
                std::process::exit(1);
            }
        })?;
    }

    eprintln!("[hublot] listening on {listen}");
    eprintln!("[hublot] fingerprint {}", protocol::pin::hex(&id.fingerprint));
    eprintln!(
        "[hublot] pairing {}",
        if pairing_open { "OPEN — a token holder may enrol" } else { "closed" }
    );

    while let Some(incoming) = endpoint.accept().await {
        let (id, tx) = (id.clone(), tx.clone());
        tokio::spawn(async move {
            if let Err(e) = serve_connection(incoming, id, pairing_open, tx).await {
                eprintln!("[hublot] connection ended: {e:#}");
            }
        });
    }
    Ok(())
}
