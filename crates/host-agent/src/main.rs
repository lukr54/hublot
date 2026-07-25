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

use std::sync::Arc;

use agent_core::Identity;
use anyhow::{Context, Result};
use protocol::{ClientMsg, ServerMsg};
use tokio::sync::broadcast;

const DEFAULT_LISTEN: &str = "0.0.0.0:7842";

fn state_dir() -> std::path::PathBuf {
    std::env::var("HUBLOT_STATE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/var/lib/hublot"))
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
                if received.is_multiple_of(8) {
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
            // The panel speaks one protocol to both kinds of agent, so it sends these without
            // asking what is on the other end. A text console has neither a pointer nor a
            // clipboard, so they are dropped here rather than made conditional over there.
            Ok(ClientMsg::MouseMove { .. })
            | Ok(ClientMsg::MouseButton { .. })
            | Ok(ClientMsg::MouseScroll { .. })
            | Ok(ClientMsg::Clipboard { .. }) => {}
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
    let (mut send, mut recv) = conn.accept_bi().await.context("accepting stream")?;
    // Who is allowed in is `agent-core`'s decision, identically for both agents. This file used to
    // carry its own copy of it, which is exactly how two copies of a security rule drift apart —
    // and they had: the audit log and the pre-authentication size cap only ever existed over there.
    // A text console has no desktop and nobody sitting at it, so the approve-on-the-machine flow
    // cannot work here and says so instead of failing vaguely. This leg pairs with its token.
    agent_core::authenticate(
        &conn,
        &mut send,
        &mut recv,
        &id,
        pairing_open,
        &agent_core::CannotAsk(
            "this agent has no screen to ask on — pair it with the token it printed",
        ),
    )
    .await?;

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

    let id = Arc::new(Identity::load_or_create(state_dir())?);
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

    let endpoint = quinn::Endpoint::server(agent_core::server_config(&id)?, listen)
        .context("binding endpoint")?;

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
