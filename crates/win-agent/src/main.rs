// A console subsystem binary opens a black window whenever Windows starts it, which for something
// launched at every logon is a window you never asked for and cannot close without stopping the
// agent. Built as a GUI binary it starts silently — and `attach_output` below gives it back a
// console when a human ran it from one, so `--pairing` still prints where you can read it.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Hublot agent for Windows — Phase 6a, screen out.
//!
//! Same identity, pairing and transport as the Linux console agent (`agent-core`); the only thing
//! that differs is what gets mirrored. **Read-only for now**: there is no `SendInput` in this
//! binary at all, exactly as the console agent shipped read-only first. Input is 6b.
//!
//!   win-agent --pairing     print the fingerprint and token
//!   win-agent --pair        allow one client to enrol
//!   win-agent               serve

#[cfg(windows)]
mod approve;
#[cfg(windows)]
mod autostart;
#[cfg(windows)]
mod capture;
#[cfg(windows)]
mod console;
#[cfg(windows)]
mod firewall;
#[cfg(windows)]
mod inject;
#[cfg(windows)]
mod pointer;

#[cfg(not(windows))]
fn main() {
    eprintln!("win-agent is Windows-only");
}

#[cfg(windows)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use anyhow::Context;
    use std::sync::Arc;
    use tokio::sync::broadcast;

    let _ = rustls::crypto::ring::default_provider().install_default();

    let state_dir = std::env::var("HUBLOT_STATE").unwrap_or_else(|_| {
        let base = std::env::var("APPDATA").unwrap_or_else(|_| ".".into());
        format!("{base}\\hublot-agent")
    });
    // Before anything is printed: a terminal if a human started us, a log file if the scheduler did.
    console::attach_output(&state_dir);
    let id = Arc::new(agent_core::Identity::load_or_create(&state_dir)?);
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--pairing") {
        println!("fingerprint: {}", protocol::pin::hex(&id.fingerprint));
        println!("token:       {}", id.token);
        return Ok(());
    }
    let listen: std::net::SocketAddr = std::env::var("HUBLOT_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:7843".to_string())
        .parse()
        .context("HUBLOT_LISTEN")?;

    /// `--allow 192.168.1.20` — the flag's value is the next argument along.
    fn value_of<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
        let i = args.iter().position(|a| a == flag)?;
        args.get(i + 1).map(|s| s.as_str()).filter(|s| !s.starts_with("--"))
    }

    if args.iter().any(|a| a == "--install") {
        return autostart::install(value_of(&args, "--allow"), listen.port());
    }
    if args.iter().any(|a| a == "--uninstall") {
        return autostart::uninstall();
    }
    if args.iter().any(|a| a == "--status") {
        return autostart::status();
    }
    let pairing_open = args.iter().any(|a| a == "--pair") || !id.has_enrolled_clients();

    // One capture thread owns the DXGI objects and broadcasts encoded tiles. Capture blocks, so it
    // gets an OS thread rather than starving a runtime worker — same shape as the console watcher.
    let (tx, _) = broadcast::channel::<Arc<capture::Update>>(64);
    // The last value we applied *from* the panel, so the watcher can tell it apart from something
    // the user actually copied here.
    let echo_guard: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let (info_tx, info_rx) = std::sync::mpsc::channel::<(u16, u16)>();
    // A newly attached viewer has nothing on its canvas and the wire only ever carries *changes*,
    // so on an idle desktop it would stay blank until something happened to move. This asks the
    // capture thread for one whole frame; it is the only thing that ever grabs the full screen.
    let (refresh_tx, refresh_rx) = std::sync::mpsc::channel::<()>();
    {
        let tx = tx.clone();
        std::thread::Builder::new().name("capture".into()).spawn(move || {
            let mut cap = acquire(0);
            let _ = info_tx.send((cap.width as u16, cap.height as u16));
            eprintln!("[hublot] capturing {}x{}", cap.width, cap.height);
            loop {
                // Coalesced deliberately: three viewers attaching at once want the same frame, and
                // it reaches all of them because the broadcast has no idea who asked.
                if refresh_rx.try_recv().is_ok() {
                    while refresh_rx.try_recv().is_ok() {}
                    match cap.full() {
                        Ok(t) => {
                            let _ = tx.send(std::sync::Arc::new(capture::Update::Tile(t)));
                        }
                        Err(e) => eprintln!("[hublot] full frame failed: {e:#}"),
                    }
                }
                match cap.next_change(500) {
                    Ok(updates) => {
                        for u in updates {
                            let _ = tx.send(Arc::new(u));
                        }
                    }
                    // **Losing the desktop is normal, not fatal.** Desktop Duplication hands back
                    // ACCESS_LOST whenever Windows switches desktops — a UAC prompt, the lock
                    // screen, Ctrl+Alt+Del, a resolution change, a driver reset — and this used to
                    // exit the process, taking the agent down with it. From the panel that looked
                    // like a link that connected and then died for no reason, which is exactly
                    // what it was.
                    Err(e) => {
                        eprintln!("[hublot] lost the desktop ({e:#}) — reacquiring");
                        let (was_w, was_h) = (cap.width, cap.height);
                        cap = acquire(cap.output);
                        if (cap.width, cap.height) != (was_w, was_h) {
                            eprintln!("[hublot] desktop is now {}x{}", cap.width, cap.height);
                            let _ = tx.send(Arc::new(capture::Update::Geometry {
                                w: cap.width as u16,
                                h: cap.height as u16,
                            }));
                        }
                        // Whatever viewers are attached are holding a stale picture of a desktop
                        // that has since changed; give them a whole frame rather than patches of
                        // one they no longer have.
                        match cap.full() {
                            Ok(t) => {
                                let _ = tx.send(Arc::new(capture::Update::Tile(t)));
                            }
                            Err(e) => eprintln!("[hublot] first frame after reacquire failed: {e:#}"),
                        }
                    }
                }
            }
        })?;
    }
    let (screen_w, screen_h) = info_rx.recv().context("capture thread never reported geometry")?;

    // Clipboard watcher. Its own thread because the sequence-number check is a blocking syscall on
    // a timer, and it must not compete with capture for the same wake-ups.
    {
        let tx = tx.clone();
        let echo = echo_guard.clone();
        std::thread::Builder::new().name("clipboard".into()).spawn(move || {
            let mut seen = winclip::sequence();
            loop {
                std::thread::sleep(std::time::Duration::from_millis(400));
                let now = winclip::sequence();
                if now == seen {
                    continue;
                }
                seen = now;
                let Some(text) = winclip::get_text(protocol::MAX_CLIPBOARD) else { continue };
                // Do not send back what we were just given: without this the two clipboards
                // bounce a value between them forever.
                if echo.lock().unwrap().as_deref() == Some(text.as_str()) {
                    continue;
                }
                let _ = tx.send(Arc::new(capture::Update::Clipboard(text)));
            }
        })?;
    }

    let endpoint = quinn::Endpoint::server(agent_core::server_config(&id)?, listen)
        .context("binding endpoint")?;
    eprintln!("[hublot] listening on {listen}");
    eprintln!("[hublot] fingerprint {}", protocol::pin::hex(&id.fingerprint));
    eprintln!(
        "[hublot] pairing {}",
        if pairing_open { "OPEN — a token holder may enrol" } else { "closed" }
    );

    while let Some(incoming) = endpoint.accept().await {
        let (id, tx, echo) = (id.clone(), tx.clone(), echo_guard.clone());
        let refresh = refresh_tx.clone();
        tokio::spawn(async move {
            if let Err(e) =
                serve(incoming, id, pairing_open, tx, refresh, echo, screen_w, screen_h).await
            {
                eprintln!("[hublot] connection ended: {e:#}");
            }
        });
    }
    Ok(())
}

/// Get hold of the desktop, waiting as long as it takes.
///
/// There is no point failing here. The two reasons duplication is unavailable are both temporary:
/// the machine is sitting at the lock screen, or Windows has just taken the desktop away and has
/// not given it back yet. An agent that exits on either is an agent that stops working the first
/// time you lock your PC and never comes back until you notice — the failure this whole function
/// exists to avoid.
///
/// The wait backs off to a few seconds so a locked machine costs nothing to keep trying on, and
/// says so once rather than filling the log.
#[cfg(windows)]
fn acquire(output: u32) -> capture::Capture {
    let mut wait = std::time::Duration::from_millis(200);
    let mut complained = false;
    loop {
        match capture::Capture::new(output) {
            Ok(c) => {
                if complained {
                    eprintln!("[hublot] desktop is back — {}x{}", c.width, c.height);
                }
                return c;
            }
            Err(e) => {
                if !complained {
                    eprintln!("[hublot] no desktop to capture ({e:#}); waiting for one");
                    complained = true;
                }
                std::thread::sleep(wait);
                wait = (wait * 2).min(std::time::Duration::from_secs(5));
            }
        }
    }
}

// Everything here is per-connection state that has to come from somewhere; bundling it into a
// struct to satisfy an argument count would add a type whose only purpose is the count.
#[allow(clippy::too_many_arguments)]
#[cfg(windows)]
async fn serve(
    incoming: quinn::Incoming,
    id: std::sync::Arc<agent_core::Identity>,
    pairing_open: bool,
    tx: tokio::sync::broadcast::Sender<std::sync::Arc<capture::Update>>,
    refresh: std::sync::mpsc::Sender<()>,
    echo: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    screen_w: u16,
    screen_h: u16,
) -> anyhow::Result<()> {
    use anyhow::Context;
    use protocol::ServerMsg;

    let conn = incoming.await.context("handshake")?;
    let (mut send, mut recv) = conn.accept_bi().await.context("accepting stream")?;
    agent_core::authenticate(&conn, &mut send, &mut recv, &id, pairing_open, &approve::Desktop).await?;

    protocol::write_msg(&mut send, &ServerMsg::ScreenInfo { w: screen_w, h: screen_h }).await?;
    protocol::write_msg(&mut send, &ServerMsg::Input { enabled: true, reason: String::new() })
        .await?;

    // The injector belongs to this connection. Dropping it releases everything held — which on
    // Windows we must do ourselves, since there is no kernel here to release a dying device's keys
    // the way there is for uinput.
    let input_task =
        tokio::spawn(input_loop(recv, inject::Injector::new(screen_w, screen_h), echo));

    let result = stream_tiles(&mut send, tx, refresh).await;
    input_task.abort();
    result
}

#[cfg(windows)]
async fn input_loop(
    mut recv: quinn::RecvStream,
    mut inj: inject::Injector,
    echo: std::sync::Arc<std::sync::Mutex<Option<String>>>,
) {
    use protocol::ClientMsg;
    eprintln!("[hublot] input loop ready");
    loop {
        match protocol::read_msg::<ClientMsg>(&mut recv).await {
            Ok(ClientMsg::Clipboard { text }) => {
                if text.len() <= protocol::MAX_CLIPBOARD {
                    // Record before setting: the watcher may wake the instant we do.
                    *echo.lock().unwrap() = Some(text.clone());
                    winclip::set_text(&text);
                }
            }
            Ok(ClientMsg::Key { code, down }) => inj.key(code, down),
            Ok(ClientMsg::MouseMove { x, y }) => inj.move_to(x, y),
            Ok(ClientMsg::MouseButton { button, down }) => inj.button(button, down),
            Ok(ClientMsg::MouseScroll { dx, dy }) => inj.scroll(dx, dy),
            Ok(ClientMsg::ReleaseAll) => inj.release_all(),
            // Only a console has VTs to switch between.
            Ok(ClientMsg::SwitchVt { .. }) => {}
            Ok(ClientMsg::Hello { .. }) => {
                eprintln!("[hublot] input loop stopping: unexpected second Hello");
                return;
            }
            Err(e) => {
                eprintln!("[hublot] input loop stopping: {e:#}");
                return;
            }
        }
    }
}

#[cfg(windows)]
async fn stream_tiles(
    send: &mut quinn::SendStream,
    tx: tokio::sync::broadcast::Sender<std::sync::Arc<capture::Update>>,
    refresh: std::sync::mpsc::Sender<()>,
) -> anyhow::Result<()> {
    use protocol::ServerMsg;
    use tokio::sync::broadcast::error::RecvError;

    // Subscribe *before* asking, or the frame we asked for can be broadcast into the gap between
    // the two and we wait for the desktop to change after all.
    let mut rx = tx.subscribe();
    let _ = refresh.send(());
    loop {
        let update = match rx.recv().await {
            Ok(u) => u,
            // Falling behind means the desktop is changing faster than this link can carry it.
            // Skipping is correct: the next update supersedes what we missed anyway.
            Err(RecvError::Lagged(n)) => {
                eprintln!("[hublot] viewer fell behind, dropped {n} updates");
                continue;
            }
            Err(RecvError::Closed) => return Ok(()),
        };
        let msg = match &*update {
            capture::Update::Tile(t) => ServerMsg::Raster {
                x: t.x,
                y: t.y,
                w: t.w,
                h: t.h,
                format: t.format,
                data: t.data.clone(),
            },
            capture::Update::Geometry { w, h } => ServerMsg::ScreenInfo { w: *w, h: *h },
            capture::Update::Clipboard(text) => ServerMsg::Clipboard { text: text.clone() },
            capture::Update::Pointer { x, y, visible } => {
                ServerMsg::Pointer { x: *x, y: *y, visible: *visible }
            }
            capture::Update::Shape { w, h, hot_x, hot_y, png } => ServerMsg::PointerShape {
                w: *w,
                h: *h,
                hot_x: *hot_x,
                hot_y: *hot_y,
                png: png.clone(),
            },
        };
        protocol::write_msg(send, &msg).await?;
    }
}
