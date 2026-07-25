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
mod autostart;
#[cfg(windows)]
mod capture;
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
    let id = Arc::new(agent_core::Identity::load_or_create(&state_dir)?);
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--pairing") {
        println!("fingerprint: {}", protocol::pin::hex(&id.fingerprint));
        println!("token:       {}", id.token);
        return Ok(());
    }
    if args.iter().any(|a| a == "--install") {
        return autostart::install();
    }
    if args.iter().any(|a| a == "--uninstall") {
        return autostart::uninstall();
    }
    if args.iter().any(|a| a == "--status") {
        return autostart::status();
    }
    let pairing_open = args.iter().any(|a| a == "--pair") || !id.has_enrolled_clients();

    let listen: std::net::SocketAddr = std::env::var("HUBLOT_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:7843".to_string())
        .parse()
        .context("HUBLOT_LISTEN")?;

    // One capture thread owns the DXGI objects and broadcasts encoded tiles. Capture blocks, so it
    // gets an OS thread rather than starving a runtime worker — same shape as the console watcher.
    let (tx, _) = broadcast::channel::<Arc<capture::Update>>(64);
    let (info_tx, info_rx) = std::sync::mpsc::channel::<(u16, u16)>();
    {
        let tx = tx.clone();
        std::thread::Builder::new().name("capture".into()).spawn(move || {
            let mut cap = match capture::Capture::new(0) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[hublot] capture unavailable: {e:#}");
                    std::process::exit(1);
                }
            };
            let _ = info_tx.send((cap.width as u16, cap.height as u16));
            eprintln!("[hublot] capturing {}x{}", cap.width, cap.height);
            loop {
                match cap.next_change(500) {
                    Ok(updates) => {
                        for u in updates {
                            let _ = tx.send(Arc::new(u));
                        }
                    }
                    Err(e) => {
                        eprintln!("[hublot] capture stopped: {e:#}");
                        std::process::exit(1);
                    }
                }
            }
        })?;
    }
    let (screen_w, screen_h) = info_rx.recv().context("capture thread never reported geometry")?;

    let endpoint = quinn::Endpoint::server(agent_core::server_config(&id)?, listen)
        .context("binding endpoint")?;
    eprintln!("[hublot] listening on {listen}");
    eprintln!("[hublot] fingerprint {}", protocol::pin::hex(&id.fingerprint));
    eprintln!(
        "[hublot] pairing {}",
        if pairing_open { "OPEN — a token holder may enrol" } else { "closed" }
    );

    while let Some(incoming) = endpoint.accept().await {
        let (id, tx) = (id.clone(), tx.clone());
        tokio::spawn(async move {
            if let Err(e) = serve(incoming, id, pairing_open, tx, screen_w, screen_h).await {
                eprintln!("[hublot] connection ended: {e:#}");
            }
        });
    }
    Ok(())
}

#[cfg(windows)]
async fn serve(
    incoming: quinn::Incoming,
    id: std::sync::Arc<agent_core::Identity>,
    pairing_open: bool,
    tx: tokio::sync::broadcast::Sender<std::sync::Arc<capture::Update>>,
    screen_w: u16,
    screen_h: u16,
) -> anyhow::Result<()> {
    use anyhow::Context;
    use protocol::ServerMsg;

    let conn = incoming.await.context("handshake")?;
    let (mut send, mut recv) = conn.accept_bi().await.context("accepting stream")?;
    agent_core::authenticate(&conn, &mut send, &mut recv, &id, pairing_open).await?;

    protocol::write_msg(&mut send, &ServerMsg::ScreenInfo { w: screen_w, h: screen_h }).await?;
    protocol::write_msg(&mut send, &ServerMsg::Input { enabled: true, reason: String::new() })
        .await?;

    // The injector belongs to this connection. Dropping it releases everything held — which on
    // Windows we must do ourselves, since there is no kernel here to release a dying device's keys
    // the way there is for uinput.
    let input_task = tokio::spawn(input_loop(recv, inject::Injector::new(screen_w, screen_h)));

    let result = stream_tiles(&mut send, tx).await;
    input_task.abort();
    result
}

#[cfg(windows)]
async fn input_loop(mut recv: quinn::RecvStream, mut inj: inject::Injector) {
    use protocol::ClientMsg;
    eprintln!("[hublot] input loop ready");
    loop {
        match protocol::read_msg::<ClientMsg>(&mut recv).await {
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
) -> anyhow::Result<()> {
    use protocol::ServerMsg;
    use tokio::sync::broadcast::error::RecvError;

    let mut rx = tx.subscribe();
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
