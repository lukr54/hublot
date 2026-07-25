//! Phase 2 spike — the mirror, without a GUI in the way.
//!
//! Proves the agent link end to end (pinned QUIC, token auth, full frames, diff reassembly) and
//! prints what the remote console is showing. If this works and the panel doesn't, the bug is in
//! the panel.
//!
//!   $env:HUBLOT_AGENT="192.168.1.50:7842"
//!   $env:HUBLOT_FP="…"; $env:HUBLOT_TOKEN="…"; cargo run -p spike-mirror

use anyhow::{Context, Result};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<()> {
    let addr: std::net::SocketAddr = std::env::var("HUBLOT_AGENT")
        .context("set HUBLOT_AGENT=host:port")?
        .parse()
        .context("HUBLOT_AGENT")?;
    let fingerprint =
        protocol::pin::parse_fingerprint(&std::env::var("HUBLOT_FP").context("set HUBLOT_FP")?)?;
    // With a token we enrol; without one we rely on having been enrolled already.
    let auth = match std::env::var("HUBLOT_TOKEN") {
        Ok(token) => protocol::Auth::Enrol { token },
        Err(_) => protocol::Auth::Certificate,
    };
    let identity = mirror::ClientIdentity::load_or_create(std::path::Path::new(
        &std::env::var("HUBLOT_CLIENT_DIR").unwrap_or_else(|_| ".hublot-spike".into()),
    ))?;
    println!("→ our certificate {}", identity.fingerprint);

    let (tx, mut rx) = mpsc::channel(8);
    let (keys_tx, keys_rx) = mpsc::channel(64);

    // HUBLOT_TYPE="KeyQ,KeyW,KeyA,KeyZ,KeyM" taps those physical keys once input is live, then
    // backspaces them away again. Deliberately no Enter: submitting at a login prompt lands on a
    // non-echoing password prompt, which blinds every later observation.
    let to_type: Vec<String> = std::env::var("HUBLOT_TYPE")
        .map(|s| s.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect())
        .unwrap_or_default();
    tokio::spawn(async move {
        if let Err(e) = mirror::stream(addr, fingerprint, identity, auth, tx, keys_rx).await {
            eprintln!("stream error: {e:#}");
        }
    });

    println!("→ connecting to {addr}");
    let mut frames = 0u64;
    while let Some(ev) = rx.recv().await {
        match ev {
            mirror::Event::Connected => println!("✓ authenticated\n"),
            mirror::Event::Enrolled => println!("✓ enrolled — the token is now spent"),
            mirror::Event::Input { enabled, reason } => {
                println!("· input {}{}", if enabled { "enabled" } else { "DISABLED" }, if reason.is_empty() { String::new() } else { format!(" ({reason})") });
                // HUBLOT_MOUSE="800,400" — move the remote pointer there. Verifiable from outside
                // the panel by asking the OS where its cursor ended up.
                if let Ok(spec) = std::env::var("HUBLOT_MOUSE") {
                    if let Some((sx, sy)) = spec.split_once(',') {
                        if let (Ok(x), Ok(y)) = (sx.trim().parse::<u16>(), sy.trim().parse::<u16>()) {
                            let keys = keys_tx.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_millis(400)).await;
                                let _ = keys.send(protocol::ClientMsg::MouseMove { x, y }).await;
                                eprintln!("  moved pointer to {x},{y}");
                            });
                        }
                    }
                }
                // HUBLOT_SWITCH_VT=2 — switch console by ioctl. Works even when this badge says
                // input is off, which is the entire point (DECISIONS.md D13).
                if let Ok(vt) = std::env::var("HUBLOT_SWITCH_VT") {
                    if let Ok(vt) = vt.trim().parse::<u8>() {
                        let keys = keys_tx.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
                            let _ = keys.send(protocol::ClientMsg::SwitchVt { vt }).await;
                            eprintln!("  requested switch to tty{vt} by ioctl");
                        });
                    }
                }
                // HUBLOT_CHORD="ControlLeft,AltLeft,F3" — press all down in order, release in
                // reverse. Verifiable without any echo: the VT switch shows up in sysfs.
                if enabled {
                    if let Ok(chord) = std::env::var("HUBLOT_CHORD") {
                        let keys = keys_tx.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                            let codes: Vec<u16> = chord
                                .split(',')
                                .filter_map(|c| protocol::keymap::evdev_for_code(c.trim()))
                                .collect();
                            for &c in &codes {
                                let _ = keys.send(protocol::ClientMsg::Key { code: c, down: true }).await;
                                tokio::time::sleep(std::time::Duration::from_millis(40)).await;
                            }
                            for &c in codes.iter().rev() {
                                let _ = keys.send(protocol::ClientMsg::Key { code: c, down: false }).await;
                                tokio::time::sleep(std::time::Duration::from_millis(40)).await;
                            }
                            eprintln!("  chord sent: {codes:?}");
                        });
                    }
                }
                if enabled && !to_type.is_empty() {
                    let keys = keys_tx.clone();
                    let codes = to_type.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        for code in &codes {
                            let Some(c) = protocol::keymap::evdev_for_code(code) else {
                                eprintln!("unknown key code `{code}`");
                                continue;
                            };
                            for down in [true, false] {
                                match keys.send(protocol::ClientMsg::Key { code: c, down }).await {
                                    Ok(()) => eprintln!("  sent {code} (evdev {c}) down={down}"),
                                    Err(e) => eprintln!("  SEND FAILED for {code}: {e}"),
                                }
                                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                            }
                        }
                        // Put the console back the way we found it — unless we're deliberately
                        // leaving evidence for a later connection to read.
                        if std::env::var("HUBLOT_NO_UNDO").is_ok() {
                            return;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
                        let bs = protocol::keymap::evdev_for_code("Backspace").unwrap();
                        for _ in 0..codes.len() {
                            for down in [true, false] {
                                let _ = keys.send(protocol::ClientMsg::Key { code: bs, down }).await;
                                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                            }
                        }
                    });
                }
            }
            mirror::Event::ScreenInfo { w, h } => {
                println!("· graphical desktop {w}x{h} — this agent mirrors pixels, not characters");
            }
            mirror::Event::Raster { x, y, w, h, mime, data } => {
                // The CLI cannot show pixels; reporting size is what makes it useful here, since
                // bytes-per-update is the number that decides whether this leg is viable.
                println!("  tile {w}x{h} at {x},{y} — {} bytes {mime}", data.len());
            }
            mirror::Event::Pointer { x, y, visible } => {
                println!("  pointer {x},{y} visible={visible}");
            }
            mirror::Event::PointerShape { w, h, hot_x, hot_y, png } => {
                println!("  pointer shape {w}x{h} hotspot {hot_x},{hot_y} — {} bytes", png.len());
            }
            mirror::Event::Closed(why) => {
                println!("\n── closed: {why} ──");
                break;
            }
            mirror::Event::Screen(s) => {
                frames += 1;
                print!("\x1b[2J\x1b[H");
                println!(
                    "── tty{} · {}x{} · cursor {},{} · frame #{frames} ──",
                    s.vt, s.cols, s.rows, s.cursor.0, s.cursor.1
                );
                for row in s.cells.chunks(s.cols as usize) {
                    let line: String = row.iter().map(|c| c.ch).collect();
                    println!("{}", line.trim_end());
                }
            }
        }
    }
    Ok(())
}
