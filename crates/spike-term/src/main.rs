//! Phase 0a — the tier-2 spike.
//!
//! Proves, against the real host, that: ticket auth works, `termproxy` works, the websocket
//! handshake is what we think it is, and commands round-trip. Then it settles the one thing the
//! documentation is ambiguous about — whether `1:<a>:<b>:` is cols-then-rows or rows-then-cols —
//! by resizing to a deliberately lopsided geometry and asking the pty what it thinks it is.
//!
//! Reads the password from `HUBLOT_PASSWORD` or prompts. It is never written to disk or logged.
//!
//!   $env:HUBLOT_USER="root@pam"; cargo run -p spike-term

use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use pve::Message;

/// Geometry chosen so the two numbers can't be confused with each other, and so neither is a
/// plausible default the shell might substitute.
const PROBE_COLS: u16 = 203;
const PROBE_ROWS: u16 = 37;

#[tokio::main]
async fn main() -> Result<()> {
    let host = env_or("HUBLOT_HOST", "192.168.1.10");
    let port: u16 = env_or("HUBLOT_PORT", "8006").parse().context("HUBLOT_PORT")?;
    let node = env_or("HUBLOT_NODE", "pve");
    let user = env_or("HUBLOT_USER", "root@pam");
    let fp_str = env_or(
        "HUBLOT_FP",
        "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
    );

    let password = match std::env::var("HUBLOT_PASSWORD") {
        Ok(p) => p,
        Err(_) => rpassword::prompt_password(format!("password for {user}: "))?,
    };

    let fingerprint = pve::parse_fingerprint(&fp_str)?;
    println!("→ connecting to {host}:{port} (node `{node}`)");
    println!("  pinned to {}", pve::hex(&fingerprint));

    let client = pve::PveClient::new(&host, port, fingerprint)?;

    let ticket = client.login(&user, &password).await?;
    println!("✓ ticket acquired for {}", ticket.username);

    let tp = client.termproxy(&ticket, &node).await?;
    println!("✓ termproxy → port {} as {}", tp.port, tp.user);

    let mut ws = client.open_console(&ticket, &node, &tp).await?;
    println!("✓ websocket authenticated (server said OK)\n");

    // Resize first, so the shell's own idea of geometry is set before we ask about it.
    ws.send(Message::Binary(pve::frame::resize(PROBE_COLS, PROBE_ROWS).into()))
        .await?;
    tokio::time::sleep(Duration::from_millis(400)).await;

    for cmd in ["stty size\n", "uname -a\n"] {
        ws.send(Message::Binary(pve::frame::data(cmd.as_bytes()).into())).await?;
        tokio::time::sleep(Duration::from_millis(600)).await;
    }

    // Drain whatever the shell produced.
    let mut out = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, ws.next()).await {
            Ok(Some(Ok(msg))) => out.extend_from_slice(&msg.into_data()),
            Ok(Some(Err(e))) => return Err(anyhow::anyhow!("ws error: {e}")),
            Ok(None) => break,
            Err(_) => break,
        }
    }

    let text = String::from_utf8_lossy(&out);
    println!("──── console output ────");
    println!("{text}");
    println!("────────────────────────\n");

    report_resize_order(&text);
    Ok(())
}

/// Strip ANSI escape sequences (CSI and OSC). A terminal stream is not line-structured text, and
/// pretending otherwise is what broke the first version of this parser: bash emits
/// `\x1b[?2004l\r` (bracketed-paste-off) immediately before command output, so the "line" holding
/// `37 203` actually began with an escape sequence and a bare carriage return.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        match chars.next() {
            // CSI: parameters, then a final byte in @..~
            Some('[') => for c in chars.by_ref() {
                if ('@'..='~').contains(&c) {
                    break;
                }
            },
            // OSC: terminated by BEL or ST
            Some(']') => for c in chars.by_ref() {
                if c == '\x07' || c == '\x1b' {
                    break;
                }
            },
            _ => {}
        }
    }
    out
}

/// Find the pty's reported geometry. Scans adjacent numeric tokens rather than trusting line
/// structure, because carriage returns and escape codes make "lines" unreliable in a raw terminal
/// stream.
fn find_geometry(text: &str) -> Option<(u16, u16)> {
    let clean = strip_ansi(text);
    let nums: Vec<u16> = clean
        .split(|c: char| c.is_whitespace())
        .map(|t| t.parse::<u16>())
        .map(Result::ok)
        .collect::<Vec<_>>()
        .windows(2)
        .find_map(|w| match w {
            [Some(a), Some(b)] => Some(vec![*a, *b]),
            _ => None,
        })?;
    Some((nums[0], nums[1]))
}

/// `stty size` prints `rows cols`. We sent `resize(PROBE_COLS, PROBE_ROWS)`, so whichever of our
/// two numbers lands in the *second* position is the one termproxy understood as columns.
fn report_resize_order(text: &str) {
    match find_geometry(text) {
        Some((rows, cols)) if rows == PROBE_ROWS && cols == PROBE_COLS => {
            println!("VERDICT: `1:<a>:<b>:` is COLS then ROWS.");
            println!("  sent 1:{PROBE_COLS}:{PROBE_ROWS}: → pty reports {rows} rows x {cols} cols");
        }
        Some((rows, cols)) if rows == PROBE_COLS && cols == PROBE_ROWS => {
            println!("VERDICT: `1:<a>:<b>:` is ROWS then COLS.");
            println!("  sent 1:{PROBE_COLS}:{PROBE_ROWS}: → pty reports {rows} rows x {cols} cols");
        }
        Some((rows, cols)) => {
            println!("INCONCLUSIVE: pty reports {rows}x{cols}, neither matches what we sent.");
            println!("  the resize may have been ignored — check the frame format.");
        }
        None => println!("INCONCLUSIVE: no `stty size` output found. Is the shell interactive?"),
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shaped like what the host actually sent on 2026-07-24: a prompt, the echoed command, the
    /// bracketed-paste-off escape and a bare CR, then the answer. The first version of the parser
    /// returned None for exactly this input.
    const TRANSCRIPT: &str = "root@pve:~# stty size\r\n\x1b[?2004l\r37 203\r\n\x1b[?2004hroot@pve:~# ";

    #[test]
    fn geometry_survives_escapes_and_bare_carriage_returns() {
        assert_eq!(find_geometry(TRANSCRIPT), Some((37, 203)));
    }

    #[test]
    fn strip_ansi_removes_csi_and_osc() {
        assert_eq!(strip_ansi("\x1b[?2004l\r37 203"), "\r37 203");
        assert_eq!(strip_ansi("\x1b]0;title\x07ok"), "ok");
    }

    /// The measured result, frozen: we sent cols=203 rows=37, and `stty size` (rows first)
    /// answered `37 203`. If this ever flips, the resize helper's argument order is wrong.
    #[test]
    fn measured_order_is_cols_then_rows() {
        let (rows, cols) = find_geometry(TRANSCRIPT).unwrap();
        assert_eq!((rows, cols), (PROBE_ROWS, PROBE_COLS));
    }
}
