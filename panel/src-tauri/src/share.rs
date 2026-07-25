//! Making *this* PC one of the machines the panel can drive.
//!
//! The agent has always been a command-line thing: find the exe, run `--pairing`, open an
//! administrator terminal, run `--install --allow`, copy two hex strings to the other machine. Each
//! step is small and the whole is genuinely unpleasant, which is the point of this file — the same
//! operations, driven from the panel that is already installed here.
//!
//! Nothing here is new capability. It starts the bundled agent, asks Windows for the one privilege
//! that genuinely needs asking, and reports what is true.

use std::path::PathBuf;

use serde::Serialize;
use tauri::{AppHandle, Manager};

/// Where the installer put the agent, or where a `cargo build` left it.
///
/// Tauri's resource directory is the install folder for a bundled app and `target/release` when run
/// from a build, so this covers both without knowing which it is.
pub fn agent_path(app: &AppHandle) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(dir) = app.path().resource_dir() {
        candidates.push(dir.join("win-agent.exe"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("win-agent.exe"));
        }
    }
    candidates.into_iter().find(|p| p.exists())
}

#[derive(Serialize, Clone, Default)]
pub struct ShareStatus {
    /// Whether we could find the agent at all — everything else is meaningless without it.
    pub agent: Option<String>,
    /// Whether something is already listening on the agent's port.
    pub running: bool,
    /// This machine's LAN addresses, so the other end knows what to dial.
    pub addresses: Vec<String>,
    pub port: u16,
    /// Whether the logon task and firewall rule exist, as the agent itself reports them.
    pub installed: bool,
    pub firewall: bool,
}

/// Is the agent up? Answered by trying to take its port rather than by hunting for a process:
/// "something already owns 7843" is the condition that actually matters, and it stays true whether
/// the agent was started by us, by the logon task, or by hand.
fn port_taken(port: u16) -> bool {
    std::net::UdpSocket::bind(("0.0.0.0", port)).is_err()
}

/// The addresses another machine could reach this one on, private ranges first.
///
/// A UDP connect to a routable address makes the OS pick the interface it would really use, which
/// beats enumerating adapters and guessing which of them is the LAN.
fn local_addresses() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        // No packet is sent; this only resolves the routing decision.
        if sock.connect("192.168.1.1:9").is_ok() || sock.connect("1.1.1.1:9").is_ok() {
            if let Ok(addr) = sock.local_addr() {
                out.push(addr.ip().to_string());
            }
        }
    }
    out
}

pub fn status(app: &AppHandle, port: u16) -> ShareStatus {
    let agent = agent_path(app);
    let mut st = ShareStatus {
        running: port_taken(port),
        addresses: local_addresses(),
        port,
        agent: agent.as_ref().map(|p| p.to_string_lossy().into_owned()),
        ..Default::default()
    };
    if let Some(path) = &agent {
        // Ask the agent rather than re-implementing its checks here; it already knows how to look
        // at its own logon task and firewall rule, and two implementations would drift.
        if let Ok(out) = std::process::Command::new(path).arg("--status").output() {
            let text = String::from_utf8_lossy(&out.stdout);
            st.installed = !text.contains("is not installed");
            st.firewall = !text.contains("No firewall rule");
        }
    }
    st
}

/// Start the agent now, without waiting for a logon.
pub fn start(app: &AppHandle, port: u16) -> Result<(), String> {
    if port_taken(port) {
        return Ok(()); // already serving; starting a second one would just fail to bind
    }
    let path = agent_path(app).ok_or("win-agent.exe is not next to the panel")?;
    std::process::Command::new(&path)
        .spawn()
        .map_err(|e| format!("could not start {}: {e}", path.display()))?;
    Ok(())
}

/// Register the logon task and the firewall rule, via a UAC prompt.
///
/// The firewall rule is the one part of this that genuinely needs administrator rights, and it is
/// also the part without which nothing works at all — so it gets a button and a consent dialog
/// rather than instructions to open an elevated terminal.
#[cfg(windows)]
pub fn install_elevated(app: &AppHandle, allow: &str) -> Result<(), String> {
    use windows::core::HSTRING;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let path = agent_path(app).ok_or("win-agent.exe is not next to the panel")?;
    let params = format!("--install --allow {allow}");
    // "runas" is what raises the UAC prompt. The window is hidden because the agent is a GUI binary
    // with nothing to show; its output goes to its log either way.
    let result = unsafe {
        ShellExecuteW(
            None,
            &HSTRING::from("runas"),
            &HSTRING::from(path.as_os_str()),
            &HSTRING::from(params),
            None,
            SW_HIDE,
        )
    };
    // ShellExecuteW returns a fake HINSTANCE; anything <= 32 is an error, and 1223 means the user
    // clicked No on the consent dialog — worth saying plainly rather than as a number.
    let code = result.0 as usize;
    if code > 32 {
        Ok(())
    } else if code == 1223 {
        Err("the administrator prompt was dismissed".into())
    } else {
        Err(format!("could not elevate (code {code})"))
    }
}
