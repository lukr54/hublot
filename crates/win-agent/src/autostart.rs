//! Starting the agent automatically.
//!
//! **Not a Windows service, and that is not a shortcut.** Services run in session 0, which has no
//! desktop — `DuplicateOutput` there fails, because there is literally nothing on screen to
//! duplicate. Capture tools that appear to run as services (Sunshine, Parsec) actually run a
//! session-0 service whose only job is to launch a *helper into the logged-in session*, which is a
//! substantial amount of machinery for the same end result.
//!
//! A logon task achieves it directly: the agent runs in the user's own session, where the desktop
//! exists, and starts without anyone logging in twice.

use anyhow::{bail, Result};
use std::process::Command;

const TASK: &str = "Hublot Agent";

fn exe() -> Result<String> {
    Ok(std::env::current_exe()?.to_string_lossy().into_owned())
}

/// `--install [--allow <address>] [--port <n>]`
///
/// Two separate things, with two different privilege requirements, which is why the failure of the
/// second does not undo the first: the logon task is per-user and needs nothing special, the
/// firewall rule needs an elevated shell.
pub fn install(allow: Option<&str>, port: u16) -> Result<()> {
    let path = exe()?;
    let out = Command::new("schtasks")
        .args([
            "/Create",
            "/TN",
            TASK,
            "/TR",
            &format!("\"{path}\""),
            "/SC",
            "ONLOGON",
            "/F",
        ])
        .output()?;
    if !out.status.success() {
        bail!(
            "schtasks failed: {}{}",
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    println!("Installed logon task \"{TASK}\" → {path}");
    println!("It will start at your next sign-in. Remove it with --uninstall.");

    // Without this the agent listens and nothing ever reaches it, which is indistinguishable from a
    // broken agent — so it is worth being loud about, in both directions.
    match allow {
        Some(ip) => match crate::firewall::allow(&path, port, ip) {
            Ok(()) => {}
            Err(e) => {
                println!();
                println!("!! The firewall rule was NOT created: {e}");
                println!("   Without it the panel cannot reach this agent.");
                println!("   Run this from an *administrator* terminal:");
                println!();
                println!("   {}", crate::firewall::command_line(&path, port, ip));
            }
        },
        None => {
            println!();
            println!(
                "No --allow address given, so no firewall rule was created. Unless one already"
            );
            println!(
                "exists, the panel will not be able to connect. Re-run as administrator with:"
            );
            println!();
            println!("   \"{path}\" --install --allow <the panel PC's address>");
        }
    }
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let out = Command::new("schtasks")
        .args(["/Delete", "/TN", TASK, "/F"])
        .output()?;
    if !out.status.success() {
        bail!(
            "schtasks failed: {}{}",
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    println!("Removed logon task \"{TASK}\".");
    // Best effort: leaving a stale allow rule behind for a binary that no longer starts would be a
    // small hole nobody would think to look for.
    let _ = crate::firewall::remove();
    Ok(())
}

pub fn status() -> Result<()> {
    let out = Command::new("schtasks")
        .args(["/Query", "/TN", TASK])
        .output()?;
    if out.status.success() {
        println!("{}", String::from_utf8_lossy(&out.stdout).trim());
    } else {
        println!("Logon task \"{TASK}\" is not installed.");
    }
    println!();
    println!("{}", crate::firewall::show());
    Ok(())
}
