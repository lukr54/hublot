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

pub fn install() -> Result<()> {
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
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let out = Command::new("schtasks").args(["/Delete", "/TN", TASK, "/F"]).output()?;
    if !out.status.success() {
        bail!(
            "schtasks failed: {}{}",
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    println!("Removed logon task \"{TASK}\".");
    Ok(())
}

pub fn status() -> Result<()> {
    let out = Command::new("schtasks").args(["/Query", "/TN", TASK]).output()?;
    if out.status.success() {
        println!("{}", String::from_utf8_lossy(&out.stdout).trim());
    } else {
        println!("Logon task \"{TASK}\" is not installed.");
    }
    Ok(())
}
