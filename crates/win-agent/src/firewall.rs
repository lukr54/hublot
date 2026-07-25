//! Letting the panel in, and nothing else.
//!
//! The Linux agent restricts itself with `IPAddressDeny=any` in its unit file. Windows has no
//! equivalent the agent can set on itself, so the same job falls to a firewall rule — and without
//! one the agent listens perfectly well and no connection ever arrives, which looks exactly like a
//! broken agent.
//!
//! Two details that decide whether this works:
//!
//! * **QUIC is UDP.** A rule for TCP would be silently useless.
//! * **The rule is scoped to the panel's address, not to a network profile.** Windows decides on its
//!   own whether your LAN is "Private" or "Public" and changes its mind after a router reboot; a
//!   rule that depends on that classification stops working for reasons that have nothing to do
//!   with you. A remote-address restriction holds regardless, and is the tighter control anyway.

use anyhow::{bail, Result};
use std::process::Command;

pub const RULE: &str = "Hublot Agent";

fn netsh(args: &[&str]) -> Result<(bool, String)> {
    let out = Command::new("netsh").args(args).output()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok((out.status.success(), text))
}

/// The command a user would have to run themselves, printed when we cannot.
pub fn command_line(exe: &str, port: u16, allow: &str) -> String {
    format!(
        "netsh advfirewall firewall add rule name=\"{RULE}\" dir=in action=allow \
         protocol=UDP localport={port} program=\"{exe}\" remoteip={allow} profile=any enable=yes"
    )
}

/// Allow inbound QUIC from `allow` only. Needs an elevated shell; says so plainly if it does not
/// have one, rather than reporting success for something that did not happen.
pub fn allow(exe: &str, port: u16, allow_ip: &str) -> Result<()> {
    // Replace rather than accumulate: re-running --install should not leave a trail of rules, and
    // Windows will happily add a second one with the same name.
    let _ = netsh(&["advfirewall", "firewall", "delete", "rule", &format!("name={RULE}")]);

    let (ok, text) = netsh(&[
        "advfirewall",
        "firewall",
        "add",
        "rule",
        &format!("name={RULE}"),
        "dir=in",
        "action=allow",
        "protocol=UDP",
        &format!("localport={port}"),
        &format!("program={exe}"),
        &format!("remoteip={allow_ip}"),
        "profile=any",
        "enable=yes",
    ])?;
    if !ok {
        bail!("{text}");
    }
    println!("Firewall: inbound UDP {port} allowed from {allow_ip} only.");
    Ok(())
}

pub fn remove() -> Result<()> {
    let (ok, text) = netsh(&["advfirewall", "firewall", "delete", "rule", &format!("name={RULE}")])?;
    if ok {
        println!("Firewall: rule \"{RULE}\" removed.");
    } else {
        println!("Firewall: no rule \"{RULE}\" to remove ({})", text.lines().next().unwrap_or(""));
    }
    Ok(())
}

/// What the rule currently says, for `--status`.
pub fn show() -> String {
    match netsh(&["advfirewall", "firewall", "show", "rule", &format!("name={RULE}")]) {
        Ok((true, text)) => text,
        Ok((false, _)) => format!("No firewall rule \"{RULE}\" — the panel will not be able to connect."),
        Err(e) => format!("could not query the firewall: {e}"),
    }
}
