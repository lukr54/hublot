//! Giving a windowless binary somewhere to talk.
//!
//! The agent is built for the GUI subsystem so that starting at logon does not flash up a console
//! nobody asked for. That costs two things, and this file buys both back:
//!
//! * **Run from a terminal, print to that terminal.** `--pairing` prints a fingerprint and a token
//!   you are meant to copy; a GUI binary starts with no console attached, so without
//!   `AttachConsole` those two lines would go nowhere and the command would look broken.
//! * **Run by the scheduler, print to a file.** Otherwise the trade is "no console window" for "no
//!   diagnostics at all", and an agent that fails to start at logon would fail in complete silence.
//!   Redirecting the standard error *handle* means every existing `eprintln!` follows automatically,
//!   with no logging framework and no call sites to change.

use std::os::windows::ffi::OsStrExt;

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::GENERIC_WRITE;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_ALWAYS, OPEN_EXISTING,
};
use windows::Win32::System::Console::{
    AttachConsole, GetStdHandle, SetStdHandle, ATTACH_PARENT_PROCESS, STD_ERROR_HANDLE,
    STD_HANDLE, STD_OUTPUT_HANDLE,
};

/// Past this the log is rotated once — two files, a couple of megabytes, forever. An agent that
/// restarts in a loop must not be able to fill the disk it is running on.
const MAX_LOG: u64 = 1 << 20;

/// Does this stream still need somewhere to go?
///
/// **The check exists so that `win-agent --pairing > token.txt` still writes to the file.** When the
/// caller redirects, the shell hands us a perfectly good handle, and overwriting it with the console
/// or a log file would silently discard exactly what the user asked to capture. A GUI process with
/// no console and no redirection gets a null handle here, which is the case worth fixing.
unsafe fn unattached(which: STD_HANDLE) -> bool {
    match GetStdHandle(which) {
        Ok(h) => h.is_invalid() || h.0.is_null(),
        Err(_) => true,
    }
}

unsafe fn point_at(h: windows::Win32::Foundation::HANDLE) {
    if unattached(STD_OUTPUT_HANDLE) {
        let _ = SetStdHandle(STD_OUTPUT_HANDLE, h);
    }
    if unattached(STD_ERROR_HANDLE) {
        let _ = SetStdHandle(STD_ERROR_HANDLE, h);
    }
}

/// Point stdout and stderr somewhere useful. Call before printing anything.
pub fn attach_output(state_dir: &str) {
    unsafe {
        if AttachConsole(ATTACH_PARENT_PROCESS).is_ok() {
            // Joined the terminal that launched us. The handles a GUI process inherits are not
            // reliably the console's, so ask for the console by name and install those.
            if let Ok(h) = CreateFileW(
                w!("CONOUT$"),
                GENERIC_WRITE.0,
                FILE_SHARE_WRITE | FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            ) {
                point_at(h);
            }
            return;
        }

        // No terminal: started by the logon task, or from Explorer. Everything the agent says goes
        // to a file rather than being thrown away.
        let _ = std::fs::create_dir_all(state_dir);
        let path = std::path::Path::new(state_dir).join("agent.log");
        if std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) >= MAX_LOG {
            let _ = std::fs::rename(&path, std::path::Path::new(state_dir).join("agent.log.1"));
        }
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        // FILE_APPEND_DATA on its own is what makes each write land at the end of the file, which
        // matters because two runs of the agent can overlap during a restart.
        if let Ok(h) = CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_APPEND_DATA.0,
            FILE_SHARE_READ,
            None,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        ) {
            point_at(h);
        }
    }
}
