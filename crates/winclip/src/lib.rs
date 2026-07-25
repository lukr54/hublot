//! Reading and writing the Windows clipboard, text only.
//!
//! Both ends of the Windows link need this and neither should own it, for the same reason pinning
//! and agent identity live in their own crates.
//!
//! **Change detection is `GetClipboardSequenceNumber`, not polling the contents.** The counter is a
//! single cheap call that needs no window and no message loop, whereas reading the text every half
//! second would open the clipboard constantly and fight every other application for it.

#![cfg(windows)]

use windows::core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, HGLOBAL};
use windows::Win32::System::DataExchange::*;
use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};

const CF_UNICODETEXT: u32 = 13;

/// Bumped by the OS on every clipboard change. Cheap enough to call on a timer.
pub fn sequence() -> u32 {
    unsafe { GetClipboardSequenceNumber() }
}

/// The format password managers and similar tools add to say "do not capture this".
///
/// Honouring it costs one call and is the difference between a convenience feature and a tool that
/// quietly copies your credentials onto another machine. It is a courtesy marker, not a guarantee —
/// only well-behaved applications set it (THREAT-MODEL.md §6).
fn should_ignore() -> bool {
    unsafe {
        let name: Vec<u16> = "Clipboard Viewer Ignore\0".encode_utf16().collect();
        let fmt = RegisterClipboardFormatW(PCWSTR(name.as_ptr()));
        fmt != 0 && IsClipboardFormatAvailable(fmt).is_ok()
    }
}

/// Open the clipboard, retrying briefly: another application may hold it for a moment, and failing
/// on the first attempt would make sync unreliable for no good reason.
fn open() -> bool {
    for _ in 0..8 {
        if unsafe { OpenClipboard(None) }.is_ok() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(15));
    }
    false
}

pub fn get_text(max_len: usize) -> Option<String> {
    unsafe {
        if IsClipboardFormatAvailable(CF_UNICODETEXT).is_err() {
            return None;
        }
        if should_ignore() {
            return None;
        }
        if !open() {
            return None;
        }
        let result = (|| {
            let handle: HANDLE = GetClipboardData(CF_UNICODETEXT).ok()?;
            let hglobal = HGLOBAL(handle.0);
            let ptr = GlobalLock(hglobal) as *const u16;
            if ptr.is_null() {
                return None;
            }
            let mut len = 0usize;
            while *ptr.add(len) != 0 && len < max_len {
                len += 1;
            }
            let text = String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len));
            let _ = GlobalUnlock(hglobal);
            Some(text)
        })();
        let _ = CloseClipboard();
        result
    }
}

pub fn set_text(text: &str) -> bool {
    unsafe {
        if !open() {
            return false;
        }
        let ok = (|| {
            EmptyClipboard().ok()?;
            let utf16: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
            let bytes = utf16.len() * 2;
            let hglobal = GlobalAlloc(GMEM_MOVEABLE, bytes).ok()?;
            let ptr = GlobalLock(hglobal) as *mut u16;
            if ptr.is_null() {
                return None;
            }
            std::ptr::copy_nonoverlapping(utf16.as_ptr(), ptr, utf16.len());
            let _ = GlobalUnlock(hglobal);
            // Ownership passes to the clipboard on success; freeing it here would be a use-after-free.
            SetClipboardData(CF_UNICODETEXT, Some(HANDLE(hglobal.0))).ok()?;
            Some(())
        })()
        .is_some();
        let _ = CloseClipboard();
        ok
    }
}
