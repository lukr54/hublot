//! Key injection via `/dev/uinput`.
//!
//! Events land in whatever VT is currently active, below any display server — which is why this
//! works on a bare text console where XTEST/Wayland injection has nothing to talk to.
//!
//! **The device is owned by a connection, not by the process.** When a session ends — cleanly, by
//! crash, or by the network vanishing — the device is dropped, and the kernel releases every key
//! still held. That was measured in spike 0b: hold Shift, kill the owner, and the next keystroke
//! comes back lowercase. It means a stuck modifier on a root console cannot outlive the session
//! that caused it, without us having to be clever.

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

const EV_SYN: u16 = 0x00;
const EV_KEY: u16 = 0x01;
const SYN_REPORT: u16 = 0x00;

const UINPUT_IOCTL_BASE: u64 = b'U' as u64;
const fn iow(nr: u64, size: u64) -> u64 {
    (1 << 30) | (size << 16) | (UINPUT_IOCTL_BASE << 8) | nr
}
const fn io_(nr: u64) -> u64 {
    (UINPUT_IOCTL_BASE << 8) | nr
}
const UI_DEV_CREATE: u64 = io_(1);
const UI_DEV_DESTROY: u64 = io_(2);
const UI_SET_EVBIT: u64 = iow(100, 4);
const UI_SET_KEYBIT: u64 = iow(101, 4);

#[repr(C)]
#[derive(Clone, Copy)]
struct InputId {
    bustype: u16,
    vendor: u16,
    product: u16,
    version: u16,
}

#[repr(C)]
struct UinputSetup {
    id: InputId,
    name: [libc::c_char; 80],
    ff_effects_max: u32,
}

#[repr(C)]
struct InputEvent {
    time: libc::timeval,
    kind: u16,
    code: u16,
    value: i32,
}

pub struct VirtualKeyboard {
    fd: std::fs::File,
    /// What we currently hold down, so we can let go deliberately as well as implicitly.
    held: std::collections::HashSet<u16>,
}

impl VirtualKeyboard {
    pub fn create() -> io::Result<Self> {
        let fd = std::fs::OpenOptions::new().write(true).open("/dev/uinput")?;
        let raw = fd.as_raw_fd();

        ioctl_int(raw, UI_SET_EVBIT, EV_KEY as i32)?;
        for key in 1..=protocol::keymap::MAX_KEYCODE as i32 {
            ioctl_int(raw, UI_SET_KEYBIT, key)?;
        }

        let mut name = [0 as libc::c_char; 80];
        for (dst, src) in name.iter_mut().zip(b"hublot".iter()) {
            *dst = *src as libc::c_char;
        }
        let setup = UinputSetup {
            id: InputId { bustype: 0x06, vendor: 0x1209, product: 0x4842, version: 1 },
            name,
            ff_effects_max: 0,
        };
        let rc = unsafe {
            libc::ioctl(raw, iow(3, std::mem::size_of::<UinputSetup>() as u64), &setup as *const _)
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::ioctl(raw, UI_DEV_CREATE) } < 0 {
            return Err(io::Error::last_os_error());
        }

        // udev needs a moment; events written before it settles are dropped on the floor.
        std::thread::sleep(std::time::Duration::from_millis(300));
        Ok(Self { fd, held: Default::default() })
    }

    fn emit(&mut self, kind: u16, code: u16, value: i32) -> io::Result<()> {
        let ev = InputEvent {
            time: libc::timeval { tv_sec: 0, tv_usec: 0 },
            kind,
            code,
            value,
        };
        let n = unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                &ev as *const _ as *const libc::c_void,
                std::mem::size_of::<InputEvent>(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Returns whether an event was actually emitted, so callers can tell "injected" apart from
    /// "deliberately dropped" without inspecting key identities.
    pub fn key(&mut self, code: u16, down: bool) -> io::Result<bool> {
        if code == 0 || code > protocol::keymap::MAX_KEYCODE {
            return Ok(false); // never emit a code we didn't register
        }
        // Suppress the source's synthetic autorepeat: a key already down staying down is not news,
        // and the kernel does its own repeat for held keys.
        if down && !self.held.insert(code) {
            return Ok(false);
        }
        if !down && !self.held.remove(&code) {
            return Ok(false);
        }
        self.emit(EV_KEY, code, i32::from(down))?;
        self.emit(EV_SYN, SYN_REPORT, 0)?;
        Ok(true)
    }

    pub fn release_all(&mut self) -> io::Result<()> {
        for code in std::mem::take(&mut self.held) {
            self.emit(EV_KEY, code, 0)?;
        }
        self.emit(EV_SYN, SYN_REPORT, 0)
    }
}

impl Drop for VirtualKeyboard {
    fn drop(&mut self) {
        // Belt and braces. The kernel would release these anyway when the device goes, but saying
        // so explicitly costs two syscalls and removes any doubt about ordering.
        let _ = self.release_all();
        unsafe { libc::ioctl(self.fd.as_raw_fd(), UI_DEV_DESTROY) };
    }
}

fn ioctl_int(fd: RawFd, req: u64, arg: i32) -> io::Result<()> {
    if unsafe { libc::ioctl(fd, req, arg) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
