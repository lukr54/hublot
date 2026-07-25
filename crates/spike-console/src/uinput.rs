//! Key injection via `/dev/uinput`.
//!
//! Events land in whatever VT is currently active, *below* any display server — which is exactly
//! why this works on a bare text console where XTEST/Wayland injection has nothing to talk to.
//!
//! Note what this does and does not control: we send **physical key identities** (evdev keycodes).
//! The character that appears is decided by the *remote* console's keymap. That is the whole of
//! DECISIONS.md D2, and `demo` below makes it visible.

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const SYN_REPORT: u16 = 0x00;

pub const KEY_Q: u16 = 16;
pub const KEY_W: u16 = 17;
pub const KEY_A: u16 = 30;
pub const KEY_Z: u16 = 44;
pub const KEY_M: u16 = 50;
#[allow(dead_code)] // wanted by the real agent, not by any spike
pub const KEY_ENTER: u16 = 28;
pub const KEY_BACKSPACE: u16 = 14;
pub const KEY_LEFTSHIFT: u16 = 42;

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
}

impl VirtualKeyboard {
    pub fn create(name: &str) -> io::Result<Self> {
        let fd = std::fs::OpenOptions::new().write(true).open("/dev/uinput")?;
        let raw = fd.as_raw_fd();

        ioctl_int(raw, UI_SET_EVBIT, EV_KEY as i32)?;
        // Claim the whole ordinary key range rather than enumerating; the agent will do the same,
        // since it must be able to relay any key the source produces.
        for key in 1..=248i32 {
            ioctl_int(raw, UI_SET_KEYBIT, key)?;
        }

        let mut name_buf = [0 as libc::c_char; 80];
        for (dst, src) in name_buf.iter_mut().zip(name.as_bytes()) {
            *dst = *src as libc::c_char;
        }
        let setup = UinputSetup {
            id: InputId { bustype: 0x06 /* BUS_VIRTUAL */, vendor: 0x1209, product: 0x4842, version: 1 },
            name: name_buf,
            ff_effects_max: 0,
        };
        let ui_dev_setup = iow(3, std::mem::size_of::<UinputSetup>() as u64);
        let rc = unsafe { libc::ioctl(raw, ui_dev_setup, &setup as *const _) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        let rc = unsafe { libc::ioctl(raw, UI_DEV_CREATE) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        // udev needs a moment to set the device up; events written before it settles are dropped.
        std::thread::sleep(std::time::Duration::from_millis(300));
        Ok(Self { fd })
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

    pub fn key_down(&mut self, code: u16) -> io::Result<()> {
        self.emit(EV_KEY, code, 1)?;
        self.emit(EV_SYN, SYN_REPORT, 0)
    }

    pub fn key_up(&mut self, code: u16) -> io::Result<()> {
        self.emit(EV_KEY, code, 0)?;
        self.emit(EV_SYN, SYN_REPORT, 0)
    }

    pub fn tap(&mut self, code: u16) -> io::Result<()> {
        self.key_down(code)?;
        std::thread::sleep(std::time::Duration::from_millis(12));
        self.key_up(code)?;
        std::thread::sleep(std::time::Duration::from_millis(12));
        Ok(())
    }

    /// Explicitly tear the device down. Dropping without this exercises the *implicit* path — which
    /// is what a crashed agent does, and what `release-test` is checking.
    pub fn destroy(self) -> io::Result<()> {
        let rc = unsafe { libc::ioctl(self.fd.as_raw_fd(), UI_DEV_DESTROY) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn ioctl_int(fd: RawFd, req: u64, arg: i32) -> io::Result<()> {
    let rc = unsafe { libc::ioctl(fd, req, arg) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
