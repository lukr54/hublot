//! Reading the physical console.
//!
//! `/dev/vcsa<N>` gives the 4-byte header `{lines, cols, x, y}` followed by one `u16` per cell
//! (low byte character, high byte attribute). `/dev/vcsu<N>` gives the same grid as UCS-4 with no
//! header and no attributes. We read **both**: text from `vcsu` because the console is UTF-8 and
//! `vcsa`'s 8-bit cells cannot carry a French locale's output, attributes from `vcsa` because
//! `vcsu` has none.
//!
//! Change notification is `poll()`, not a timer. Both of the descriptors it watches have a way of
//! never blocking that reads like working code.
//!
//! On `/dev/vcsa*` the signal is `POLLPRI`, never `POLLIN`. `vcs_poll()` returns `DEFAULT_POLLMASK`
//! for these devices, so readability is set on every poll whatever the console is doing: there is
//! always a screen there to read. `POLLPRI` is the only bit meaning *changed since the last
//! `read()`*, and the driver forces an initial one so an update between the last read and the first
//! poll cannot be lost.
//!
//! On `/sys/class/tty/tty0/active` the pending event has to be consumed by reading that exact
//! descriptor before each poll, or kernfs goes on reporting it. See `drain_active`.
//!
//! Get either wrong and `poll()` returns at once every time, the timeout never engages, and this
//! becomes a busy loop re-decoding the whole grid as fast as the core allows. Both were wrong
//! together, at a steady 100% of a core with nothing connected. Polled correctly, idle costs
//! nothing.

use std::io;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, RawFd};

use protocol::{Cell, Screen};

pub struct Console {
    pub vt: u8,
    vcsa: std::fs::File,
    vcsu: std::fs::File,
    /// Held open so we can poll it: the VT driver calls `sysfs_notify` on this attribute when the
    /// active console changes, which is how we notice the user switching away.
    active: std::fs::File,
}

impl Console {
    pub fn open(vt: u8) -> io::Result<Self> {
        Ok(Self {
            vt,
            vcsa: std::fs::File::open(format!("/dev/vcsa{vt}"))?,
            vcsu: std::fs::File::open(format!("/dev/vcsu{vt}"))?,
            active: std::fs::File::open("/sys/class/tty/tty0/active")?,
        })
    }

    /// Switch the active console. Works whatever mode the keyboard is in, which is the entire
    /// point — see DECISIONS.md D13.
    pub fn switch_to(vt: u8) -> io::Result<()> {
        const VT_ACTIVATE: u64 = 0x5606;
        const VT_WAITACTIVE: u64 = 0x5607;
        let tty0 = std::fs::OpenOptions::new().write(true).open("/dev/tty0")?;
        for req in [VT_ACTIVATE, VT_WAITACTIVE] {
            if unsafe { libc::ioctl(tty0.as_raw_fd(), req, vt as libc::c_int) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Whether the *currently active* console will act on injected keys.
    ///
    /// `K_OFF` means the kernel drops keyboard input for that VT entirely; the raw modes hand
    /// scancodes to the foreground process, which a getty will not echo. In every one of those
    /// cases our `write()` succeeds and nothing happens — which is exactly the failure that cost
    /// an afternoon to diagnose (D13). Report it up front instead.
    pub fn keyboard_accepts_input() -> io::Result<(u8, bool)> {
        const KDGKBMODE: u64 = 0x4B44;
        const K_XLATE: u8 = 0x01;
        const K_UNICODE: u8 = 0x03;
        let tty0 = std::fs::OpenOptions::new().write(true).open("/dev/tty0")?;
        let mut mode: libc::c_long = 0;
        if unsafe { libc::ioctl(tty0.as_raw_fd(), KDGKBMODE, &mut mode) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mode = mode as u8;
        Ok((mode, matches!(mode, K_XLATE | K_UNICODE)))
    }

    pub fn describe_kbd_mode(mode: u8) -> &'static str {
        match mode {
            0x00 => "raw (scancode) mode — a getty will not echo",
            0x01 => "XLATE",
            0x02 => "mediumraw (keycode) mode — a getty will not echo",
            0x03 => "Unicode",
            0x04 => "K_OFF — keyboard input is disabled for this console",
            _ => "an unrecognised mode",
        }
    }

    pub fn active_vt() -> io::Result<u8> {
        let s = std::fs::read_to_string("/sys/class/tty/tty0/active")?;
        s.trim()
            .strip_prefix("tty")
            .and_then(|n| n.parse().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("bad active vt: {s:?}")))
    }

    pub fn read(&mut self) -> io::Result<Screen> {
        let mut header = [0u8; 4];
        pread_exact(self.vcsa.as_raw_fd(), &mut header, 0)?;
        let (rows, cols) = (header[0] as usize, header[1] as usize);
        let count = rows * cols;

        let mut attrs = vec![0u8; count * 2];
        pread_exact(self.vcsa.as_raw_fd(), &mut attrs, 4)?;

        let mut text = vec![0u8; count * 4];
        pread_exact(self.vcsu.as_raw_fd(), &mut text, 0)?;

        let cells = (0..count)
            .map(|i| {
                let cp = u32::from_ne_bytes([
                    text[i * 4],
                    text[i * 4 + 1],
                    text[i * 4 + 2],
                    text[i * 4 + 3],
                ]);
                Cell {
                    ch: char::from_u32(cp).unwrap_or('\u{fffd}'),
                    attr: attrs[i * 2 + 1],
                }
            })
            .collect();

        Ok(Screen {
            vt: self.vt,
            cols: cols as u16,
            rows: rows as u16,
            cursor: (header[2] as u16, header[3] as u16),
            cells,
        })
    }

    /// Consume the pending sysfs event so the next `poll()` waits for the *next* one.
    ///
    /// kernfs decides "has this changed?" by comparing a counter on this descriptor against one on
    /// the node, and only a `read()` of **this** descriptor moves it. Reading the value through a
    /// separate `File::open` — which is what `active_vt()` does — leaves this one untouched, so the
    /// counters never agree and `poll()` reports `POLLPRI` immediately, every time, forever. The
    /// seek matters as much as the read: at EOF the next read returns 0 without re-entering the
    /// kernel's seq-file start, and the counter stays where it was.
    fn drain_active(&self) -> io::Result<()> {
        let mut f = &self.active;
        f.seek(SeekFrom::Start(0))?;
        let mut buf = [0u8; 64];
        loop {
            match f.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// Block until the console changes or the active VT is switched.
    ///
    /// The timeout is a safety net, not the mechanism — if the sysfs notification for VT switches
    /// ever stops firing we still notice within a couple of seconds instead of never.
    pub fn wait(&self, timeout_ms: i32) -> io::Result<()> {
        // Before blocking, not after: a switch that lands between here and the `poll()` below bumps
        // the node's counter and the poll returns at once, so re-arming early cannot lose one.
        self.drain_active()?;

        let mut fds = [
            // `POLLPRI` alone, and never `POLLIN`: see the note at the top of this file. Asking for
            // readability here is asking for something that is always true, and the wait stops
            // waiting.
            libc::pollfd { fd: self.vcsa.as_raw_fd(), events: libc::POLLPRI, revents: 0 },
            libc::pollfd { fd: self.active.as_raw_fd(), events: libc::POLLPRI, revents: 0 },
        ];
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout_ms) };
        if n < 0 {
            let e = io::Error::last_os_error();
            // A signal during poll is not a failure; the caller loops and polls again.
            if e.kind() == io::ErrorKind::Interrupted {
                return Ok(());
            }
            return Err(e);
        }
        Ok(())
    }
}

fn pread_exact(fd: RawFd, buf: &mut [u8], offset: i64) -> io::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        let n = unsafe {
            libc::pread(
                fd,
                buf[done..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - done,
                offset + done as i64,
            )
        };
        match n {
            -1 => {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            n => done += n as usize,
        }
    }
    Ok(())
}
