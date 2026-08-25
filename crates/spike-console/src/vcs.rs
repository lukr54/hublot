//! Reading the console: `/dev/vcsa<N>` for geometry, `/dev/vcsu<N>` for UCS-4 text.
//!
//! Device minors: vcs = 0..63, vcsu = 64..127, vcsa = 128..191. Only **vcsa** carries the 4-byte
//! header `{lines, cols, x, y}`; vcs and vcsu are bare screen contents.
//!
//! Change notification is `poll()`, not a timer: the driver reports readable whenever that VT has
//! been updated since the last `read()`, and delivers a forced initial POLLPRI on the first poll so
//! an update between your last read and your first poll can't be lost. That is why this costs
//! nothing at idle (DECISIONS.md D3).

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

pub struct Console {
    pub vt: u8,
    vcsa: std::fs::File,
    vcsu: std::fs::File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    pub lines: u8,
    pub cols: u8,
    pub cursor_x: u8,
    pub cursor_y: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Screen {
    pub geom: Geometry,
    /// One `char` per cell, row-major.
    pub cells: Vec<char>,
}

impl Screen {
    pub fn row(&self, y: usize) -> String {
        let w = self.geom.cols as usize;
        self.cells[y * w..(y + 1) * w].iter().collect()
    }

    pub fn rows(&self) -> impl Iterator<Item = String> + '_ {
        (0..self.geom.lines as usize).map(|y| self.row(y))
    }

    /// Non-blank rows, trimmed — what you'd actually want to show or diff.
    pub fn text(&self) -> String {
        self.rows()
            .map(|r| r.trim_end().to_string())
            .collect::<Vec<_>>()
            .join("\n")
            .trim_end()
            .to_string()
    }
}

impl Console {
    pub fn open(vt: u8) -> io::Result<Self> {
        let vcsa = std::fs::File::open(format!("/dev/vcsa{vt}"))?;
        let vcsu = std::fs::File::open(format!("/dev/vcsu{vt}"))?;
        Ok(Self { vt, vcsa, vcsu })
    }

    /// Make `vt` the active console and wait for the switch to land.
    ///
    /// Injected keys go to whatever VT is *active*, so a test that wants to see its own typing has
    /// to be on a VT where something is listening. The agent will never call this on the host —
    /// it follows the user's VT rather than choosing one.
    pub fn switch_to(vt: u8) -> io::Result<()> {
        const VT_ACTIVATE: u64 = 0x5606;
        const VT_WAITACTIVE: u64 = 0x5607;
        let tty0 = std::fs::OpenOptions::new().write(true).open("/dev/tty0")?;
        let fd = tty0.as_raw_fd();
        for req in [VT_ACTIVATE, VT_WAITACTIVE] {
            let rc = unsafe { libc::ioctl(fd, req, vt as libc::c_int) };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// The VT currently shown on the physical screen.
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
        let geom = Geometry {
            lines: header[0],
            cols: header[1],
            cursor_x: header[2],
            cursor_y: header[3],
        };

        let count = geom.lines as usize * geom.cols as usize;
        let mut buf = vec![0u8; count * 4];
        pread_exact(self.vcsu.as_raw_fd(), &mut buf, 0)?;

        let cells = buf
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| char::from_u32(u32::from_ne_bytes(*c)).unwrap_or('\u{fffd}'))
            .collect();

        Ok(Screen { geom, cells })
    }

    /// Block until this VT changes. Returns immediately the first time, by design.
    pub fn wait_for_change(&self, timeout_ms: i32) -> io::Result<bool> {
        let mut pfd = libc::pollfd {
            fd: self.vcsa.as_raw_fd(),
            events: libc::POLLPRI | libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n > 0)
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
            -1 => return Err(io::Error::last_os_error()),
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            n => done += n as usize,
        }
    }
    Ok(())
}
