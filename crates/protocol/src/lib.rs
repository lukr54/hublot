//! The agent link: what the host agent sends the panel, and how it is framed.
//!
//! **The mirror is a cell grid, not a byte stream.** The kernel's console driver has already done
//! the terminal emulation — `/dev/vcsu` hands us a finished 2D buffer of characters and `/dev/vcsa`
//! the matching attributes. So nothing on this link needs a VT parser, and neither end contains
//! one. That is the single biggest simplification in the project, and it exists only because we
//! read the console rather than a pty.

pub mod keymap;

/// Re-exported so both ends of every link reach pinning by the same path.
pub use pinning as pin;

use anyhow::{bail, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;
pub const ALPN: &[u8] = b"hublot/1";

/// Refuse anything larger before allocating for it. A console frame is a few KB; this is three
/// orders of magnitude of headroom and still bounds what a hostile peer can make us allocate.
pub const MAX_MSG: usize = 1 << 20;

/// Clipboard payloads above this are dropped rather than synced. Someone copying a large file's
/// worth of text should not have it silently cross the network, and it bounds what a hostile peer
/// can push into your clipboard.
pub const MAX_CLIPBOARD: usize = 256 * 1024;

/// One console cell: a Unicode character and the VGA attribute byte that goes with it.
///
/// Attribute layout (the console's, not ours): bits 0–3 foreground, 4–6 background, bit 7 blink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cell {
    pub ch: char,
    pub attr: u8,
}

impl Default for Cell {
    fn default() -> Self {
        Self { ch: ' ', attr: 0x07 }
    }
}

/// A contiguous span of changed cells, addressed by offset into the row-major grid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    pub offset: u32,
    pub cells: Vec<Cell>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RasterFormat {
    /// Lossy, small, and slightly soft on text. Fine for photographic content.
    Jpeg,
    /// Lossless. Costs more bytes but keeps text crisp, which is what a desktop is mostly made of.
    Png,
}

impl RasterFormat {
    pub fn mime(self) -> &'static str {
        match self {
            RasterFormat::Jpeg => "image/jpeg",
            RasterFormat::Png => "image/png",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Screen {
    pub vt: u8,
    pub cols: u16,
    pub rows: u16,
    pub cursor: (u16, u16),
    pub cells: Vec<Cell>,
}

/// How a client claims to be allowed in.
///
/// Either way the TLS handshake has already proven possession of the client key, and the agent
/// compares that certificate's fingerprint — the token only ever authorises *enrolling* a new
/// fingerprint, never a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Auth {
    /// First contact: present the agent's printed token to have our certificate enrolled.
    Enrol { token: String },
    /// Every time after that. Carries nothing — the certificate did the talking.
    Certificate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientMsg {
    Hello { version: u32, auth: Auth },
    /// A physical key, by evdev code. The *remote* keymap decides which character appears —
    /// see DECISIONS.md D2.
    Key { code: u16, down: bool },
    /// Release everything held. Sent on focus loss, view change, and window hide.
    ReleaseAll,
    /// Text copied on the panel's machine, offered to the remote one.
    Clipboard { text: String },
    /// Absolute pointer position, in the captured screen's own pixels.
    ///
    /// Absolute rather than relative on purpose: a lost or reordered motion message is corrected by
    /// the very next one, where a lost *delta* would leave the two cursors permanently offset.
    MouseMove { x: u16, y: u16 },
    /// 0 = left, 1 = right, 2 = middle.
    MouseButton { button: u8, down: bool },
    /// Wheel notches; positive is away from the user.
    MouseScroll { dx: i16, dy: i16 },
    /// Switch the active console by **ioctl**, not by injecting Ctrl+Alt+Fn.
    ///
    /// This exists because a VT whose keyboard is disabled (`K_OFF`) ignores the chord that would
    /// take you off it — so injection-based switching can strand the user on a console they cannot
    /// leave. `VT_ACTIVATE` works regardless of keyboard mode. See DECISIONS.md D13.
    SwitchVt { vt: u8 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerMsg {
    /// Sent on connect, on VT switch, and whenever the geometry changes.
    Full(Screen),
    /// Only the cells that changed since the previous message.
    Diff {
        vt: u8,
        cursor: (u16, u16),
        runs: Vec<Run>,
    },
    /// Enrolment succeeded; the client's certificate is now on the agent's allowlist and the token
    /// will not be accepted again.
    Enrolled,
    /// Geometry of a graphical desktop. Sent once on connect and whenever it changes.
    ScreenInfo { w: u16, h: u16 },
    /// Text copied on the remote machine, offered to the panel's.
    Clipboard { text: String },
    /// Where the remote pointer is. Captured frames never contain it — Windows composites the
    /// cursor in hardware — so it travels separately and the viewer draws it.
    Pointer { x: i16, y: i16, visible: bool },
    /// What the remote pointer looks like. Sent only when it changes, so the viewer caches it.
    /// PNG because a cursor is hard edges plus an alpha channel.
    PointerShape { w: u16, h: u16, hot_x: u16, hot_y: u16, png: Vec<u8> },
    /// A rectangle of the desktop that changed.
    ///
    /// The console leg ships characters because the kernel finished the rendering for us; a
    /// Windows desktop has no such gift, so this leg ships pixels. The compression format is
    /// per-rectangle rather than per-session: text regions want lossless, photographic ones do not.
    Raster {
        x: u16,
        y: u16,
        w: u16,
        h: u16,
        format: RasterFormat,
        data: Vec<u8>,
    },
    /// Whether this session may inject. A read-only agent, or one that could not open
    /// `/dev/uinput`, says so up front rather than swallowing keystrokes silently.
    Input { enabled: bool, reason: String },
    Error(String),
}

/// Compute the runs of cells that differ. Returns `None` when the grids are not comparable
/// (different geometry), which the caller must answer with a `Full`.
pub fn diff(prev: &Screen, next: &Screen) -> Option<Vec<Run>> {
    if prev.cols != next.cols || prev.rows != next.rows || prev.vt != next.vt {
        return None;
    }
    let mut runs = Vec::new();
    let mut i = 0usize;
    while i < next.cells.len() {
        if prev.cells[i] == next.cells[i] {
            i += 1;
            continue;
        }
        let start = i;
        // Extend through unchanged gaps shorter than the per-run overhead; splitting on every
        // single matching cell would produce more framing bytes than it saves.
        let mut last_change = i;
        while i < next.cells.len() && i - last_change < 8 {
            if prev.cells[i] != next.cells[i] {
                last_change = i;
            }
            i += 1;
        }
        runs.push(Run {
            offset: start as u32,
            cells: next.cells[start..=last_change].to_vec(),
        });
        i = last_change + 1;
    }
    Some(runs)
}

/// Apply runs in place. Returns false if a run would fall outside the grid — which means the two
/// ends have desynchronised and the caller should ask for a fresh `Full`.
pub fn apply(screen: &mut Screen, runs: &[Run]) -> bool {
    for run in runs {
        let start = run.offset as usize;
        let end = start + run.cells.len();
        if end > screen.cells.len() {
            return false;
        }
        screen.cells[start..end].copy_from_slice(&run.cells);
    }
    true
}

// ── framing ─────────────────────────────────────────────────────────────────────────────────────

pub async fn write_msg<T: Serialize>(send: &mut quinn::SendStream, msg: &T) -> Result<()> {
    let body = postcard::to_stdvec(msg).context("encoding message")?;
    if body.len() > MAX_MSG {
        bail!("refusing to send {} byte message", body.len());
    }
    send.write_all(&(body.len() as u32).to_le_bytes()).await?;
    send.write_all(&body).await?;
    Ok(())
}

pub async fn read_msg<T: DeserializeOwned>(recv: &mut quinn::RecvStream) -> Result<T> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await.context("reading length prefix")?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_MSG {
        bail!("peer announced a {len} byte message; refusing");
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await.context("reading body")?;
    postcard::from_bytes(&body).context("decoding message")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn screen(cells: &str) -> Screen {
        Screen {
            vt: 1,
            cols: cells.chars().count() as u16,
            rows: 1,
            cursor: (0, 0),
            cells: cells.chars().map(|ch| Cell { ch, attr: 7 }).collect(),
        }
    }

    #[test]
    fn identical_screens_produce_no_runs() {
        let a = screen("hello world");
        assert!(diff(&a, &a).unwrap().is_empty());
    }

    #[test]
    fn diff_then_apply_reproduces_the_target() {
        // Same width — a console grid never changes size just because someone typed.
        let a = screen("root@pve:~#  ");
        let b = screen("root@pve:~# w");
        let runs = diff(&a, &b).unwrap();
        let mut patched = a.clone();
        assert!(apply(&mut patched, &runs));
        assert_eq!(patched.cells, b.cells);
    }

    #[test]
    fn geometry_change_forces_a_full_frame() {
        assert!(diff(&screen("abc"), &screen("abcd")).is_none());
    }

    #[test]
    fn small_gaps_are_coalesced_into_one_run() {
        // Two changes three cells apart: one run is cheaper than two.
        let runs = diff(&screen("aXbbYc"), &screen("aZbbWc")).unwrap();
        assert_eq!(runs.len(), 1);
    }

    /// The whole tier-1 update path except the socket: diff a change, wrap it as the agent would,
    /// encode and decode it exactly as the wire does, then apply it as the client does. Guards the
    /// serialisation of `Diff`, which is otherwise only exercised when a remote console happens to
    /// change while someone is watching.
    #[test]
    fn a_diff_survives_the_wire_and_reproduces_the_screen() {
        let before = screen("dev login:      ");
        let after = screen("dev login: root ");

        let runs = diff(&before, &after).expect("same geometry");
        assert!(!runs.is_empty(), "a visible change must produce runs");

        let encoded = postcard::to_stdvec(&ServerMsg::Diff {
            vt: after.vt,
            cursor: after.cursor,
            runs,
        })
        .unwrap();
        let decoded: ServerMsg = postcard::from_bytes(&encoded).unwrap();

        let ServerMsg::Diff { vt, cursor, runs } = decoded else {
            panic!("round-trip changed the message type");
        };
        assert_eq!(vt, after.vt);
        assert_eq!(cursor, after.cursor);

        let mut patched = before.clone();
        assert!(apply(&mut patched, &runs));
        assert_eq!(patched.cells, after.cells, "reassembled screen must match the source");
    }

    #[test]
    fn apply_rejects_a_run_past_the_end() {
        let mut s = screen("abc");
        let bad = vec![Run { offset: 2, cells: vec![Cell::default(); 4] }];
        assert!(!apply(&mut s, &bad));
    }
}
