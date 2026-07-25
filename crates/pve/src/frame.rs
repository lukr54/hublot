//! termproxy's client→server framing.
//!
//! Everything the client sends is a binary websocket message with a tiny textual header.
//! Server→client is raw terminal bytes with no framing at all — do not try to parse it.
//!
//! Verified against the pve-xtermjs protocol description and an independent Go reimplementation
//! (DECISIONS.md D5). The one thing neither source agrees on is the resize argument order, which
//! is why [`resize`] takes them positionally and `spike-term` measures it.

/// `0:<byte-len>:<data>` — keystrokes / input.
pub fn data(payload: &[u8]) -> Vec<u8> {
    let mut out = format!("0:{}:", payload.len()).into_bytes();
    out.extend_from_slice(payload);
    out
}

/// `1:<cols>:<rows>:` — terminal resize.
///
/// **Cols first.** Measured 2026-07-24 against the real host: sent `1:203:37:`, and the pty reported
/// `37 203` from `stty size` (which prints rows first). The Go reimplementation's `1:{height}:{width}:`
/// is wrong; pve-xtermjs's `1:COLS:ROWS:` is right. See DECISIONS.md D5.
pub fn resize(cols: u16, rows: u16) -> Vec<u8> {
    format!("1:{cols}:{rows}:").into_bytes()
}

/// `2` — keepalive. The server expects one roughly every 30s.
pub fn ping() -> Vec<u8> {
    b"2".to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_frames_carry_byte_length_not_char_length() {
        assert_eq!(data(b"ls\n"), b"0:3:ls\n");
        // 'é' is two bytes in UTF-8 — a char count would frame this as 2 and desync the stream.
        assert_eq!(data("é\n".as_bytes()), b"0:3:\xc3\xa9\n");
    }

    #[test]
    fn control_frames() {
        // cols, then rows — the order the host actually honoured.
        assert_eq!(resize(203, 37), b"1:203:37:");
        assert_eq!(ping(), b"2");
    }
}
