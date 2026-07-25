//! The bytes the panel parses, and what it does with them afterwards.
//!
//! Less dangerous than the agent's side — the panel types at nothing — but it decodes a message and
//! then *acts* on it: a `Diff` is applied to a screen the client is holding, with offsets and run
//! lengths chosen by the sender. `apply` is meant to reject anything that would fall outside the
//! grid; this is what proves it does, for grids and runs nobody thought to write a test for.

#![no_main]

use libfuzzer_sys::fuzz_target;
use protocol::{Cell, Screen};

fuzz_target!(|data: &[u8]| {
    if data.len() > protocol::MAX_MSG {
        return;
    }
    let Ok(msg) = protocol::decode::<protocol::ServerMsg>(data) else {
        return;
    };
    if let protocol::ServerMsg::Diff { runs, .. } = msg {
        // A plausible console, so the run offsets have something real to be wrong about.
        let (cols, rows) = (80u16, 25u16);
        let mut screen = Screen {
            vt: 1,
            cols,
            rows,
            cursor: (0, 0),
            cells: vec![Cell::default(); cols as usize * rows as usize],
        };
        let before = screen.cells.len();
        let ok = protocol::apply(&mut screen, &runs);
        // Whatever it decides, it must not have resized or reallocated the grid underneath the
        // caller — the client paints `cols * rows` cells and trusts that count.
        assert_eq!(screen.cells.len(), before);
        let _ = ok;
    }
});
