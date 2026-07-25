//! Injecting keys and pointer motion with `SendInput`.
//!
//! **The keycode mapping is very nearly the identity, and that is not a coincidence.** Linux's
//! evdev keycodes were numbered from the AT set-1 scancodes, so `KEY_A` is 30 and set-1 `A` is
//! 0x1E — the same number. Everything up to F12 maps straight through; only the keys that arrive
//! with an `E0` prefix on real hardware need a table.
//!
//! Keys are sent as **scancodes**, never virtual-key codes, so the *target's* keyboard layout
//! decides which character appears. That is the same rule as the console leg (DECISIONS.md D2):
//! we transmit which key was pressed, never what it means.

use windows::Win32::UI::Input::KeyboardAndMouse::*;

/// evdev keycode → (set-1 scancode, needs the E0 prefix).
fn scancode(evdev: u16) -> Option<(u16, bool)> {
    // Identity for the main block: evdev was numbered from these very scancodes.
    if (1..=88).contains(&evdev) && !(84..=85).contains(&evdev) {
        return Some((evdev, false));
    }
    Some((
        match evdev {
            96 => 0x1C,  // keypad enter
            97 => 0x1D,  // right ctrl
            98 => 0x35,  // keypad /
            99 => 0x37,  // print screen
            100 => 0x38, // right alt
            102 => 0x47, // home
            103 => 0x48, // up
            104 => 0x49, // page up
            105 => 0x4B, // left
            106 => 0x4D, // right
            107 => 0x4F, // end
            108 => 0x50, // down
            109 => 0x51, // page down
            110 => 0x52, // insert
            111 => 0x53, // delete
            125 => 0x5B, // left meta
            126 => 0x5C, // right meta
            127 => 0x5D, // menu
            _ => return None,
        },
        true,
    ))
}

fn send(inputs: &[INPUT]) {
    unsafe {
        SendInput(inputs, std::mem::size_of::<INPUT>() as i32);
    }
}

/// Tracks what is held so a session can be ended cleanly.
///
/// Windows has no equivalent of the kernel releasing a dying uinput device's keys, so what came
/// free on Linux has to be done by hand here — and it matters just as much, since a stuck Alt on
/// a remote desktop is every bit as unpleasant.
#[derive(Default)]
pub struct Injector {
    held_keys: std::collections::HashSet<u16>,
    held_buttons: std::collections::HashSet<u8>,
    screen: (u16, u16),
}

impl Injector {
    pub fn new(screen_w: u16, screen_h: u16) -> Self {
        // Built field by field rather than with `..Default::default()`: a type that implements Drop
        // cannot be partially moved from.
        Self {
            held_keys: Default::default(),
            held_buttons: Default::default(),
            screen: (screen_w.max(1), screen_h.max(1)),
        }
    }

    pub fn key(&mut self, evdev: u16, down: bool) {
        let Some((sc, extended)) = scancode(evdev) else { return };
        // Suppress autorepeat from the source; the target does its own.
        if down && !self.held_keys.insert(evdev) {
            return;
        }
        if !down && !self.held_keys.remove(&evdev) {
            return;
        }
        let mut flags = KEYEVENTF_SCANCODE;
        if extended {
            flags |= KEYEVENTF_EXTENDEDKEY;
        }
        if !down {
            flags |= KEYEVENTF_KEYUP;
        }
        send(&[INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT { wVk: VIRTUAL_KEY(0), wScan: sc, dwFlags: flags, time: 0, dwExtraInfo: 0 },
            },
        }]);
    }

    pub fn move_to(&self, x: u16, y: u16) {
        // Absolute coordinates are normalised to 0..65535 across the primary display, which is the
        // one we capture.
        let nx = (x as u32 * 65535 / (self.screen.0.saturating_sub(1)).max(1) as u32) as i32;
        let ny = (y as u32 * 65535 / (self.screen.1.saturating_sub(1)).max(1) as u32) as i32;
        send(&[INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx: nx,
                    dy: ny,
                    mouseData: 0,
                    dwFlags: MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }]);
    }

    pub fn button(&mut self, button: u8, down: bool) {
        if down && !self.held_buttons.insert(button) {
            return;
        }
        if !down && !self.held_buttons.remove(&button) {
            return;
        }
        let flags = match (button, down) {
            (0, true) => MOUSEEVENTF_LEFTDOWN,
            (0, false) => MOUSEEVENTF_LEFTUP,
            (1, true) => MOUSEEVENTF_RIGHTDOWN,
            (1, false) => MOUSEEVENTF_RIGHTUP,
            (2, true) => MOUSEEVENTF_MIDDLEDOWN,
            (2, false) => MOUSEEVENTF_MIDDLEUP,
            _ => return,
        };
        send(&[INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT { dx: 0, dy: 0, mouseData: 0, dwFlags: flags, time: 0, dwExtraInfo: 0 },
            },
        }]);
    }

    pub fn scroll(&self, dx: i16, dy: i16) {
        for (flag, amount) in [(MOUSEEVENTF_WHEEL, dy), (MOUSEEVENTF_HWHEEL, dx)] {
            if amount == 0 {
                continue;
            }
            send(&[INPUT {
                r#type: INPUT_MOUSE,
                Anonymous: INPUT_0 {
                    mi: MOUSEINPUT {
                        dx: 0,
                        dy: 0,
                        mouseData: (amount as i32 * 120) as u32,
                        dwFlags: flag,
                        time: 0,
                        dwExtraInfo: 0,
                    },
                },
            }]);
        }
    }

    pub fn release_all(&mut self) {
        for evdev in std::mem::take(&mut self.held_keys) {
            if let Some((sc, extended)) = scancode(evdev) {
                let mut flags = KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP;
                if extended {
                    flags |= KEYEVENTF_EXTENDEDKEY;
                }
                send(&[INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT { wVk: VIRTUAL_KEY(0), wScan: sc, dwFlags: flags, time: 0, dwExtraInfo: 0 },
                    },
                }]);
            }
        }
        for button in std::mem::take(&mut self.held_buttons) {
            let flags = match button {
                0 => MOUSEEVENTF_LEFTUP,
                1 => MOUSEEVENTF_RIGHTUP,
                2 => MOUSEEVENTF_MIDDLEUP,
                _ => continue,
            };
            send(&[INPUT {
                r#type: INPUT_MOUSE,
                Anonymous: INPUT_0 {
                    mi: MOUSEINPUT { dx: 0, dy: 0, mouseData: 0, dwFlags: flags, time: 0, dwExtraInfo: 0 },
                },
            }]);
        }
    }
}

impl Drop for Injector {
    /// The connection ending must not leave a modifier down on someone's desktop.
    fn drop(&mut self) {
        self.release_all();
    }
}

#[cfg(test)]
mod tests {
    use super::scancode;

    #[test]
    fn the_main_block_is_the_identity() {
        // evdev was numbered from set-1, so these agree by construction rather than by table.
        assert_eq!(scancode(30), Some((0x1E, false))); // A
        assert_eq!(scancode(16), Some((0x10, false))); // Q
        assert_eq!(scancode(88), Some((0x58, false))); // F12
    }

    #[test]
    fn extended_keys_carry_the_e0_prefix() {
        assert_eq!(scancode(103), Some((0x48, true))); // up arrow
        assert_eq!(scancode(97), Some((0x1D, true))); // right ctrl
        assert_eq!(scancode(29), Some((0x1D, false))); // left ctrl — same scancode, no prefix
    }

    #[test]
    fn unmapped_codes_are_dropped() {
        assert_eq!(scancode(0), None);
        assert_eq!(scancode(200), None);
    }
}
