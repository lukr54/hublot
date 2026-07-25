//! `KeyboardEvent.code` → evdev keycode.
//!
//! Both naming schemes identify a **physical key position** using its US-QWERTY label, so this is a
//! direct correspondence rather than a translation. Nothing here knows or cares what character the
//! key produces — that is the remote console's keymap's job, and deliberately so (DECISIONS.md D2).
//!
//! Which is why the panel captures `code` and never `key`: `key` is the character *this* machine's
//! layout would produce, and sending it would mean translating twice and getting it wrong once.

/// Returns the evdev keycode for a browser key code, or `None` for keys we don't relay.
pub fn evdev_for_code(code: &str) -> Option<u16> {
    Some(match code {
        "Escape" => 1,
        "Digit1" => 2, "Digit2" => 3, "Digit3" => 4, "Digit4" => 5, "Digit5" => 6,
        "Digit6" => 7, "Digit7" => 8, "Digit8" => 9, "Digit9" => 10, "Digit0" => 11,
        "Minus" => 12, "Equal" => 13, "Backspace" => 14, "Tab" => 15,
        "KeyQ" => 16, "KeyW" => 17, "KeyE" => 18, "KeyR" => 19, "KeyT" => 20,
        "KeyY" => 21, "KeyU" => 22, "KeyI" => 23, "KeyO" => 24, "KeyP" => 25,
        "BracketLeft" => 26, "BracketRight" => 27, "Enter" => 28, "ControlLeft" => 29,
        "KeyA" => 30, "KeyS" => 31, "KeyD" => 32, "KeyF" => 33, "KeyG" => 34,
        "KeyH" => 35, "KeyJ" => 36, "KeyK" => 37, "KeyL" => 38,
        "Semicolon" => 39, "Quote" => 40, "Backquote" => 41, "ShiftLeft" => 42, "Backslash" => 43,
        "KeyZ" => 44, "KeyX" => 45, "KeyC" => 46, "KeyV" => 47, "KeyB" => 48,
        "KeyN" => 49, "KeyM" => 50,
        "Comma" => 51, "Period" => 52, "Slash" => 53, "ShiftRight" => 54,
        "NumpadMultiply" => 55, "AltLeft" => 56, "Space" => 57, "CapsLock" => 58,
        "F1" => 59, "F2" => 60, "F3" => 61, "F4" => 62, "F5" => 63,
        "F6" => 64, "F7" => 65, "F8" => 66, "F9" => 67, "F10" => 68,
        "NumLock" => 69, "ScrollLock" => 70,
        "Numpad7" => 71, "Numpad8" => 72, "Numpad9" => 73, "NumpadSubtract" => 74,
        "Numpad4" => 75, "Numpad5" => 76, "Numpad6" => 77, "NumpadAdd" => 78,
        "Numpad1" => 79, "Numpad2" => 80, "Numpad3" => 81, "Numpad0" => 82, "NumpadDecimal" => 83,
        // The extra key AZERTY and other 102-key layouts have next to left shift. Easy to forget
        // on a US keyboard; not optional here.
        "IntlBackslash" => 86,
        "F11" => 87, "F12" => 88,
        "NumpadEnter" => 96, "ControlRight" => 97, "NumpadDivide" => 98,
        "PrintScreen" => 99, "AltRight" => 100,
        "Home" => 102, "ArrowUp" => 103, "PageUp" => 104, "ArrowLeft" => 105,
        "ArrowRight" => 106, "End" => 107, "ArrowDown" => 108, "PageDown" => 109,
        "Insert" => 110, "Delete" => 111,
        "Pause" => 119,
        "MetaLeft" => 125, "MetaRight" => 126, "ContextMenu" => 127,
        "IntlRo" => 89, "IntlYen" => 124,
        _ => return None,
    })
}

/// Highest keycode we will ever emit. The agent registers the range up to here.
pub const MAX_KEYCODE: u16 = 127;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions_map_by_place_not_by_letter() {
        // The physical key labelled A on QWERTY is KEY_A(30) — which prints `q` on the French
        // console. That is the intended behaviour, and the whole of D2.
        assert_eq!(evdev_for_code("KeyA"), Some(30));
        assert_eq!(evdev_for_code("KeyQ"), Some(16));
        assert_eq!(evdev_for_code("KeyM"), Some(50));
    }

    #[test]
    fn the_102nd_key_is_present() {
        // Missing this one is a classic: it doesn't exist on a US keyboard but AZERTY leans on it.
        assert_eq!(evdev_for_code("IntlBackslash"), Some(86));
    }

    #[test]
    fn vt_switching_keys_are_relayable() {
        for (code, expect) in [("F1", 59), ("F6", 64), ("ControlLeft", 29), ("AltLeft", 56)] {
            assert_eq!(evdev_for_code(code), Some(expect), "{code}");
        }
    }

    #[test]
    fn unknown_codes_are_dropped_not_guessed() {
        assert_eq!(evdev_for_code("BrightnessUp"), None);
        assert_eq!(evdev_for_code(""), None);
    }

    #[test]
    fn nothing_exceeds_the_registered_range() {
        for code in ["ContextMenu", "IntlYen", "Pause", "F12", "NumpadDecimal"] {
            assert!(evdev_for_code(code).unwrap() <= MAX_KEYCODE, "{code}");
        }
    }
}
