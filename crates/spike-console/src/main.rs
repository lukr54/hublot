//! Phase 0b — the console-mirror spike.
//!
//! Three things to prove, on a machine we're allowed to break (the VM), before any of it goes near
//! the hypervisor:
//!
//!   mirror        the screen can be read, event-driven, with correct Unicode
//!   demo          keys can be injected, and the *remote keymap* decides the character (D2)
//!   release-test  a dying agent does not leave a modifier stuck on a root console (D7)
//!
//! Needs group `tty` (read /dev/vcs*) and access to /dev/uinput. Not root, in principle — see
//! THREAT-MODEL.md §5 and R1.

mod uinput;
mod vcs;

use std::io::Write;

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_else(|| "mirror".into());
    let result = match cmd.as_str() {
        "mirror" => mirror(),
        "demo" => demo(),
        "release-test" => release_test(),
        other => {
            eprintln!("unknown command `{other}`; try: mirror | demo | release-test");
            std::process::exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        eprintln!("(reading /dev/vcs* needs group `tty`; /dev/uinput needs write access)");
        std::process::exit(1);
    }
}

/// Optional second argument switches VT first — `demo 1` to land on the getty, which is the only
/// VT that will echo what we type back at us.
fn open_active() -> std::io::Result<vcs::Console> {
    if let Some(vt) = std::env::args().nth(2).and_then(|s| s.parse::<u8>().ok()) {
        println!("→ switching to tty{vt}");
        vcs::Console::switch_to(vt)?;
    }
    let vt = vcs::Console::active_vt()?;
    println!("→ active VT is tty{vt}");
    vcs::Console::open(vt)
}

/// Stream the console. Every wake here is a real change — there is no timer in this loop.
fn mirror() -> std::io::Result<()> {
    let mut console = open_active()?;
    let mut wakes = 0u64;
    println!("mirroring tty{} — Ctrl-C to stop\n", console.vt);
    loop {
        if console.wait_for_change(5000)? {
            wakes += 1;
            let screen = console.read()?;
            print!("\x1b[2J\x1b[H");
            println!(
                "── tty{} {}x{} cursor {},{} · wake #{wakes} ──",
                console.vt,
                screen.geom.cols,
                screen.geom.lines,
                screen.geom.cursor_x,
                screen.geom.cursor_y
            );
            println!("{}", screen.text());
            std::io::stdout().flush()?;
        }
    }
}

/// Inject five keys chosen because QWERTY and AZERTY disagree about every one of them.
fn demo() -> std::io::Result<()> {
    use uinput::*;

    let mut console = open_active()?;
    let before = console.read()?;

    println!("→ creating virtual keyboard");
    let mut kb = VirtualKeyboard::create("hublot-spike")?;

    let keys = [KEY_Q, KEY_W, KEY_A, KEY_Z, KEY_M];
    println!("→ injecting keycodes {keys:?}");
    for k in keys {
        kb.tap(k)?;
    }
    std::thread::sleep(std::time::Duration::from_millis(400));

    let after = console.read()?;

    // Leave the console as we found it. Deliberately no ENTER: submitting at a login prompt lands
    // on a non-echoing password prompt, which would blind every subsequent test.
    for _ in 0..keys.len() {
        kb.tap(KEY_BACKSPACE)?;
    }
    kb.destroy()?;

    let appeared = new_chars(&before, &after);
    println!("\n── what appeared on tty{} ──\n{appeared:?}\n", console.vt);
    println!("  a QWERTY console would show:  \"qwazm\"");
    println!("  an AZERTY (fr) console shows: \"azqw,\"");
    println!(
        "\nThis is D2 in one line: we sent physical key positions, and the console's own keymap\n\
         decided the characters. Match the source layout to the remote keymap and it is exact."
    );
    Ok(())
}

/// D7's free safety layer: if the kernel releases held keys when a uinput device disappears, then
/// an agent crash cannot leave Shift (or worse, Ctrl) stuck on a root console.
///
/// We hold Shift on one device, let that device die *without* an explicit release, then tap a
/// letter from a second device. Case tells us the answer, and case is layout-independent — on this
/// AZERTY console KEY_A prints `q`, but `q` vs `Q` is all we're reading.
fn release_test() -> std::io::Result<()> {
    use uinput::*;

    let mut console = open_active()?;

    println!("→ device A: pressing LEFTSHIFT and holding");
    let mut a = VirtualKeyboard::create("hublot-spike-dying")?;
    a.key_down(KEY_LEFTSHIFT)?;
    std::thread::sleep(std::time::Duration::from_millis(200));

    println!("→ device A: closing fd with the key still down (what a crash does)");
    drop(a);
    std::thread::sleep(std::time::Duration::from_millis(400));

    let before = console.read()?;
    println!("→ device B: tapping a letter key");
    let mut b = VirtualKeyboard::create("hublot-spike-probe")?;
    b.tap(KEY_A)?;
    std::thread::sleep(std::time::Duration::from_millis(400));
    let after = console.read()?;
    b.tap(KEY_BACKSPACE)?;
    b.destroy()?;

    let appeared = new_chars(&before, &after);
    let letters: Vec<char> = appeared.chars().filter(|c| c.is_alphabetic()).collect();
    println!("\n── appeared: {appeared:?} ──");

    match letters.first() {
        Some(c) if c.is_lowercase() => {
            println!("VERDICT: keys ARE released when the device dies.");
            println!("  Got {c:?} (lowercase) — the held Shift did not survive device A.");
            println!("  D7 layer 4 confirmed: an agent crash self-heals a stuck modifier.");
        }
        Some(c) => {
            println!("VERDICT: keys are NOT released — {c:?} came out shifted.");
            println!("  D7 layer 4 does not hold. The agent-side watchdog is then load-bearing,");
            println!("  not a belt-and-braces extra. Treat it as required for v1.");
        }
        None => println!("INCONCLUSIVE: nothing legible appeared. Is a shell or login prompt focused?"),
    }
    Ok(())
}

/// Characters present in `after` at positions where it differs from `before`.
fn new_chars(before: &vcs::Screen, after: &vcs::Screen) -> String {
    if before.geom.cols != after.geom.cols || before.geom.lines != after.geom.lines {
        return after.text();
    }
    before
        .cells
        .iter()
        .zip(after.cells.iter())
        .filter(|(b, a)| b != a && !a.is_whitespace() && **a != '\0')
        .map(|(_, a)| *a)
        .collect()
}
