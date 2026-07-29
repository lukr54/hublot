# Software KVM — Decision Register

> One entry per decision that shapes the code, with the evidence behind it. Written 2026-07-24,
> before any code existed — the point was to be wrong on paper, cheaply.
> Facts here are **measured or cited**, not recalled. Anything unverified is marked ⚠️.

---

## D0. Why build this at all — the honest accounting

**This has to come first, because port 22 is open on the Proxmox host.**

`ssh root@192.168.1.10` in Windows Terminal, today, with zero lines of code, already achieves:
your desk keyboard becomes unnecessary for shell work, and you stop switching monitor inputs.
Those were the two things you asked for. Any plan that doesn't confront this is theater.

So, precisely, what does this project add over an SSH window?

| Gain | Real? | Notes |
|------|-------|-------|
| See what's **actually on** the console | **Yes** | boot messages, failed systemd units printing to tty1, kernel oopses, emergency shell. SSH structurally cannot show these — it's a different session. |
| **Copy text off the console** | **Yes, and it beats the physical screen** | you cannot select text on a physical TTY. The mirror holds the character buffer, so selection, copy, and search become possible. This is a capability *gain*, not parity. |
| One hotkey-summoned window that's always there | Yes, modest | ergonomics, not capability |
| Works when sshd is down but the agent isn't | Marginal | narrow window; and tier 2 covers "agent down, pveproxy up" |
| Works when the network is down | **No** | the classic reason to walk to the console. The agent is unreachable then too. That's IPMI/PiKVM territory and this project must never claim it. |

**Conclusion / recommended scope.** Phase 1 (panel + tier-2 shell) is small, immediately useful, and
worth doing on its own. Phases 2–3 (the mirror + injection) are **the actual project**, and their
justification is *"I want to see and copy from the real console, in one unified window"* — plus it
being a genuinely interesting Rust problem. That is a legitimate reason to build something. It is
not the same as necessity, and the README should say so in those words.

---

## D1. Auth model — forced by Proxmox, not chosen

**⚠️→✅ Resolved: PVE API tokens do NOT work for console endpoints.** Multiple confirmed reports:
`termproxy`/`vncshell` reject token principals with *"value 'root@pam!Test01' does not look like a
valid user name"*, and `vncwebsocket` 401s. The token name appended to the principal breaks the
ticket validation path used by console endpoints.

**Consequence:** the panel must hold a **real login credential** and call
`POST /api2/json/access/ticket` (ticket valid ~2 h, plus a CSRF token).

**Decision:** do **not** store `root@pam`. Create a dedicated PVE user — `console@pve` — granted only:
- `Sys.Console` on `/nodes/pve` (host shell)
- `VM.Console` on `/vms/<vmid>` (the VM's console)

Store its password sealed with **DPAPI, user-scoped**, in Windows Credential Manager. Pin the PVE
cluster CA (`CN=pve.example`) in the Rust TLS config, so the self-signed warning stops being something you
click through and starts being something that fails loudly.

**Honest caveat, do not gloss:** `Sys.Console` on a node grants a **root shell** on that node. The
stored credential is root-shell-equivalent no matter how narrow the role looks. The gain over
`root@pam` is that it can't drive the rest of the API (create/destroy VMs, read all configs, change
firewall) — real, but partial.

**✅ Decided: store it.** DPAPI user-scoped, in Windows Credential Manager. Rationale accepted: a tool
you must authenticate to is a tool you stop using, and an SSH key granting root on that same host
already lives on this machine — the marginal exposure is small. Keep "prompt per Windows login" as a
config toggle for anyone who wants it, but it is not the default and not a v1 blocker.

---

## D2. Keyboard layout — the sharpest edge in the whole design

**Measured:** your Windows PC has **two** layouts loaded — `00000809` (UK English, primary) and
`0000040c` (French). The Ubuntu VM's console keymap is **`fr`, variant `oss`** (AZERTY), charmap
UTF-8. The **Proxmox host's is `fr` with an empty variant** — plain AZERTY — and `datacenter.cfg`
carries `keyboard: fr`, so the VM's VNC console leg maps the same way.

**This is a small stroke of luck.** Windows `0000040c` (French — France) corresponds to plain X11
`fr`, *not* to `fr-oss`, which differs in dead keys and AltGr placement. So the machine we actually
inject into (the host) is an **exact** match for a layout you already have installed, and the pinning
in option (c) below is precise rather than approximate. Had we been injecting into the VM, we'd be
one variant off and chasing intermittent wrong characters.

The problem: `uinput` injects **physical key identities** (evdev keycodes). The remote console then
applies **its own** keymap. Press the physical key labelled `A` on a UK layout, send its keycode, and
an AZERTY console prints `q`. If Windows is in UK mode and the console is `fr`, everything you type
is scrambled.

**Options considered:**

| Option | How | Verdict |
|--------|-----|---------|
| (a) Raw scancode passthrough | send physical keycode, remote keymap applies | Correct **only** when your active Windows layout matches the remote keymap |
| (b) Character-level re-synthesis | capture the character Windows produced, reverse-map it to a keycode+modifier combo on the remote keymap (dump it with `dumpkeys`) | Handles mismatched layouts, but dead keys, compose sequences, AltGr and non-typable characters all become edge cases. Fragile. |
| (c) **Passthrough + layout pinning** | on panel focus, force the Windows layout to the one matching the remote console (`ActivateKeyboardLayout`); restore on blur; show which layout is live | **Chosen** |

**Why (c):** it makes (a) *correct by construction* instead of correct by luck, costs ~20 lines,
and has no edge cases — the remote keymap does exactly the job it was designed for. You already have
`fr` installed on Windows, so the switch is free. Requirement: the panel must show, unmissably, which
layout is active while the console is focused.

**Concretely:** on panel focus → `ActivateKeyboardLayout(0x0000040C)`; on blur → restore the previous
HKL. Store the target layout per remote node in config (it is a property of the *remote keymap*, not
a global setting) so a future node with a different keymap just works.

**✅ Confirmed empirically 2026-07-24** (`spike-console demo`). Injected keycodes
`[16, 17, 30, 44, 50]` — physical Q, W, A, Z, M — and the console rendered **`azqw,`**, not
`qwazm`. Every one of the five characters differs from what a QWERTY console would have produced.
This is the failure mode in miniature: nothing errors, nothing warns, you simply get different text
than you typed. Layout pinning is not a nicety.

Fall back to (b) only if you later drive a machine whose keymap you can't match.

**Revised at implementation time (Phase 3, 2026-07-25) — (c) became "warn", not "switch".**

The panel captures `KeyboardEvent.code`, which already names the **physical** key position and is
completely independent of the active Windows layout. So the transmitted keycode is correct no matter
what layout is loaded — option (a)'s failure mode never reaches the wire.

What remains is purely human: if you are *thinking* in UK layout, you will press the key labelled A
expecting `a`, and the French console will print `q`. Nothing is technically wrong; the person is.

Auto-switching the layout (`ActivateKeyboardLayout`) is per-thread, and WebView2 handles input on
its own thread — so silently changing the layout might simply not take effect where it matters, and
"looks like it works, sometimes doesn't" is the worst outcome available. Instead the panel
**detects and says so**: `navigator.keyboard.getLayoutMap()` reports what the live layout produces
for a physical key (`KeyQ` → `a` on AZERTY, `q` on UK/US), and a badge appears when it disagrees
with the console's `fr` keymap.

Honest trade: telling you beats fixing it silently *and unreliably*. Auto-switch stays available if
the badge proves annoying, but it needs testing against WebView2's input thread before it is
trustworthy.

⚠️ **One residual mismatch, low priority:** the VM's console is `fr-oss` while PVE maps its VNC input
as plain `fr`. Keys where the two variants differ will be wrong *in the VM console tab only* (Phase 4,
rarely used — the VM is an SSH box). Fix by aligning the VM to plain `fr`, not by writing code.

---

## D3. Change notification — event-driven, not polled

**⚠️→✅ Resolved:** `/dev/vcs*` supports **`poll()`/`select()` and SIGIO**. Semantics: readable is
reported whenever that VT has been updated since the last `read()`. A **forced initial `POLLPRI`** is
delivered on the first `poll()`, deliberately, so you can't lose an update that happened between your
last read and your first poll. This support was added precisely to kill the 40 ms polling loops that
Braille daemons used to run.

**Consequence:** the mirror is **event-driven and costs nothing at idle** — no 30 Hz poll loop.

**Implementation trap, worth knowing now:** `POLLPRI` is not supported by tokio's async fd
readiness (open upstream issue). Do **not** try to bolt this onto the async runtime. Run a dedicated
blocking thread calling `libc::poll` with `POLLPRI|POLLIN`, `read()` the buffer, diff it, and send
frames over a channel to the async side. Small, obvious, testable.

---

## D4. `vcsa` vs `vcsu` — read both

**Measured on the VM:** `/dev/vcs{,1-6}`, `/dev/vcsa{,1-6}` **and** `/dev/vcsu{,1-6}` all exist,
mode `0660`, owner `root:tty`.

- `vcsa` — 4-byte header `{lines, cols, x, y}` then one `unsigned short` per cell (host byte order):
  low byte = character, high byte = attributes. **8-bit characters only.** Console is UTF-8, so
  anything outside the console's 256-glyph map is lost here.
- `vcsu` — UCS-4 characters, **no attributes**, read-only. Solves the Unicode problem.
- ⚠️ The man page shipped on man7/Debian is an older revision: it documents neither `vcsu` nor the
  poll semantics. Trust the measured devices and the kernel patches, and confirm in spike 0b.

**Decision:** read **`vcsu` for text + `vcsa` for the header and attributes**, two reads on the same
notification. Cost is trivial (80×25 → 8 KB + 4 KB) and it gets you correct box-drawing and accents,
which a French-locale console will produce.

Note the man page's stated `0644` does **not** match this machine's `0660` — another reason to trust
measurement over documentation here.

---

## D5. Tier-2 wire protocol — verified

Sequence to open a host shell without any agent:

1. `POST /api2/json/access/ticket` → `ticket`, `CSRFPreventionToken`
2. `POST /api2/json/nodes/pve/termproxy` → `{user, ticket, port}`
3. WebSocket to `wss://192.168.1.10:8006/api2/json/nodes/pve/vncwebsocket?port=…&vncticket=…`,
   sending the `PVEAuthCookie` as a header on the upgrade
4. **First websocket message** (binary): `<user>:<ticket>\n` → server replies `OK`
5. Then: input `0:<len>:<data>` · resize `1:<a>:<b>:` · ping `2` every 30 s

Gotchas confirmed by an independent Go reimplementation: **binary frames only**, and **no concurrent
writes** to the socket (serialize through one writer task).

**✅ Whole path verified against the real host 2026-07-24** (`spike-term`): ticket → termproxy
(port 5900) → websocket → `OK` → commands round-tripping from a root shell on `ai`
(Linux 6.17.2-1-pve). Certificate pinning worked as designed.

**✅ Resize order settled: `1:<cols>:<rows>:` — cols first.** Sent `1:203:37:`; the pty reported
`37 203` from `stty size`, which prints rows first. So pve-xtermjs's `1:COLS:ROWS:` is correct and
the Go reimplementation's `1:{height}:{width}:` is **wrong**. Worth remembering as a general lesson:
of two secondary sources, the one closer to the implementation won. Neither deserved to be trusted
over a five-second measurement.

⚠️ **Parser lesson, paid for once already:** a terminal stream is not line-structured text. The
first version of the spike's parser looked for a line containing exactly two integers and found
nothing — because bash emits `\x1b[?2004l` (bracketed-paste-off) and a bare `\r` immediately before
command output, so the "line" was `\x1b[?2004l\r37 203` and the escape sequence parsed as the first
whitespace-separated token. Anything downstream that reads terminal output must strip escapes and
treat `\r` as a cursor movement, not a separator. There is a frozen regression test for this in
`spike-term`.

---

## D6. Known limits of the mirror — write these in the README, not the bug tracker

| Limit | Cause | Mitigation |
|-------|-------|------------|
| **No early boot** — GRUB, initramfs, pre-network | the agent starts late in boot; so does `pveproxy` | tier 3 (physical screen) or IPMI. Accept it. |
| **No graphical framebuffer** | `vcsa` is text-mode only; a program painting `/dev/fb0` leaves it stale | rare on a stock Proxmox host. Detect and show "console is in graphics mode" rather than a frozen screen. |
| **No scrollback buffer of its own** | `vcsa` exposes the visible screen only | but Shift+PgUp *is* injectable, and scrolling changes the visible screen — so scrollback works, by driving the VT. Nice accident. |
| **Follows VT switches** | user may switch to tty2 | watch `/sys/class/tty/tty0/active`, re-read, tell the panel |
| **Dead when the network is** | inherent | D0 says this out loud |
| **A VT can silently refuse injected input** | see D13 | detect it, and never strand the user on one |

## D15. Two panes, and the focused one is the only one that can be typed into

The panel used to mirror one machine chosen from a dropdown. That is fine when you are working on
one thing and useless when you are watching a host and a VM at the same time — which is the actual
reason both are configured.

**Chips, not a dropdown.** A dropdown implies exactly one answer. Chips are toggles: click to show,
click again to put away, two at a time. Asking for a third replaces the pane you are *not* focused
on, because the focused one is presumably the one you meant to keep. The mirror refuses to become
empty — closing the last pane would leave the tab showing nothing with no obvious way back.

**Two is the ceiling, and it is an ergonomic limit, not a technical one.** Nothing under the UI
counts panes: sessions are a map keyed by target, and a third would work. Three consoles in a
hotkey-summoned overlay is a search, not a glance.

**Focus stops being a consequence and becomes a choice — so it has to be visible.** With one pane,
"which machine am I typing into" was answered by window focus (THREAT-MODEL R4/R8). With two, the
answer is a decision the user makes, and getting it wrong means typing a command meant for a VM
into a hypervisor's root console. Three things make that hard to do by accident:

1. The focused pane is outlined in the same green as the input-live badge; the other is dimmed.
2. Only the focused pane can receive a keystroke — the others are inert, not merely unfocused.
3. **Changing focus releases held keys on every machine**, before a single key reaches the new one.
   Releasing all of them rather than just the pane being left costs one message to an agent that is
   holding nothing, and rules out carrying a modifier across.

**Every event is tagged with its target.** Not doing this is the bug that would have been found
late and looked like corruption: two live sessions, one canvas, frames from the wrong machine.

**The clipboard became a fan-out** rather than a second mechanism. Text from machine A is set
locally and forwarded to every *other* connected machine, A excluded explicitly. Each remote's own
echo guard (D14) stops the value coming back, so the mesh terminates for the same reason the
two-machine case did.

---

## D16. The Windows agent is a GUI binary that can still talk

`win-agent` was a console-subsystem executable started by a logon task, which means Windows opened a
black console window at every logon — one you cannot close without stopping the agent. Building it
for the GUI subsystem fixes that and costs two things, both bought back in `console.rs`:

- **Run from a terminal, print to that terminal.** `--pairing` prints a fingerprint and a token you
  are meant to copy, and a GUI process starts with no console attached, so those lines would go
  nowhere. `AttachConsole(ATTACH_PARENT_PROCESS)` joins the console of whoever launched us and
  `CONOUT$` gives us a handle to it.
- **Run by the scheduler, print to a file.** Otherwise the trade is "no console window" for "no
  diagnostics at all", and an agent that fails at logon fails in silence. Redirecting the standard
  error *handle* means every existing `eprintln!` follows with no call sites changed and no logging
  framework. Rotates once at 1 MiB.

**The subtle part is not overriding a redirection that already exists.** `win-agent --pairing >
token.txt` hands us a perfectly good handle; replacing it with the console or the log file would
silently discard exactly what was asked for. So each stream is only redirected when its current
handle is null — which is the case that needed fixing and the only one.

Verified both ways: with explicitly redirected handles the pairing lines land in the file, and
started with no console at all (via WMI, as the scheduler does it) the startup diagnostics land in
`agent.log` with no window appearing.

---

## D17. The panel's chrome had an ID selector eating its own tabs

Worth writing down because the bug was invisible in code review and obvious in a measurement.

`#bar button { width: 26px }` was written for the two icon buttons in the title bar. It also matched
the three **tab** buttons nested inside `<nav id="tabs">`, and an ID selector outranks `.tab` no
matter which rule comes later — so every tab was pinned to 26px while its label needed 36–56px, and
the text spilled over its neighbours. On screen: *"shellmirrœettings"*.

Scoped to `#bar > button`, which the tabs are not.

The general lesson, applied across the bar and the pane headers: **decide explicitly which flex item
is allowed to give way.** Everything fixed gets `flex: 0 0 auto`; the one thing that may shrink gets
`min-width: 0` plus an ellipsis — without `min-width: 0` a flex item refuses to shrink below its
content and the squeeze lands on its neighbours instead. Text that must not be lost when truncated
lives in the element's `title`, which is how a pane can report *"this console is in K_OFF — keyboard
input is disabled for this console"* without growing a second row and stealing height from the
console it is describing.

**How it was found and fixed without the app.** `harness.html` is generated from `index.html` with a
stubbed `window.__TAURI__` in front of the real `app.js`, so the panel's UI can be driven in a
browser. The check that matters is not a screenshot but a measurement: any element whose
`scrollWidth` exceeds its `clientWidth` while its overflow is `visible` is painting over something.

---

## D18. Pairing by approving it on the machine, not by transcribing secrets

**Prompted by the user, after trying to set up a second Windows PC:** *"there's got to be a more
streamlined way… it should be as simple as opening hublot, getting a pair code, entering it on the
master machine."* They were right, and the honest reading is harsher: the old flow was four
command-line steps, an administrator terminal, and two hex strings copied by hand between machines.
Every one of those steps existed because it was easy to *implement*, not because it was reasonable
to *do*.

The flow now: open hublot on the machine to be controlled → **share this PC** → it shows its
address. On the panel, type that address. A dialog appears on the shared machine showing six
digits; the panel shows the same six. Click Allow. Nothing is transcribed at all.

**How this stays safe without an out-of-band fingerprint.** The old model pinned the agent's
certificate, which the user carried across by hand — that hand-carry *was* the security. Remove it
and first contact has nothing to verify against, so something else has to do that work: the six
digits are a hash of **both** certificates (`pinning::sas`). Anyone sitting in the middle must
terminate two TLS connections and therefore present a different certificate to each end, so the two
ends compute different numbers and the person comparing them sees it. Landing on the same six
digits by chance is one in a million, with one attempt, and a mismatch is visible rather than
silent.

Deliberate details:

- **Order is fixed, server then client.** Hash them the other way round on one side and every
  honest pairing looks like an attack.
- **The digits are sent before the agent blocks on its dialog**, so the panel can display them while
  the user is still standing at the other machine, rather than after they have decided.
- **The dialog defaults to No** and is system-modal: the agent has no window of its own, so without
  that it can open behind whatever is on screen and the panel simply appears to hang.
- **The fingerprint is written down the moment approval succeeds.** From then on it is ordinary
  pinning (`PinnedCert`) and this path is never taken again for that machine. Losing that write
  would silently drop a paired machine back to asking for approval.
- **`TrustOnFirstUse` lives in `crates/pinning`**, beside `PinnedCert`, so the one place where
  pinning is deliberately deferred is visible to anyone reading how pinning works — rather than
  improvised at a call site.

**Approval is not gated on the pairing window, and that was a correction.** It was, at first, by
analogy with tokens — and the analogy is wrong. A pairing window exists because a *token* is a
secret that can leak, so it has to stop working. Approval has no secret to leak; the control is a
person at the machine, and they can exercise it whenever they like. Gating it produced a dead end
found in use: a panel that had lost its record of a machine could only ask to pair, the agent could
only answer *"pairing is closed"*, and no amount of restarting either end could recover it without
editing files by hand. What removing the gate costs is that anyone who can reach the port can make
a dialog appear — which the person reading it denies, and which the firewall rule already limits to
the panel's address.

**Nothing may overwrite a known certificate with a blank one.** The same incident had a second
cause: the webview edits a *copy* of the config, pairing writes the certificate in the background,
and any form opened beforehand — the settings tab most obviously — still holds an empty fingerprint
field and saves it straight back over the real one. The panel then silently forgets a machine it is
paired with. `save_config` now keeps the existing fingerprint whenever the incoming one is empty.

**The console agent keeps tokens**, and says so: a text VT has no desktop and nobody sitting at it,
so `Auth::Approve` is refused with *"this agent has no screen to ask on — pair it with the token it
printed"*. That is why approving is a trait (`Approver`) rather than an assumption in the handshake.

Verified 2026-07-25 against a live agent: both ends independently reported **840923**, the same
value recomputed by hand from the two certificate files, and substituting a different server
certificate gives **333573** — the mismatch the whole design depends on.

---

## D13. Some VTs swallow injected input — and that looks exactly like a broken agent

Found the hard way on 2026-07-25, after four rounds of debugging what turned out to be working code.

**Reproduction** (VM, Ubuntu 24.04): on **tty1**, injection works completely — letters echo,
`Ctrl+Alt+F2` switches VT. Switch to **tty2** and *nothing* injected has any effect: no letters, no
Enter, no `Ctrl+Alt+F1` to get back, and no change to the shared CapsLock LED state. Both VTs run
identical `agetty` processes. Meanwhile every layer we control reports success — the agent logs
`10 received / 10 injected`, `write()` returns fine, and the device is registered with `EV=3`,
keycodes 1–127, bound to the `kbd` handler.

**Confirmed 2026-07-25:** `kbd_mode -C /dev/tty2` reports *"The keyboard is in some unknown mode"* —
what it prints when `KDGKBMODE` returns a value outside the four modes it names. In practice that
means **`K_OFF`**, which older `kbd_mode` builds don't recognise: keyboard input for that VT is
disabled at the kernel level. It explains every symptom simultaneously — no echo, no Enter, no
VT-switch chords, no CapsLock LED — while our `write()` calls legitimately succeed, because the
events reach the input core and are then dropped for that console.

`K_OFF` is typically set by a session manager taking ownership of a VT (systemd-logind does this),
so it is a property of the machine's state, not of the agent. Restore with
`kbd_mode -u -C /dev/tty2`; escape a stranded VT with `chvt 1`.

**✅ Both consequences below were fixed and verified the same day (2026-07-25).** The agent now reads
`KDGKBMODE` and reports honestly — on tty2 the badge reads *"input DISABLED (this console is in
K_OFF — keyboard input is disabled for this console)"*, which also confirmed the hypothesis
programmatically. VT switching moved to `VT_ACTIVATE`, and escaping a `K_OFF` console back to a
working one was demonstrated from the stranded state itself, with typing working immediately after.

**Two consequences for the product, both real:**

1. **The VT buttons can strand you.** Switching to a VT that ignores input leaves no way back —
   the chord that would return you is itself ignored. Before shipping VT switching, the panel must
   either verify the destination accepts input, or keep an escape hatch that does not depend on
   injection.
2. **"Injected" must not be reported as "delivered."** The agent can honestly say it wrote the
   event; it cannot say the kernel acted on it. The `input live` badge currently means the former
   and reads like the latter. A round-trip check — inject, then watch for *any* console change or
   cursor movement — would let the panel say `input not reaching this VT` instead of looking broken.

**The debugging lesson, which cost more than the bug:** every layer I could instrument said
"success", so I kept re-reading code that was correct. What finally settled it was running a
*known-good binary from an earlier phase* against the same environment — spike-console still printed
`azqw,` on tty1, proving the environment and the technique were both fine and the difference lay
somewhere I had not varied. Keep the old spikes runnable; they are the control group.

---

## D14. Clipboard sync is automatic and bidirectional — with the risk stated plainly

**Your call, 2026-07-25:** *"whatever causes the least friction — personal use, not publishing it."*
So: no hotkey, no confirmation, no per-direction toggle. Copy on one machine, paste on the other.

The alternative was a **manual push** — a hotkey that sends the clipboard once, which is the
hardened option THREAT-MODEL §6 recommends and which never lets a secret cross a machine boundary
without an explicit act. It was rejected on friction, knowingly. §6's judgement has not changed;
what changed is that this is a two-machine personal setup where both ends are already yours, and
the link is already pinned and mutually authenticated.

Three things from §6 were kept anyway, because each costs one call:

- **"Clipboard Viewer Ignore" is honoured.** Password managers set it. It is a courtesy marker only
  well-behaved applications obey — it is not a control, and a copied password from an application
  that doesn't set it *will* cross.
- **Text only.** No `CF_HDROP`, no `CF_HTML` — the two formats §6 wants sanitised are simply not
  carried, which is cheaper and safer than sanitising them.
- **256 KB cap**, checked on receive as well as send.

**Implementation notes that are not obvious:**

- Change detection is `GetClipboardSequenceNumber`, a single call needing no window and no message
  loop. Reading the text on a timer instead would contend with every other application for the
  clipboard twice a second.
- **The echo guard is what makes it terminate.** Each side stores the last value it applied from the
  other and refuses to send that value back, and it must be *recorded before* the clipboard is set,
  because the watcher can wake between those two statements.
- The console leg ignores clipboard messages: a text VT has no clipboard. The panel sends the same
  message to whichever agent is active and does not branch on its kind.

---

## D7. Fail-safe on key release — safety-critical

A dropped `KeyUp`, a crashed agent, or a yanked network mid-keypress leaves a **modifier stuck on a
root console**. Ctrl held down at a root shell is genuinely dangerous.

Layers:
1. Key events go on a **reliable** stream (never a datagram).
2. Panel loses window focus, or the connection drops → `ReleaseAll`.
3. Agent-side watchdog: no keepalive within N ms → release everything itself.
4. ✅ **A free fourth layer, confirmed 2026-07-24** (`spike-console release-test`). Held `LEFTSHIFT`
   on one virtual device, closed that device's fd without releasing — the same kernel path a process
   death takes — then tapped a letter from a second device. It came out **lowercase**. The kernel
   releases held keys when an input device is unregistered, so **an agent crash self-heals a stuck
   modifier on the root console**. This is the strongest guarantee in the system and it costs us
   nothing.

   Consequence for v1: layer 3's watchdog stays belt-and-braces rather than load-bearing. Do not
   delete it — it still covers the *network* dropping while the agent lives on, which the kernel
   knows nothing about — but the catastrophic case (agent dies with Ctrl held at a root prompt) is
   handled below us.

---

## D8. Scope — what is deliberately NOT in v1

- **Mouse, edge-flip, cursor pinning** — nothing on the Linux side has a cursor.
- **File transfer / drag-drop** — no console use case. Deferred with the second-Windows-box work.
- **Clipboard sync as a background service** — but **explicit** clipboard *is* in scope, both ways:
  paste Windows clipboard into the console, and select/copy console text out. The latter is D0's
  strongest single feature and should not be deferred to "polish".
- **Second Windows box as a full sink** — deferred, not cancelled. Nothing here forecloses it.

---

## D12. Mutual TLS instead of PAKE — the plan was wrong about this

The original plan called for SPAKE2 pairing. Building the approval flow made it clear that would
have been cargo-cult cryptography.

**PAKE exists to protect a low-entropy secret** — a six-digit PIN a human types — from an offline
dictionary attack. Our pairing secret is **32 bytes of `/dev/urandom` that you copy and paste**.
There is nothing to brute-force. PAKE would have added a delicate, easy-to-misuse protocol and
bought precisely nothing.

**What actually strengthens this link is asymmetric identity**, which we lacked. So:

- The panel generates its **own certificate** on first run. Its fingerprint *is* its identity.
- Enrolment: present the token once, and the agent writes that fingerprint to an allowlist.
- Afterwards: the TLS handshake proves possession of the client key, and the agent checks the
  fingerprint. **`Auth::Certificate` carries no secret at all.**
- The panel **deletes the token** once spent. Leaving it in the credential store would preserve a
  weaker way in for no benefit.
- Enrolment is only open when the agent is started with `--pair`, or when nobody is enrolled yet.
  Otherwise a leaked token is a permanent way in rather than a one-time one.

TLS accepts any structurally valid client certificate and the *application* checks the allowlist.
That sounds lax and isn't: TLS's job is proving key possession, and putting the identity decision in
one readable place beats hiding it in a stateful verifier. Nothing is accepted before the check.

**Net result: strictly stronger than the plan, and less code.** Worth remembering that the plan's
recommendation survived three revisions before implementation exposed it as unnecessary.

## D10. The mirror is a cell grid, not a byte stream — so there is no terminal emulator

The tier-2 shell needs xterm.js because a pty emits a byte stream full of escape sequences that
something has to interpret. **The mirror needs nothing of the kind.** The kernel's console driver
has already done that work: `/dev/vcsu` hands over a finished 2D buffer of characters and `/dev/vcsa`
the matching attribute bytes. What arrives is the *result* of terminal emulation, not the input to it.

So the tier-1 path contains no VT parser at either end. The agent reads cells, the wire carries
cells, and the panel paints cells into a `<pre>` grouped into spans by attribute. Consequences worth
knowing:

- **Escape sequences cannot desynchronise the view.** The category of bug that cost us an afternoon
  in D5 structurally cannot occur here.
- **Colour is free and exact** — the attribute byte *is* the VGA palette index, so the 16 console
  colours map one-to-one instead of being inferred from ANSI codes.
- **The cursor is a coordinate**, not a state machine, because `vcsa`'s header carries it.
- **Cost:** no scrollback of our own. But Shift+PgUp is injectable and scrolling changes the visible
  screen, so scrollback works by driving the VT (D6).

The wire is diffed; consumers are not. The agent sends changed runs because the network deserves
that, and the client reassembles a whole screen before handing anything to the UI — a view that
applies patches is a view with a desync bug in its future. A run that would land outside the grid,
or a diff for the wrong VT, is treated as desynchronisation and drops the connection rather than
smearing one console's text over another's.

## D11. Agent authentication — pinned certificate plus a pre-shared token *(interim)*

The agent generates a self-signed certificate and a 32-byte token on first run; the panel pins the
certificate by SHA-256 and presents the token, compared without an early return. Address and pin
live in `config.json`; the **token goes to the credential store**, next to the Proxmox password.

Same verifier as the Proxmox link — pinning now lives in its own `pinning` crate, because writing
that code twice is how one copy quietly stops matching the other. It deliberately depends on rustls
and a hash and nothing else, so pinning an HTTPS connection doesn't drag QUIC in behind it.

**Honest about what this is not:** a bearer token is weaker than the PAKE + mutual-TLS pairing
Phase 5 calls for. It is sufficient *because tier 1 is read-only today* — this agent has no
injection path compiled into it at all. Phase 3 changes that calculus completely: the moment the
agent can type on a root console, bearer-token auth stops being adequate and the pairing work
becomes a prerequisite, not polish.

⚠️ **Deployment note:** generate the identity as the user the agent will run as. On the VM the test
identity was generated unprivileged so the token could be read for testing; on the real host that
would leave a hypervisor console token readable by a non-root account.

## D9. Name — **`hublot`** ✅

French for *porthole*: a small window in a hull, onto a place you are not. That is precisely the
thing. Chosen over `porthole`, `bezel`, `vcs`, `tty0`; a French name also stands out against
`lumen`/`blit`/`cram`/`sift`/`phantom`/`reelwall`/`loadout`/`rdm`, which are all English.

Folder renamed `software-kvm` → `hublot` (the old name was also just wrong — this is not a KVM).

⚠️ **Known collision, accepted:** Hublot is a large Swiss watch brand. No legal issue for a dev tool
in a wholly different class of goods, but the name is SEO-dominated — `hublot github` will never
surface this. Revisit only if it ever gets a product page under Nexalit.

---

## Host facts — confirmed 2026-07-24

Everything the mirror rests on, verified on 192.168.1.10 rather than assumed:

| Check | Result | Consequence |
|-------|--------|-------------|
| `/sys/class/tty/tty0/active` | `tty1` | host sits on a **text VT** — the mirror is viable |
| `ls -l /dev/vcsu1` | `crw-rw---- root tty` | unicode buffer present, group-readable → agent runs as a user in group **`tty`**, no root |
| `/etc/default/keyboard` | `XKBLAYOUT="fr"`, variant empty | pin Windows to `0000040c`; exact match (D2) |
| `/etc/pve/datacenter.cfg` | `keyboard: fr` | VM VNC leg maps consistently |

## Open questions

None blocking. Both remaining calls were made 2026-07-24: auth = **stored** (D1), name = **hublot** (D9).

Deliberately left for implementation time rather than planned to death here:
- **Panel UX detail** — exact hotkeys, window geometry/persistence, the live-console indicator's
  visual design. Cheaper to decide with a window in front of you than on paper.
- **Test harness** — a recorded-`vcsa`-stream replay fixture so the renderer and differ can be tested
  without a live host. Design it once spike 0b shows what the stream actually looks like.
