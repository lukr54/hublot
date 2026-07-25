# hublot

A porthole onto a machine you're not inside.

Mirrors the text console of a Proxmox host into a window on the main PC, and types back into it —
so one keyboard drives both machines and the second monitor stops being something you look at.

**It is not a KVM.** Nothing on the Linux side has a cursor, so there is no bezel to cross and no
mouse to share. It reads the console out of `/dev/vcsu` and injects keys through `/dev/uinput`,
which means the window is a *mirror of the physical screen*, not a separate shell that resembles it.

**It is not a rescue console either.** When the network is down or the kernel has panicked, the
agent is just as unreachable as SSH. That's what IPMI and PiKVM are for. This is an ergonomics tool,
and [DECISIONS.md](DECISIONS.md) D0 makes the honest case for building it anyway — including the
part where `ssh root@host` already does most of the job.

What it adds over an SSH window: you see what is *actually on* the console (boot messages, failed
units, emergency shells), and you can **select and copy console text** — which a physical TTY
cannot do at all.

## Layout

```
panel/                 the window itself — Tauri; the only piece with a UI
crates/protocol/       the wire format, and the browser-key → evdev map. Shared by every other crate
crates/pinning/        certificate pinning, both directions
crates/mirror/         client half of the agent link — reassembles diffs into whole screens
crates/agent-core/     agent identity, pairing, enrolment. Shared by both agents
crates/winclip/        the Windows clipboard, text only. Shared by the panel and the Windows agent
crates/pve/            Proxmox API client — ticket auth, termproxy, console websocket, pinned TLS
crates/host-agent/     the Linux agent — /dev/vcsu out, /dev/uinput in          (Linux-only)
crates/win-agent/      the Windows agent — Desktop Duplication out, SendInput in
crates/spike-term/     Phase 0a — proves the tier-2 console path against the real host
crates/spike-console/  Phase 0b — proves the mirror + injection                 (Linux-only)
crates/spike-screen/   Phase 6 — measures what a desktop actually costs to mirror
crates/spike-mirror/   the agent link with no GUI in the way. If this works and the panel doesn't,
                       the bug is in the panel
```

`spike-console` is deliberately `libc`-only because it is the seed of `host-agent`, whose dependency
tree is attack surface.

**The Linux crates are not in `Cargo.toml`.** They cannot compile on Windows, so the workspace here
describes the Windows half and [Cargo-linux.toml](Cargo-linux.toml) describes the other one. Build
it after touching anything shared — `protocol` above all, since adding a message variant is exactly
what makes `host-agent`'s match non-exhaustive without a word of warning on this side:

```bash
cp Cargo-linux.toml Cargo.toml && cargo build --release -p host-agent
```

## Documents

| | |
|---|---|
| [PLAN.md](PLAN.md) | measured topology, architecture, verified wire protocol, phases |
| [DECISIONS.md](DECISIONS.md) | why each choice, with evidence and rejected alternatives |
| [THREAT-MODEL.md](THREAT-MODEL.md) | assets, adversaries, and the things that make this dangerous |

## Checks

`cargo test`, `cargo clippy -- -D warnings` and `cargo deny` run in CI on both platforms — the two
workspaces are checked separately because they compile different code (see `Cargo-linux.toml`).

The protocol parser has fuzz targets in [fuzz/](fuzz), because it decodes attacker-reachable bytes
inside a process that can type at a root console:

```bash
cargo +nightly fuzz run client_msg -- -rss_limit_mb=512
```

## Installing

```bash
cargo tauri build
```

produces `target/release/bundle/nsis/hublot_<version>_x64-setup.exe`, a per-user installer needing
no administrator rights. **`win-agent.exe` is bundled inside it**, so installing the panel also
places the Windows desktop agent alongside it.

On a Windows machine you want to *mirror*, copy `win-agent.exe` there — full instructions in
[deploy/windows-agent-README.txt](deploy/windows-agent-README.txt), which ships beside it. The short
version:

```bash
win-agent.exe --pairing
```

prints its fingerprint and pairing token, and then, **from an administrator terminal**:

```bash
win-agent.exe --install --allow 192.168.1.20
```

registers a logon task and opens the firewall for that one address. `--uninstall` and `--status` do
the obvious; `--pair` re-opens enrolment on an agent that already has a client.

**The firewall rule is not optional and is the step people skip.** QUIC is UDP, Windows blocks
inbound UDP by default, and without the rule the agent listens perfectly while nothing ever reaches
it — indistinguishable from a broken agent. It is scoped to the panel's address rather than to a
network profile on purpose: Windows re-classifies networks as Private or Public by itself, and a
rule that depends on that classification stops working for reasons that have nothing to do with you.

**It is a logon task, not a service, and that is deliberate.** Services run in session 0, which has
no desktop — `DuplicateOutput` there has nothing to duplicate. Capture tools that appear to run as
services actually run a session-0 stub whose only job is to launch a helper into the logged-in
session; a logon task reaches the same place directly.

> Run `--install` from your own terminal. Task and registry changes made from a sandboxed shell can
> be virtualised away and silently fail to take effect.

## Installing the agent on a Linux host

From `deploy/`, beside a `host-agent` binary built for that machine:

```bash
sudo ./install.sh 192.168.1.20
```

The argument is the machine running the panel. That address is the **only** one allowed to reach the
agent (`IPAddressDeny=any` in the unit), and the agent listens on whichever local address routes to
it — not `0.0.0.0`, because a guest running on the same hypervisor must not be able to reach
something that can type at a root console.

It creates an unprivileged `hublot` user in groups `tty` and `input`, installs a udev rule so
`/dev/uinput` is writable without root, installs a hardened systemd unit, and prints the pairing
fingerprint and token to paste into the panel. `uninstall.sh` undoes it; `--purge` also removes the
identity, which un-pairs every panel.

## Two machines at once

Every configured machine is a chip in the mirror toolbar. Click one to put it on screen, click it
again to put it away; two can be up side by side. Keystrokes only ever reach the **focused** pane —
outlined in green, with the other dimmed — and moving focus releases everything held on every
machine first. Asking for a third pane replaces the one you are not typing into.

## Clipboard

Between Windows machines the clipboard follows you, both ways, automatically — copy on one, paste
on the other. Text only, 256 KB, and content marked *"Clipboard Viewer Ignore"* (what password
managers set) is skipped.

There is **no off switch**, which is a deliberate trade and not an oversight: read
[THREAT-MODEL.md](THREAT-MODEL.md) R10 before pointing this at a machine that isn't yours. The
console leg doesn't participate at all — a text VT has no clipboard.

## Running the Phase 0 spikes

Neither spike writes anything to disk, and neither touches the Proxmox host's configuration.

**0a — tier-2 console path** (from Windows; prompts for the password, never stores it):

```bash
cargo run -p spike-term
```

**0b — mirror, injection, and the key-release safety property** (on the Linux box, as root):

```bash
sudo /scratch/hublot-spike/target/release/spike-console demo 1
```

`demo` types five keycodes chosen because QWERTY and AZERTY disagree about every one of them, then
reads the screen back and cleans up after itself. `release-test` holds Shift on a virtual device,
kills that device, and checks whether the next keystroke comes out shifted. `mirror` streams the
console until you stop it.
