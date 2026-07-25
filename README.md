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
crates/pve/            Proxmox API client — ticket auth, termproxy, console websocket, pinned TLS
crates/spike-term/     Phase 0a — proves the tier-2 console path against the real host
crates/spike-console/  Phase 0b — proves the mirror + injection (Linux-only; built on the target)
```

`spike-console` is excluded from the workspace: it only compiles on Linux, and it is deliberately
`libc`-only because it is the seed of `host-agent`, whose dependency tree is attack surface.

## Documents

| | |
|---|---|
| [PLAN.md](PLAN.md) | measured topology, architecture, verified wire protocol, phases |
| [DECISIONS.md](DECISIONS.md) | why each choice, with evidence and rejected alternatives |
| [THREAT-MODEL.md](THREAT-MODEL.md) | assets, adversaries, and the things that make this dangerous |

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
