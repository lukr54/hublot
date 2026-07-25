# Software KVM — Threat Model & Security Analysis

This tool is a **sanctioned keylogger + remote-input-injector + file-dropper**, one leg of which types into a **hypervisor root console**. It deserves a serious threat model. Treat the network between nodes as **untrusted** — even a home LAN has IoT devices, other users, and is spoofable.

## 0. Assets (what an attacker wins)
- **Every keystroke** — including your Windows password and the **Proxmox root password**.
- **Input injection on any sink** — equivalent to arbitrary command execution (you can open a terminal and type anything). On the Proxmox host that is **root on the hypervisor → every VM**.
- **Clipboard contents** — frequently passwords, API keys, TOTP codes.
- **File read/write on sinks** — the file channel writes attacker-influenceable files to disk.

Because injection ≈ RCE, the security of the whole system reduces to: *only an authenticated, paired source may ever reach a sink, over an encrypted channel, and the sink agent must be minimally privileged.*

## 1. Adversaries & trust boundaries
- **LAN attacker** — another device/host on the network (compromised IoT, roommate, guest, a compromised VM on the Proxmox host itself).
- **Active MITM** — ARP/DNS spoofing on the LAN.
- **Malware on a sink** — reads what we inject / clipboard / staged files.
- **Physical access** — someone at the unlocked source PC.
- **Trust boundary:** network = untrusted. Endpoints = semi-trusted. The Proxmox host is the crown jewel and a compromised VM on it is *inside* the LAN.

---

## 2. Transport
| Risk | Mitigation |
|------|-----------|
| **Keystroke sniffing** (plaintext = every password on the wire) | TLS 1.3 / QUIC always. **No plaintext mode, no "encryption off" toggle.** |
| **MITM** (LAN has no CA; DNS/ARP spoofable) | **Mutual authentication with pinned identities** — both ends verify the other's pinned cert/pubkey (TOFU pin set at pairing). Reject unknown peers. Server-auth-only TLS is *not* enough. |
| **Downgrade / weak ciphers** | TLS 1.3 only, no fallback (rustls default). |
| **Replay** (re-inject a recorded "rm -rf" frame) | AEAD + sequence numbers within the session (QUIC/TLS handles it). App-layer: monotonic `seq` on input, drop stale/duplicate motion datagrams. |

## 3. Pairing / authentication — *the whole ballgame*
Injection = RCE, so authentication is the primary control, and it must be **mutual**:
- **Sink must authenticate the source** — else a LAN attacker injects commands into your Proxmox root console.
- **Source must authenticate the sink** — else you're tricked into streaming your keystrokes to a rogue "sink" (keylogger).

Controls:
- **PAKE pairing** (SPAKE2 / CPace) with a short code shown on one node, entered on the other → mutual auth + a session key resistant to offline dictionary and MITM. (Weaker-but-ok alternative: TOFU + a **Short Authentication String** the user compares on both screens, Signal/Bluetooth-style.)
- **No default credentials, ever.** Each install generates a unique keypair; pin peers on pairing.
- **Explicit, time-boxed pairing window** — only accept new pairings when the user opens pairing from the tray; one at a time; auto-close after ~30 s. Prevents opportunistic rogue pairing.

## 4. Injection risks (inherent to the function)
- **Injection ≈ code execution.** There is no way to make "accept arbitrary keystrokes" intrinsically safe; the defense is auth (§3) + least privilege (§5). Rate/anomaly limits don't help (real typing is fast).
- **Stuck-key / lost key-up** — a dropped `KeyUp` or a mid-press disconnect leaves a modifier stuck (Ctrl held, or an autorepeating key on the root console). **Deliver key up/down reliably; on any disconnect/focus-loss, sink auto-releases all keys** (`ReleaseAll` + local safety timer). Critical for the Proxmox console.
- **Focus mis-routing** — you think you're typing locally but focus flipped to the Proxmox root shell (or you paste a password into the wrong host). Safety *and* security issue. Mitigations: unmistakable **active-node indicator** (tray color + optional on-screen badge), **deliberate flip** (dwell-at-edge or hotkey, no twitchy auto-cross), and never silently auto-flip into the Proxmox host — a stray command there is catastrophic.

## 5. The Proxmox agent — highest-value target
- **Privilege.** Writing `/dev/uinput` does **not** require root. Do **not** run as root. Run as a **dedicated unprivileged user** in a group granted only `/dev/uinput` via udev:
  ```
  KERNEL=="uinput", GROUP="kvm-input", MODE="0660"
  ```
  Then harden the systemd unit — it should need almost nothing but a socket and that device:
  ```
  NoNewPrivileges=yes
  ProtectSystem=strict
  ProtectHome=yes
  PrivateTmp=yes
  CapabilityBoundingSet=            # empty
  RestrictAddressFamilies=AF_INET AF_INET6
  SystemCallFilter=@system-service
  MemoryDenyWriteExecute=yes
  DeviceAllow=/dev/uinput rw
  ```
- **Network parser = the attack surface.** The agent parses attacker-reachable bytes; a bug = code execution as the agent user *on the hypervisor*. Rust kills memory-safety bugs but not logic bugs or `unsafe`/FFI bugs. Minimize `unsafe`, **fuzz the protocol parser**, keep the dependency tree small, `cargo audit`/`cargo deny`.
- **Listening exposure.** Bind to the specific management interface, not `0.0.0.0`; firewall the port to the source PC's IP; **block it from the VM networks** — a compromised VM on this very host is a LAN-local attacker with a direct line to the agent.
- **Inherent risk.** The agent types into the active VT = a root shell. Whoever can drive it has root-console execution. Auth (§3) + firewall + least privilege + audit logging are the whole defense.

## 6. Clipboard
- **Clipboard = secret-exfil channel.** Password managers, API keys, TOTP codes pass through it. Auto-sync means those secrets traverse the network (encrypted — ok) **and land on the other machine's clipboard**, readable by any local app/malware there.
- Mitigations:
  - **Never sync to the Proxmox node** (keyboard-only — already the case).
  - **Honor sensitivity markers** — skip content flagged `ExcludeClipboardContentFromMonitorProcessing` or "Clipboard Viewer Ignore" (what password managers set). Often-overlooked and important.
  - **Size cap + format allowlist** (text/image/`CF_HDROP` only); sanitize `CF_HTML`/`CF_HDROP` payloads on receive.
  - **Toggleable auto-sync**, and consider a manual "push clipboard" hotkey as a hardened option.
  - Avoid a feedback loop (ignore updates you just set).

## 7. File transfer — remote arbitrary write
- **Path traversal.** Filenames with `..\`, absolute paths, alternate data streams (`file:evil`), Windows reserved names (`CON`,`PRN`,`NUL`,`AUX`,`COM1`…), trailing dots/spaces, or Unicode tricks could write outside the staging dir or overwrite system files. **Strip all path components, generate safe names, write only into a controlled quarantine dir, validate against reserved names/long-path.**
- **No auto-execute / safe drop location.** Never drop into startup/auto-run locations. Stage in a **quarantine temp dir with tight ACLs**; expose files only as drop paths on an explicit user drop. Don't auto-open.
- **Disk-fill / zip-bomb DoS.** Enforce per-transfer and aggregate size quotas + a free-space check before writing.
- **Staging-dir TOCTOU / junction attacks.** Create the staging dir securely (per-user, not world-writable, in a location a non-admin local process can't pre-create as a junction/symlink). Tight ACLs so local malware can't read staged (possibly sensitive) files.
- **Integrity.** Per-file hash (already in the protocol) to catch corruption/bugs; TLS covers tampering in transit.
- Optional: AV-scan staged files (Defender `MpCmdRun`/AMSI) before exposing them.

## 8. Local privilege & installation (Windows)
- **Run in the user session, not SYSTEM.** LL hooks + `SendInput` must run in the interactive desktop/session; a SYSTEM service is both wrong and a bigger target. Autostart via Task Scheduler at logon.
- **UAC / secure desktop / UIPI.** Hooks and `SendInput` from a medium-integrity process **cannot** drive elevated windows, the UAC prompt, or the Ctrl+Alt+Del secure desktop. That's a *feature* — don't run elevated with `uiAccess` just to punch through it; that would let the KVM (and anything that compromises it) drive credential prompts. **v1 explicitly does not drive elevated/secure-desktop UI; document it.**
- **Keys at rest.** Protect each node's private key + pinned peer keys: Windows **DPAPI** (`CryptProtectData`) + tight ACLs; Linux owner-only perms (later: TPM-sealed). Never world-readable.
- **Supply chain.** A malicious dependency = a keylogger with network access — literally worst case here. Small dep tree, pinned versions, `cargo audit`/`cargo deny`, review every crate that touches input, crypto, or the network, and all `unsafe`.

## 9. Availability / DoS
- **Handshake flood** → rate-limit and fast-drop unpaired connections; firewall.
- **Malformed/oversized frames** → bound every length, validate before allocating, backpressure the bulk channel; fuzz the parser (§5).

## 10. Logging & privacy — the ironic footgun
- **Never log input payloads.** A stray `println!("{event:?}")` in a debug build writes your passwords to disk in plaintext. Structurally forbid input/clipboard/file *content* from logs (a `Debug` impl that redacts, or newtypes that don't print their contents).
- **Do** audit metadata: pairings, new-peer connections, file-transfer events (names/sizes, not content) — reviewable by the user.

## 11. Physical / session
- **Unlocked source = full access** to the Proxmox root console (same as any physical keyboard — inherent). On **session lock**, disengage hooks and refuse to flip to any sink (`WTSRegisterSessionNotification`). Don't let the lock screen drive a sink.
- **Sleep/disconnect** → `ReleaseAll`, drop the session cleanly, park the cursor locally.

---

## Cross-cutting principles
1. **Encryption + mutual auth are non-optional** — no off switch.
2. **Least privilege everywhere**, especially the Proxmox agent (unprivileged user, systemd sandbox, firewalled).
3. **Fail safe** — on any error/disconnect: release all keys, park the cursor locally, never leave a sink "driven."
4. **Minimize trusted surface** — tiny dep tree, minimal `unsafe`, fuzz the network parser.
5. **Secrets never touch logs.**

## v1 security checklist (must-do, not later)
- [ ] TLS 1.3 / QUIC, no plaintext path.
- [ ] Mutual auth with pinned identities; PAKE pairing; explicit time-boxed pairing window; no default creds.
- [ ] Reliable key up/down + `ReleaseAll` on disconnect/lock/focus-loss.
- [ ] Clear active-node indicator; deliberate (non-twitchy) flip; no silent auto-flip to Proxmox.
- [ ] Proxmox agent: unprivileged user + udev rule + hardened systemd unit + firewalled to the source IP, blocked from VM nets.
- [ ] Clipboard: honor sensitivity markers, size cap, format allowlist, no sync to Proxmox.
- [ ] File drop: path sanitization, quarantine dir with tight ACLs, size quotas, no auto-execute.
- [ ] Windows app runs in user session (not SYSTEM); does not drive elevated/secure-desktop UI; keys sealed with DPAPI.
- [ ] Input/clipboard/file **content never logged**; parser fuzzed; `cargo audit`/`cargo deny` in CI.

---

# Revision 2026-07-24 — deltas from the corrected topology

See PLAN.md §1–§2. The design gained a **screen-out** leg (mirroring the host's text VT) and a
**PVE API client**. Everything above still holds; these are additions.

## R1. New asset: the console *contents* (this is the big one)
Previously the agent only *accepted* keystrokes. It now also **reads `/dev/vcsa*` — everything
displayed on the hypervisor's root console** — and ships it over the network. That is a new,
permanent exfiltration channel for whatever scrolls past on tty1: command output, `pvesh` dumps,
key material printed by a careless one-liner, error messages naming internal hosts.

- Reading `vcsa`/`vcsu` needs group **`tty`**; writing `uinput` needs group **`input`** (both are
  `root:tty` / `root:root 0600` today, so a udev rule is required for the latter regardless). The
  agent user gets **exactly those two groups and no more** — still no root. Extend §5's unit with
  `DeviceAllow=/dev/vcsa1 r` (and the specific VTs you mirror) rather than a blanket allow.
- **Mirror only the VTs you actually watch.** Don't stream all six because it's easy.
- The screen stream must be as authenticated and encrypted as the key stream — same QUIC connection,
  no "it's only a screen, ship it over HTTP" shortcut.
- **Content never logged**, same rule as keystrokes. A crash dump containing a VT buffer is a leak.

## R2. New secret at rest: PVE credentials on Windows
Tier 2 (termproxy) authenticates to Proxmox from the main PC. If PVE API tokens turn out to work for
console endpoints, use a **scoped token** with the narrowest privileges that open a console. If they
do not (verify — PLAN.md §5), the panel is storing **a password that can administer the hypervisor**.

- Seal it with **DPAPI, user-scoped**, never in a config file, never in the repo, never in a log.
- Prefer a dedicated PVE user over `root@pam` if console access can be delegated at all.
- **Pin the PVE CA certificate** (`CN=pve.example`, issued by the cluster CA). The Rust side does the TLS,
  so pinning is trivial — and it removes the "click through the self-signed warning" habit that
  makes a MITM invisible.
- The webview never receives the ticket, the password, or the CSRF token.

## R3. The panel is now a keylogger-shaped process
It already was, as the source. Worth restating with the PiP in the picture: a window that captures
keys globally *and* holds a live root console is a single process worth compromising. Keep the
capture path and the render path separated, and keep the panel out of the elevated/secure desktop.

## R4. Focus mis-routing gets worse, not better
§4's warning sharpens: with a PiP overlay, "which machine am I typing into" is now a **window focus
question**, and window focus is easy to lose track of. The mirrored console must carry an
unmistakable, always-visible frame/badge when it is live, and losing window focus must
`ReleaseAll` immediately.

## R5. Additions to the v1 checklist
- [ ] Agent user in `tty` + `input` only; per-device `DeviceAllow` for the exact VTs mirrored.
- [ ] Screen stream encrypted + authenticated on the same connection as input; VT contents never logged.
- [ ] PVE credential sealed with DPAPI; scoped token preferred over a password; PVE CA cert pinned.
- [ ] Webview never sees credentials, tickets, or CSRF tokens.
- [ ] Panel loses window focus → `ReleaseAll`; live-console badge always visible while mirroring.

---

# Revision 2026-07-25 — Phase 3 makes the agent able to type

Until now the agent was read-only *by construction* — no injection code was compiled into it. That
is no longer true, and it changes the risk profile more than any other single change in the project.

## R6. Authentication is no longer a shared secret
A bearer token was acceptable for a screen stream. It is not acceptable for something that can type
at a root prompt, so the auth upgrade shipped **with** injection rather than after it (D12):
- client certificate, proven by the TLS handshake, checked against an allowlist on the agent;
- the token authorises **enrolment only**, once, and only while pairing is open (`--pair`, or no
  clients enrolled yet);
- the panel deletes the token once spent, so no weaker path lingers.

**Still to do before this faces anything but a trusted LAN:** firewall the agent's port to the
panel's address, and keep it unreachable from VM networks — a compromised guest on the same host is
a LAN-local attacker with a direct line to a root console (§5 already said this; injection makes it
urgent rather than prudent).

## R7. Stuck keys are handled below us, not by us
The virtual keyboard is owned by the connection. Any end to that session — clean, crash, or network
loss — drops the device, and the kernel releases every held key (measured, spike 0b / D7). A stuck
`Ctrl` at a root prompt therefore cannot outlive the session that caused it. The panel additionally
sends `ReleaseAll` on blur, tab change and window hide.

## R8. Focus is now a safety control, not a convenience
With keys live, "which machine am I typing into" is decided by window focus. The mirror grid carries
a green focus ring precisely while keystrokes are leaving the machine, and blur releases everything.
This is the mitigation for §4's focus-misrouting risk in its sharpest form.

## R9. What injection does *not* protect against
Anyone who can drive the panel can type as root on the hypervisor. There is no confirmation step, no
command filtering, and there should not be — it is a keyboard. The defence is entirely in R6 plus
the machine the panel runs on. Treat the panel's client certificate as equivalent to an SSH key for
root on that host, because that is what it is.

---

# Revision 2026-07-25 — clipboard sync shipped, and what §6 asked for that it doesn't do

## R10. Automatic clipboard sync is a standing exfiltration channel, by choice
§6 said it: password managers, API keys and TOTP codes pass through the clipboard, and automatic
sync means they land on the *other* machine's clipboard where any local process can read them. That
is now the shipped behaviour, decided deliberately (DECISIONS.md **D14**) because both machines are
the same person's and the friction of a manual push was judged not worth paying.

Of §6's mitigations, what actually shipped:

| §6 asked for | Shipped |
|---|---|
| Never sync to the Proxmox node | **Yes** — the console leg drops clipboard messages; a text VT has no clipboard |
| Honour "Clipboard Viewer Ignore" | **Yes**, on read, on both ends |
| Size cap | **Yes**, 256 KB, checked on receive too |
| Format allowlist, sanitise `CF_HTML`/`CF_HDROP` | **Stronger** — text only, so those formats are never carried |
| Avoid a feedback loop | **Yes** — echo guard on both sides |
| Toggleable auto-sync / manual push | **No.** Not built. This is the gap. |

The residual risk in one sentence: **anything you copy on either Windows machine is on both of them
within half a second**, unless the application that put it there set the ignore marker. If a shared
or less-trusted machine is ever added, the toggle stops being optional.

The ignore marker deserves a second mention because it is easy to over-trust: it is a *courtesy*
that a well-behaved application sets. A password pasted out of a text file, a browser field, or any
manager that doesn't set it will cross the link.
