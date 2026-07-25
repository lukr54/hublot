#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! The Hublot panel — Phase 1.
//!
//! A borderless, always-on-top console window summoned by a global hotkey. This phase implements
//! **tier 2** (PLAN.md §3): a pty shell on the Proxmox node via `termproxy`. That is not yet a
//! mirror of the physical console — tier 1 arrives in Phases 2–3 — but it is the thing that stops
//! you opening a browser tab.
//!
//! Two rules hold this file's shape:
//!
//! * **Credentials never cross into the webview.** Login, the ticket, the CSRF token and the socket
//!   all live here. The frontend sends keystrokes and receives bytes; it cannot reach the network.
//! * **One writer.** termproxy panics on concurrent writes, so every outbound frame — input, resize
//!   and keepalive — funnels through a single `select!` loop.

use std::sync::Mutex;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::mpsc;

const KEYRING_SERVICE: &str = "hublot";

/// One machine whose console we can mirror. Any Linux box running the agent qualifies — the
/// Proxmox host, or a VM on it, which is why the "VM console tab" needed no new protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTarget {
    pub name: String,
    pub addr: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub node: String,
    pub user: String,
    /// SHA-256 of the node's TLS leaf certificate. See DECISIONS.md D1 for why we pin rather than
    /// verify names: the leaf's SANs list an address this host no longer has.
    pub fingerprint: String,
    pub hotkey: String,
    /// Tier 1: the host agent. Address and pin are not secrets and live here; the pairing token
    /// does not, and goes to the credential store alongside the Proxmox password.
    pub agent_addr: String,
    pub agent_fingerprint: String,
    /// Every mirrorable machine. Seeded from the single-agent fields above the first time an older
    /// config is loaded, so upgrading doesn't lose a pairing.
    #[serde(default)]
    pub agents: Vec<AgentTarget>,
    /// Kept only so older configs still parse and can seed `visible`; `visible` is the truth.
    #[serde(default)]
    pub active_agent: usize,
    /// Which targets are on screen right now, in order — one pane each, at most two. This is the
    /// single source of truth for what the mirror shows; having both this and an "active" index
    /// would be two facts that can disagree.
    #[serde(default)]
    pub visible: Vec<usize>,
}

/// Two panes fit; a third turns a glance into a search. The limit is ergonomic, not technical —
/// nothing below cares how many sessions are live.
const MAX_PANES: usize = 2;

impl Config {
    /// Fold a pre-multi-target config into the list, then a pre-split config into `visible`.
    fn migrate(&mut self) {
        if self.agents.is_empty() && !self.agent_addr.is_empty() {
            self.agents.push(AgentTarget {
                name: "host".into(),
                addr: std::mem::take(&mut self.agent_addr),
                fingerprint: std::mem::take(&mut self.agent_fingerprint),
            });
        }
        if self.active_agent >= self.agents.len() {
            self.active_agent = 0;
        }
        if self.visible.is_empty() && !self.agents.is_empty() {
            self.visible = vec![self.active_agent];
        }
        self.clamp_visible();
    }

    /// A saved layout must never outlive the targets it names, or the panel opens onto a pane that
    /// can never connect and gives no hint why.
    fn clamp_visible(&mut self) {
        let mut seen = std::collections::HashSet::new();
        self.visible.retain(|i| *i < self.agents.len() && seen.insert(*i));
        self.visible.truncate(MAX_PANES);
        if self.visible.is_empty() && !self.agents.is_empty() {
            self.visible = vec![0];
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: "192.168.1.10".into(),
            port: 8006,
            node: "pve".into(),
            user: "root@pam".into(),
            fingerprint:
                "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
                    .into(),
            hotkey: "Ctrl+Alt+H".into(),
            agent_addr: String::new(),
            agent_fingerprint: String::new(),
            agents: Vec::new(),
            active_agent: 0,
            visible: Vec::new(),
        }
    }
}

/// Outbound frames. Everything the panel sends to the node passes through here so that exactly one
/// task owns the websocket sink.
enum Out {
    Data(Vec<u8>),
    Resize { cols: u16, rows: u16 },
}

/// Sessions are per target index, because more than one can be live at a time — that is what the
/// split view *is*. Both maps are keyed the same way and mean different things: `generation` is
/// the authority on "is this task still current", and survives the gaps between reconnect attempts
/// when there is no sender to hold.
#[derive(Default)]
struct AppState {
    config: Mutex<Config>,
    tx: Mutex<Option<mpsc::UnboundedSender<Out>>>,
    /// Bumped whenever a target is (re)connected or closed; a task whose generation is stale exits
    /// quietly instead of two connections fighting over the same pane.
    mirror_generation: Mutex<std::collections::HashMap<usize, u64>>,
    /// Outbound events toward each connected agent.
    mirror_keys: Mutex<std::collections::HashMap<usize, tokio::sync::mpsc::Sender<protocol::ClientMsg>>>,
    /// Exactly which accelerator is live, so a rebind releases that one and no other.
    registered_hotkey: Mutex<Option<String>>,
    /// The last clipboard value we applied *from* a remote machine.
    clipboard_echo: Mutex<Option<String>>,
}

impl AppState {
    /// Send to one agent, dropping the message if that target isn't connected. A keystroke arriving
    /// a moment after a link dropped is not an error worth surfacing.
    fn send_to(&self, target: usize, msg: protocol::ClientMsg) {
        if let Some(tx) = self.mirror_keys.lock().unwrap().get(&target) {
            let _ = tx.try_send(msg);
        }
    }

    /// Send to every connected agent except one. Used by the clipboard, where `except` is whichever
    /// machine the text came from.
    fn broadcast(&self, except: Option<usize>, msg: protocol::ClientMsg) {
        for (i, tx) in self.mirror_keys.lock().unwrap().iter() {
            if Some(*i) != except {
                let _ = tx.try_send(msg.clone());
            }
        }
    }
}

#[derive(Serialize, Clone)]
struct Status {
    state: &'static str,
    detail: String,
}

/// Same, but tagged with the pane it belongs to. Every mirror event carries this now: with two
/// machines on screen, an untagged frame is a frame painted into the wrong pane.
#[derive(Serialize, Clone)]
struct MirrorStatus {
    target: usize,
    state: &'static str,
    detail: String,
}

fn set_status(app: &AppHandle, state: &'static str, detail: impl Into<String>) {
    // Global emit, not emit_to: a targeted emit races window creation and silently drops.
    let _ = app.emit("console:status", Status { state, detail: detail.into() });
}

// ── config ──────────────────────────────────────────────────────────────────────────────────────

fn config_path(app: &AppHandle) -> std::path::PathBuf {
    let dir = app.path().app_config_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let _ = std::fs::create_dir_all(&dir);
    dir.join("config.json")
}

fn load_config(app: &AppHandle) -> Config {
    let mut cfg: Config = std::fs::read_to_string(config_path(app))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    cfg.migrate();
    cfg
}

#[tauri::command]
fn get_config(state: State<'_, AppState>) -> Config {
    state.config.lock().unwrap().clone()
}

#[tauri::command]
fn save_config(app: AppHandle, state: State<'_, AppState>, config: Config) -> Result<(), String> {
    let json = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
    std::fs::write(config_path(&app), json).map_err(|e| e.to_string())?;
    *state.config.lock().unwrap() = config;
    Ok(())
}

// ── credential ──────────────────────────────────────────────────────────────────────────────────

fn keyring_entry(cfg: &Config) -> Result<keyring::Entry, String> {
    keyring::Entry::new(KEYRING_SERVICE, &format!("{}@{}", cfg.user, cfg.host))
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn has_credential(state: State<'_, AppState>) -> bool {
    let cfg = state.config.lock().unwrap().clone();
    keyring_entry(&cfg).map(|e| e.get_password().is_ok()).unwrap_or(false)
}

#[tauri::command]
fn set_credential(state: State<'_, AppState>, password: String) -> Result<(), String> {
    let cfg = state.config.lock().unwrap().clone();
    keyring_entry(&cfg)?.set_password(&password).map_err(|e| e.to_string())
}

#[tauri::command]
fn clear_credential(state: State<'_, AppState>) -> Result<(), String> {
    let cfg = state.config.lock().unwrap().clone();
    match keyring_entry(&cfg)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

// ── session ─────────────────────────────────────────────────────────────────────────────────────

#[tauri::command]
async fn connect(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    let cfg = state.config.lock().unwrap().clone();
    let password = keyring_entry(&cfg)?
        .get_password()
        .map_err(|_| "no stored credential".to_string())?;

    set_status(&app, "connecting", format!("{}@{}", cfg.user, cfg.host));

    let fingerprint = pve::parse_fingerprint(&cfg.fingerprint).map_err(|e| e.to_string())?;
    let client = pve::PveClient::new(&cfg.host, cfg.port, fingerprint).map_err(|e| e.to_string())?;
    let ticket = client.login(&cfg.user, &password).await.map_err(|e| e.to_string())?;
    let tp = client.termproxy(&ticket, &cfg.node).await.map_err(|e| e.to_string())?;
    let ws = client
        .open_console(&ticket, &cfg.node, &tp)
        .await
        .map_err(|e| e.to_string())?;

    let (tx, mut rx) = mpsc::unbounded_channel::<Out>();
    *state.tx.lock().unwrap() = Some(tx);

    set_status(&app, "connected", format!("{}@{} · node {}", cfg.user, cfg.host, cfg.node));

    tauri::async_runtime::spawn(async move {
        let (mut sink, mut stream) = ws.split();
        let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(30));
        keepalive.tick().await; // the first tick fires immediately; skip it

        let reason = loop {
            tokio::select! {
                incoming = stream.next() => match incoming {
                    // Server→client is raw terminal bytes with no framing. Ship them to the
                    // frontend as base64 rather than decoding to a String here: a UTF-8 sequence
                    // can straddle two websocket messages, and xterm's own decoder handles that
                    // correctly where a lossy per-chunk decode would corrupt it.
                    Some(Ok(msg)) => {
                        let bytes = msg.into_data();
                        if !bytes.is_empty() {
                            let _ = app.emit("console:data", B64.encode(&bytes));
                        }
                    }
                    Some(Err(e)) => break format!("connection error: {e}"),
                    None => break "connection closed by host".to_string(),
                },
                outgoing = rx.recv() => match outgoing {
                    Some(Out::Data(d)) => {
                        if sink.send(pve::Message::Binary(pve::frame::data(&d).into())).await.is_err() {
                            break "write failed".to_string();
                        }
                    }
                    Some(Out::Resize { cols, rows }) => {
                        if sink.send(pve::Message::Binary(pve::frame::resize(cols, rows).into())).await.is_err() {
                            break "write failed".to_string();
                        }
                    }
                    None => break "disconnected".to_string(),
                },
                _ = keepalive.tick() => {
                    if sink.send(pve::Message::Binary(pve::frame::ping().into())).await.is_err() {
                        break "keepalive failed".to_string();
                    }
                }
            }
        };

        if let Some(state) = app.try_state::<AppState>() {
            *state.tx.lock().unwrap() = None;
        }
        set_status(&app, "disconnected", reason);
    });

    Ok(())
}

#[tauri::command]
fn disconnect(state: State<'_, AppState>) {
    // Dropping the sender ends the select! loop, which emits the status change.
    *state.tx.lock().unwrap() = None;
}

#[tauri::command]
fn send_input(state: State<'_, AppState>, data: String) -> Result<(), String> {
    let tx = state.tx.lock().unwrap();
    let tx = tx.as_ref().ok_or("not connected")?;
    tx.send(Out::Data(data.into_bytes())).map_err(|_| "not connected".to_string())
}

#[tauri::command]
fn resize(state: State<'_, AppState>, cols: u16, rows: u16) -> Result<(), String> {
    let tx = state.tx.lock().unwrap();
    let Some(tx) = tx.as_ref() else { return Ok(()) }; // resizing while disconnected is harmless
    tx.send(Out::Resize { cols, rows }).map_err(|_| "not connected".to_string())
}

// ── mirror (tier 1) ─────────────────────────────────────────────────────────────────────────────

/// Tokens are keyed by address, so each target keeps its own pairing secret — and so a token can be
/// stored for a machine that isn't the one currently on screen.
fn agent_keyring(addr: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(KEYRING_SERVICE, &format!("agent@{addr}")).map_err(|e| e.to_string())
}

#[tauri::command]
fn has_agent_token(state: State<'_, AppState>, addr: String) -> bool {
    if addr.is_empty() {
        return false;
    }
    let _ = state;
    agent_keyring(&addr).map(|e| e.get_password().is_ok()).unwrap_or(false)
}

#[tauri::command]
fn set_agent_token(state: State<'_, AppState>, addr: String, token: String) -> Result<(), String> {
    let _ = state;
    agent_keyring(&addr)?.set_password(&token).map_err(|e| e.to_string())
}

/// Choose which targets are on screen — one index for a single pane, two for a split.
///
/// Saving and reconciling are one step on purpose: a layout that persists but doesn't take effect
/// (or the reverse) is the kind of split-brain that shows up as "it forgot my second pane".
#[tauri::command]
async fn set_visible(
    app: AppHandle,
    state: State<'_, AppState>,
    indices: Vec<usize>,
) -> Result<(), String> {
    {
        let mut cfg = state.config.lock().unwrap();
        cfg.visible = indices;
        cfg.clamp_visible();
        let json = serde_json::to_string_pretty(&*cfg).map_err(|e| e.to_string())?;
        std::fs::write(config_path(&app), json).map_err(|e| e.to_string())?;
    }
    mirror_sync(app.clone(), app.state::<AppState>()).await
}

/// What the webview needs to paint one console frame.
///
/// Rows go over as one string each rather than a single flat buffer: JavaScript strings are UTF-16,
/// so a flat buffer would need index arithmetic that breaks the moment a character sits outside the
/// BMP. Per-row strings let the frontend iterate code points and stay correct.
#[derive(Serialize, Clone)]
struct FramePayload {
    target: usize,
    vt: u8,
    cols: u16,
    rows: u16,
    cursor: (u16, u16),
    text: Vec<String>,
    /// One attribute byte per cell, row-major, base64'd.
    attrs: String,
}

impl FramePayload {
    fn of(target: usize, s: &protocol::Screen) -> Self {
        let w = s.cols as usize;
        Self {
            target,
            vt: s.vt,
            cols: s.cols,
            rows: s.rows,
            cursor: s.cursor,
            text: s.cells.chunks(w).map(|r| r.iter().map(|c| c.ch).collect()).collect(),
            attrs: B64.encode(s.cells.iter().map(|c| c.attr).collect::<Vec<_>>()),
        }
    }
}

/// Send a key event to one pane's agent. Silently ignored when not connected — a keystroke arriving
/// a moment after the link dropped is not an error worth surfacing.
#[tauri::command]
fn mirror_key(
    state: State<'_, AppState>,
    target: usize,
    code: String,
    down: bool,
) -> Result<(), String> {
    let Some(evdev) = protocol::keymap::evdev_for_code(&code) else {
        return Ok(()); // a key we deliberately don't relay
    };
    state.send_to(target, protocol::ClientMsg::Key { code: evdev, down });
    Ok(())
}

/// Let go of everything, on **every** connected machine.
///
/// Called on focus loss, tab change, window hide, and whenever focus moves from one pane to
/// another. Releasing all of them rather than just the pane you left is deliberate: the cost is one
/// message to an agent holding nothing, and the failure it prevents — a modifier stuck down on a
/// root console — is the one THREAT-MODEL R4 cares about most.
#[tauri::command]
fn mirror_release_all(state: State<'_, AppState>) {
    state.broadcast(None, protocol::ClientMsg::ReleaseAll);
}

// A Tauri command's arguments are its wire format — the webview names each one — so collapsing
// these into a struct would just move the same nine fields somewhere less obvious.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
fn mirror_mouse(
    state: State<'_, AppState>,
    target: usize,
    kind: String,
    x: u16,
    y: u16,
    button: u8,
    down: bool,
    dx: i16,
    dy: i16,
) -> Result<(), String> {
    let msg = match kind.as_str() {
        "move" => protocol::ClientMsg::MouseMove { x, y },
        "button" => protocol::ClientMsg::MouseButton { button, down },
        "scroll" => protocol::ClientMsg::MouseScroll { dx, dy },
        _ => return Ok(()),
    };
    // Motion is dropped rather than queued when the link is saturated: a stale pointer position is
    // worthless, and the next one is already on its way.
    state.send_to(target, msg);
    Ok(())
}

/// Switch console by ioctl rather than by injecting Ctrl+Alt+Fn.
///
/// A console with its keyboard disabled ignores the chord that would take you off it, so
/// injection-based switching can leave you somewhere you cannot leave (DECISIONS.md D13).
#[tauri::command]
fn mirror_switch_vt(state: State<'_, AppState>, target: usize, vt: u8) -> Result<(), String> {
    let keys = state.mirror_keys.lock().unwrap();
    let tx = keys.get(&target).ok_or("not connected")?;
    tx.try_send(protocol::ClientMsg::SwitchVt { vt }).map_err(|_| "not connected".to_string())
}

/// Make the live sessions match `config.visible`: connect what should be on screen, drop what
/// should not.
///
/// One reconciling entry point rather than connect/disconnect pairs at every call site. The panel
/// calls this on opening the mirror, on changing the layout, and on the reconnect button, and each
/// time the answer is the same: whatever is visible should be connected, and nothing else.
#[tauri::command]
async fn mirror_sync(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    let cfg = state.config.lock().unwrap().clone();

    let live: Vec<usize> = state.mirror_keys.lock().unwrap().keys().copied().collect();
    for i in live {
        if !cfg.visible.contains(&i) {
            disconnect_target(&app, i);
        }
    }

    let mut first_error = None;
    for &i in &cfg.visible {
        let already = state.mirror_generation.lock().unwrap().contains_key(&i);
        if already {
            continue;
        }
        if let Err(e) = connect_target(&app, &cfg, i) {
            let _ = app.emit(
                "mirror:status",
                MirrorStatus { target: i, state: "error", detail: e.clone() },
            );
            first_error.get_or_insert(e);
        }
    }
    match first_error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Tear down one pane's session. Bumping the generation is what actually stops it: the task checks
/// its own generation before every paint and returns quietly when it has been superseded.
fn disconnect_target(app: &AppHandle, index: usize) {
    let Some(state) = app.try_state::<AppState>() else { return };
    state.mirror_generation.lock().unwrap().remove(&index);
    let gone = state.mirror_keys.lock().unwrap().remove(&index);
    if let Some(tx) = gone {
        // Best effort: an agent that hears this releases held keys immediately rather than waiting
        // for the connection to time out.
        let _ = tx.try_send(protocol::ClientMsg::ReleaseAll);
    }
}

fn connect_target(app: &AppHandle, cfg: &Config, index: usize) -> Result<(), String> {
    let target = cfg.agents.get(index).ok_or("no such mirror target")?.clone();
    if target.addr.is_empty() {
        return Err("no agent address configured".into());
    }
    let addr: std::net::SocketAddr = target
        .addr
        .parse()
        .map_err(|_| format!("`{}` is not a host:port address", target.addr))?;
    let fingerprint =
        protocol::pin::parse_fingerprint(&target.fingerprint).map_err(|e| e.to_string())?;

    // Our own certificate lives beside the config. Its fingerprint is our identity to the agent,
    // so this file is what "already paired" actually means. One certificate serves every target:
    // it identifies this panel, not this connection.
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    let identity = mirror::ClientIdentity::load_or_create(&dir).map_err(|e| e.to_string())?;

    let state = app.state::<AppState>();
    let generation = {
        let mut g = state.mirror_generation.lock().unwrap();
        let next = g.get(&index).copied().unwrap_or(0) + 1;
        g.insert(index, next);
        next
    };
    let app = app.clone();
    let token_addr = target.addr.clone();

    tauri::async_runtime::spawn(async move {
        // Reconnect with backoff. A console you glance at occasionally is useless if a brief
        // network blip leaves it dead until you notice and click something.
        let mut backoff = 1u64;
        // Every emit is tagged with the pane it belongs to; without that, two live sessions paint
        // into each other's canvases.
        let status = |state: &'static str, detail: String| {
            let _ = app.emit("mirror:status", MirrorStatus { target: index, state, detail });
        };
        loop {
            let stale = app
                .try_state::<AppState>()
                .map(|s| s.mirror_generation.lock().unwrap().get(&index) != Some(&generation))
                .unwrap_or(true);
            if stale {
                return;
            }

            // A stored token means we have not enrolled yet; enrolment spends it and we fall back
            // to certificate auth from then on. Keyed by address, so pairing a second machine does
            // not disturb the first.
            let auth = agent_keyring(&token_addr)
                .ok()
                .and_then(|e| e.get_password().ok())
                .map_or(protocol::Auth::Certificate, |token| protocol::Auth::Enrol { token });

            status("connecting", addr.to_string());

            let (tx, mut rx) = tokio::sync::mpsc::channel(8);
            let (keys_tx, keys_rx) = tokio::sync::mpsc::channel(64);
            if let Some(s) = app.try_state::<AppState>() {
                s.mirror_keys.lock().unwrap().insert(index, keys_tx);
            }

            {
                let (app, identity) = (app.clone(), identity.clone());
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = mirror::stream(addr, fingerprint, identity, auth, tx, keys_rx).await {
                        let _ = app.emit(
                            "mirror:status",
                            MirrorStatus { target: index, state: "error", detail: format!("{e:#}") },
                        );
                    }
                });
            }

            let mut fatal = false;
            while let Some(ev) = rx.recv().await {
                // A newer connect superseded us: stop painting rather than two streams interleaving
                // frames into one view.
                let current = app
                    .try_state::<AppState>()
                    .and_then(|s| s.mirror_generation.lock().unwrap().get(&index).copied());
                if current != Some(generation) {
                    return;
                }
                if matches!(ev, mirror::Event::Connected) {
                    backoff = 1; // a successful connection earns a fresh budget
                }
                if let mirror::Event::Closed(why) = &ev {
                    // Pairing problems will not fix themselves by waiting.
                    fatal = why.contains("not enrolled") || why.contains("pairing") || why.contains("token");
                }
                match ev {
                mirror::Event::Connected => status("connected", addr.to_string()),
                mirror::Event::Enrolled => {
                    // The token has done its one job. Delete it rather than leave a second, weaker
                    // way in sitting in the credential store.
                    if let Ok(entry) = agent_keyring(&token_addr) {
                        let _ = entry.delete_credential();
                    }
                    status("connected", "paired".into());
                }
                mirror::Event::Input { enabled, reason } => {
                    let _ = app.emit("mirror:input", MirrorStatus {
                        target: index,
                        state: if enabled { "enabled" } else { "disabled" },
                        detail: reason,
                    });
                }
                mirror::Event::Screen(s) => {
                    let _ = app.emit("mirror:frame", FramePayload::of(index, &s));
                }
                mirror::Event::ScreenInfo { w, h } => {
                    let _ = app.emit(
                        "mirror:screeninfo",
                        serde_json::json!({ "target": index, "w": w, "h": h }),
                    );
                }
                mirror::Event::Clipboard(text) => {
                    // Record before setting, because our own watcher may wake the instant we do —
                    // without this the two clipboards pass a value back and forth forever.
                    if let Some(s) = app.try_state::<AppState>() {
                        *s.clipboard_echo.lock().unwrap() = Some(text.clone());
                        // With two machines mirrored, text copied on one should reach the other as
                        // well as this PC. Sending it on from here rather than letting the watcher
                        // do it is what makes that a fan-out instead of a loop: the origin is
                        // excluded explicitly, and every *other* agent's own echo guard stops the
                        // value bouncing back from there.
                        s.broadcast(Some(index), protocol::ClientMsg::Clipboard { text: text.clone() });
                    }
                    winclip::set_text(&text);
                }
                mirror::Event::Pointer { x, y, visible } => {
                    let _ = app.emit(
                        "mirror:pointer",
                        serde_json::json!({ "target": index, "x": x, "y": y, "visible": visible }),
                    );
                }
                mirror::Event::PointerShape { w, h, hot_x, hot_y, png } => {
                    let _ = app.emit(
                        "mirror:pointershape",
                        serde_json::json!({
                            "target": index, "w": w, "h": h, "hotX": hot_x, "hotY": hot_y,
                            "url": format!("data:image/png;base64,{}", B64.encode(&png)),
                        }),
                    );
                }
                mirror::Event::Raster { x, y, w, h, mime, data } => {
                    // A data: URL is the cheapest path to the canvas — the webview's own image
                    // decoders do the work, and we never hand the frontend anything but pixels.
                    let _ = app.emit(
                        "mirror:raster",
                        serde_json::json!({
                            "target": index, "x": x, "y": y, "w": w, "h": h,
                            "url": format!("data:{mime};base64,{}", B64.encode(&data)),
                        }),
                    );
                }
                mirror::Event::Closed(why) => {
                    status("disconnected", why);
                    break;
                }
                }
            }

            // Only clear our own slot, and only if a newer session hasn't already claimed it.
            if let Some(s) = app.try_state::<AppState>() {
                let ours = s.mirror_generation.lock().unwrap().get(&index) == Some(&generation);
                if ours {
                    s.mirror_keys.lock().unwrap().remove(&index);
                } else {
                    return;
                }
            }
            if fatal {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
            backoff = (backoff * 2).min(15);
        }
    });
    Ok(())
}

// ── window ──────────────────────────────────────────────────────────────────────────────────────

#[tauri::command]
fn hide_panel(app: AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.hide();
    }
}

/// Bind the summon hotkey, replacing whatever is currently live.
///
/// Order matters and is deliberate: **register the new accelerator before releasing the old one.**
/// If the new one is malformed or already taken by another app, the failure leaves you with a
/// working hotkey instead of a panel you can no longer summon.
///
/// Called from a command, never from inside a shortcut callback — doing the latter deadlocks the
/// plugin (learned in loadout's HUD work).
fn bind_hotkey(app: &AppHandle, accelerator: &str) -> Result<(), String> {
    use tauri_plugin_global_shortcut::{GlobalShortcutExt, ShortcutState};

    let state = app.state::<AppState>();
    let current = state.registered_hotkey.lock().unwrap().clone();
    if current.as_deref() == Some(accelerator) {
        return Ok(());
    }

    let handle = app.clone();
    app.global_shortcut()
        .on_shortcut(accelerator, move |_, _, ev| {
            if ev.state() == ShortcutState::Pressed {
                toggle_panel(&handle);
            }
        })
        .map_err(|e| format!("`{accelerator}` could not be registered: {e}"))?;

    if let Some(old) = current {
        let _ = app.global_shortcut().unregister(old.as_str());
    }
    *state.registered_hotkey.lock().unwrap() = Some(accelerator.to_string());
    Ok(())
}

#[tauri::command]
fn set_hotkey(app: AppHandle, hotkey: String) -> Result<(), String> {
    let hotkey = hotkey.trim().to_string();
    if hotkey.is_empty() {
        return Err("no accelerator given".into());
    }
    bind_hotkey(&app, &hotkey)?;

    let state = app.state::<AppState>();
    let mut cfg = state.config.lock().unwrap().clone();
    cfg.hotkey = hotkey;
    let json = serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?;
    std::fs::write(config_path(&app), json).map_err(|e| e.to_string())?;
    *state.config.lock().unwrap() = cfg;
    Ok(())
}

/// Forget the stored Proxmox password. The next connect will ask for it again.
#[tauri::command]
fn forget_pve_credential(state: State<'_, AppState>) -> Result<(), String> {
    clear_credential(state)
}

fn toggle_panel(app: &AppHandle) {
    let Some(w) = app.get_webview_window("main") else { return };
    let visible = w.is_visible().unwrap_or(false);
    let focused = w.is_focused().unwrap_or(false);
    if visible && focused {
        let _ = w.hide();
    } else {
        let _ = w.show();
        let _ = w.set_focus();
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            get_config,
            save_config,
            has_credential,
            set_credential,
            clear_credential,
            connect,
            disconnect,
            send_input,
            resize,
            hide_panel,
            has_agent_token,
            set_agent_token,
            mirror_sync,
            mirror_key,
            mirror_release_all,
            mirror_switch_vt,
            mirror_mouse,
            set_hotkey,
            forget_pve_credential,
            set_visible,
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            let cfg = load_config(&handle);
            let hotkey = cfg.hotkey.clone();
            *app.state::<AppState>().config.lock().unwrap() = cfg;

            // One clipboard watcher for the whole app rather than one per connection. It only has
            // anywhere to send when a mirror session is up, and the sequence number makes the idle
            // case a single cheap syscall.
            {
                let h = handle.clone();
                tauri::async_runtime::spawn(async move {
                    let mut seen = winclip::sequence();
                    loop {
                        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
                        let now = winclip::sequence();
                        if now == seen {
                            continue;
                        }
                        seen = now;
                        // `get_text` returns nothing for content marked "Clipboard Viewer Ignore",
                        // which is how password managers ask not to be copied around.
                        let Some(text) = winclip::get_text(protocol::MAX_CLIPBOARD) else { continue };
                        let Some(state) = h.try_state::<AppState>() else { continue };
                        if state.clipboard_echo.lock().unwrap().as_deref() == Some(text.as_str()) {
                            continue;
                        }
                        // Everything mirrored gets it: you copied here, so "the other machine"
                        // means all of them.
                        state.broadcast(None, protocol::ClientMsg::Clipboard { text });
                    }
                });
            }

            // Same path the settings pane uses, so there is one implementation of binding.
            if let Err(e) = bind_hotkey(&handle, &hotkey) {
                eprintln!("{e}");
                // Fall back to the default so a bad saved config can't leave the panel unsummonable.
                if hotkey != Config::default().hotkey {
                    let fallback = Config::default().hotkey;
                    eprintln!("falling back to `{fallback}`");
                    let _ = bind_hotkey(&handle, &fallback);
                }
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running hublot");
}
