"use strict";

// Fail loudly, not blankly. Without this guard a missing bridge throws on the first line and the
// window renders as an empty rectangle with nothing to go on — the single most confusing failure
// mode a WebView app has.
const BRIDGE = window.__TAURI__;
if (!BRIDGE) {
  document.body.innerHTML =
    '<div style="padding:24px;font:13px/1.6 system-ui;color:#f85149">' +
    "<b>No Tauri bridge.</b><br />This page is being served outside the hublot app, so it has no " +
    "way to reach the console. Run <code>hublot-panel.exe</code> instead." +
    "</div>";
  throw new Error("no __TAURI__ bridge");
}

const { invoke } = BRIDGE.core;
const { listen } = BRIDGE.event;
const { getCurrentWindow } = BRIDGE.window;

const el = {
  bar: document.getElementById("bar"),
  dot: document.getElementById("dot"),
  detail: document.getElementById("detail"),
  reconnect: document.getElementById("reconnect"),
  hide: document.getElementById("hide"),
  term: document.getElementById("term"),
  gate: document.getElementById("gate"),
  gateForm: document.getElementById("gate-form"),
  gateWho: document.getElementById("gate-who"),
  gatePw: document.getElementById("gate-pw"),
  gateError: document.getElementById("gate-error"),
};

// ── terminal ────────────────────────────────────────────────────────────────

const term = new Terminal({
  fontFamily: "Cascadia Mono, Consolas, monospace",
  fontSize: 13,
  cursorBlink: true,
  // The console we're attached to is a real pty; let it own the scrollback.
  scrollback: 5000,
  theme: {
    background: "#0d1117",
    foreground: "#c9d1d9",
    cursor: "#58a6ff",
    selectionBackground: "#264f78",
  },
});
const fit = new FitAddon.FitAddon();
term.loadAddon(fit);
term.open(el.term);

/// Base64 → bytes. We deliberately hand xterm raw bytes rather than a decoded string: a UTF-8
/// sequence can straddle two websocket messages, and xterm's decoder carries state across writes
/// where a per-chunk decode would produce replacement characters.
function bytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

let lastSize = { cols: 0, rows: 0 };
function syncSize() {
  fit.fit();
  const { cols, rows } = term;
  if (cols !== lastSize.cols || rows !== lastSize.rows) {
    lastSize = { cols, rows };
    invoke("resize", { cols, rows }).catch(() => {});
  }
}

new ResizeObserver(() => syncSize()).observe(el.term);
term.onData((d) => invoke("send_input", { data: d }).catch(() => {}));

// ── status ──────────────────────────────────────────────────────────────────

function setStatus(state, detail) {
  el.dot.dataset.state = state;
  el.detail.textContent = detail || "";
}

listen("console:data", (e) => term.write(bytes(e.payload)));

listen("console:status", (e) => {
  const { state, detail } = e.payload;
  // Only the visible view owns the status light; otherwise the two tiers fight over it.
  if (view === "shell") setStatus(state, detail);
  if (state === "connected") {
    // Tell the pty our real geometry now that there is something to tell.
    lastSize = { cols: 0, rows: 0 };
    syncSize();
    term.focus();
  }
  if (state === "disconnected") {
    term.writeln(`\r\n\x1b[38;5;203m── ${detail} ──\x1b[0m`);
  }
});

// ── mirror (tier 1) ─────────────────────────────────────────────────────────

const mir = {
  pane: document.getElementById("mirror"),
  grid: document.getElementById("grid"),
  form: document.getElementById("pair"),
  addr: document.getElementById("pair-addr"),
  fp: document.getElementById("pair-fp"),
  token: document.getElementById("pair-token"),
  error: document.getElementById("pair-error"),
};

function esc(s) {
  return s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
}

/// Paint a console frame. Cells are grouped into spans by attribute, so a row of plain text is one
/// span rather than eighty — the difference between a repaint you notice and one you don't.
function paint(f) {
  const attrs = bytes(f.attrs);
  const rows = [];
  for (let y = 0; y < f.text.length; y++) {
    // Iterate code points, not UTF-16 units: one console cell is one code point, and indexing by
    // unit would drift the moment anything outside the BMP appears.
    const chars = Array.from(f.text[y]);
    let html = "";
    let run = "";
    let runAttr = -1;
    const flush = () => {
      if (!run) return;
      const fg = runAttr & 0x0f;
      const bg = (runAttr >> 4) & 0x07;
      html += `<span class="f${fg} b${bg}">${esc(run)}</span>`;
      run = "";
    };
    for (let x = 0; x < chars.length; x++) {
      const a = attrs[y * f.cols + x] ?? 7;
      const isCursor = x === f.cursor[0] && y === f.cursor[1];
      if (isCursor) {
        flush();
        html += `<span class="cur f${a & 0x0f} b${(a >> 4) & 0x07}">${esc(chars[x])}</span>`;
        runAttr = -1;
        continue;
      }
      if (a !== runAttr) {
        flush();
        runAttr = a;
      }
      run += chars[x];
    }
    flush();
    rows.push(html);
  }
  mir.grid.innerHTML = rows.join("\n");
}

// ── injection (tier 1, Phase 3) ─────────────────────────────────────────────

let inputEnabled = false;

const badge = document.getElementById("input-badge");
const layoutWarn = document.getElementById("layout-warn");

function setInput(enabled, reason) {
  inputEnabled = enabled;
  badge.dataset.on = String(enabled);
  badge.textContent = enabled ? "input live" : `input off${reason ? ` — ${reason}` : ""}`;
}

const release = () => invoke("mirror_release_all").catch(() => {});

/// Keys are sent by *physical position* (`event.code`), never by character (`event.key`).
/// The remote console's keymap decides what appears — see DECISIONS.md D2. Sending the character
/// would mean translating twice and getting it wrong once.
function onKey(e, down) {
  if (view !== "mirror" || !inputEnabled) return;
  if (!mir.form.hidden) return; // the pairing form owns the keyboard while it is up
  if (e.target && e.target.tagName === "INPUT") return;
  e.preventDefault();
  invoke("mirror_key", { code: e.code, down }).catch(() => {});
}

document.addEventListener("keydown", (e) => onKey(e, true));
document.addEventListener("keyup", (e) => onKey(e, false));

// Anything that means "you are no longer typing here" must let go of held keys. A modifier stuck
// down on a root console is the failure this guards against.
window.addEventListener("blur", release);
document.addEventListener("visibilitychange", () => document.hidden && release());

// Switch console by ioctl, not by injecting Ctrl+Alt+Fn.
//
// Injecting the chord looks more "authentic" and is a trap: a console whose keyboard is disabled
// ignores the very chord that would take you off it, so you end up somewhere you cannot leave
// (DECISIONS.md D13). VT_ACTIVATE works regardless of keyboard mode — and it works even when the
// input badge says input is off, which is exactly when you need it most.
document.querySelectorAll("button.vt").forEach((b) => {
  b.addEventListener("click", async () => {
    await invoke("mirror_switch_vt", { vt: Number(b.dataset.vt) }).catch(() => {});
    mir.grid.focus();
  });
});

/// Detect whether the Windows layout matches the console's keymap.
///
/// `navigator.keyboard.getLayoutMap()` reports what the *active* layout produces for a physical
/// key. Physical KeyQ gives `a` on French AZERTY and `q` on UK/US — so one lookup tells us whether
/// the user's muscle memory will line up with the remote keymap. We never change their layout;
/// we say when it disagrees, which is the honest half of D2.
async function checkLayout() {
  try {
    if (!navigator.keyboard || !navigator.keyboard.getLayoutMap) return;
    const map = await navigator.keyboard.getLayoutMap();
    const q = (map.get("KeyQ") || "").toLowerCase();
    if (q && q !== "a") {
      layoutWarn.hidden = false;
      layoutWarn.textContent = `Windows layout is not AZERTY (KeyQ→"${q}") — the console maps fr, so characters will differ`;
    } else {
      layoutWarn.hidden = true;
    }
  } catch {
    /* Keyboard API unavailable; skip rather than guess. */
  }
}

listen("mirror:input", (e) => setInput(e.payload.state === "enabled", e.payload.detail));

// ── graphical desktops (Windows agent) ──────────────────────────────────────
//
// A console agent sends a character grid; a Windows agent sends compressed rectangles. The mirror
// pane adapts to whichever it is talking to rather than making you pick a tab, because from where
// you sit both are just "the other machine's screen".

const screenEl = document.getElementById("screen");
const screenCtx = screenEl.getContext("2d");

listen("mirror:screeninfo", (e) => {
  const { w, h } = e.payload;
  screenEl.width = w;
  screenEl.height = h;
  screenEl.hidden = false;
  mir.grid.hidden = true;
  fitScreen();
});

/// Scale the canvas to the pane while preserving aspect, so a 1080p desktop is legible in a small
/// window. The backing store stays at native resolution — we downscale for display only.
function fitScreen() {
  if (screenEl.hidden || !screenEl.width) return;
  const box = mir.pane.getBoundingClientRect();
  const avail = Math.max(120, box.height - 40);
  const scale = Math.min((box.width - 16) / screenEl.width, avail / screenEl.height, 1);
  screenEl.style.width = `${Math.floor(screenEl.width * scale)}px`;
  screenEl.style.height = `${Math.floor(screenEl.height * scale)}px`;
}
new ResizeObserver(fitScreen).observe(mir.pane);

listen("mirror:raster", (e) => {
  const { x, y, url } = e.payload;
  const img = new Image();
  // Decoding happens off the main thread; drawing a stale tile is harmless because the next one
  // for that region supersedes it.
  img.onload = () => {
    screenCtx.drawImage(img, x, y);
    drawCursor();
  };
  img.src = url;
});

// ── pointer ─────────────────────────────────────────────────────────────────
//
// Desktop Duplication deliberately excludes the mouse pointer from captured frames — it is
// delivered separately, as a shape and position. Until we composite the real one, the panel draws
// its own at the last position it *sent*. That is client-side prediction: it feels instant because
// it owes nothing to the round trip, but it will not show the remote cursor's shape, nor follow it
// when the remote machine moves the pointer itself.

let cursor = null;

function drawCursor() {
  if (!cursor) return;
  const { x, y } = cursor;
  screenCtx.save();
  screenCtx.beginPath();
  screenCtx.moveTo(x, y);
  screenCtx.lineTo(x, y + 17);
  screenCtx.lineTo(x + 5, y + 13);
  screenCtx.lineTo(x + 9, y + 20);
  screenCtx.lineTo(x + 12, y + 18);
  screenCtx.lineTo(x + 8, y + 11);
  screenCtx.lineTo(x + 13, y + 11);
  screenCtx.closePath();
  screenCtx.fillStyle = "#fff";
  screenCtx.strokeStyle = "#000";
  screenCtx.lineWidth = 1.5;
  screenCtx.stroke();
  screenCtx.fill();
  screenCtx.restore();
}

/// Canvas pixels → remote screen pixels. The canvas is displayed scaled to fit, so a click at the
/// visible position must be undone by that same scale before it means anything remotely.
function toScreen(e) {
  const r = screenEl.getBoundingClientRect();
  const x = ((e.clientX - r.left) / r.width) * screenEl.width;
  const y = ((e.clientY - r.top) / r.height) * screenEl.height;
  return {
    x: Math.max(0, Math.min(screenEl.width - 1, Math.round(x))),
    y: Math.max(0, Math.min(screenEl.height - 1, Math.round(y))),
  };
}

function sendMouse(kind, opts = {}) {
  if (!inputEnabled) return;
  invoke("mirror_mouse", {
    kind,
    x: opts.x ?? 0,
    y: opts.y ?? 0,
    button: opts.button ?? 0,
    down: opts.down ?? false,
    dx: opts.dx ?? 0,
    dy: opts.dy ?? 0,
  }).catch(() => {});
}

// Coalesce motion to one message per animation frame. A mouse can produce far more events than a
// remote desktop can usefully consume, and only the newest position matters.
let pendingMove = null;
screenEl.addEventListener("mousemove", (e) => {
  const p = toScreen(e);
  cursor = p;
  if (pendingMove) return;
  pendingMove = requestAnimationFrame(() => {
    pendingMove = null;
    sendMouse("move", cursor);
    drawCursor();
  });
});

const BUTTON = { 0: 0, 2: 1, 1: 2 }; // browser order → left / right / middle

screenEl.addEventListener("mousedown", (e) => {
  e.preventDefault();
  screenEl.focus();
  const p = toScreen(e);
  sendMouse("move", p);
  sendMouse("button", { button: BUTTON[e.button] ?? 0, down: true });
});
screenEl.addEventListener("mouseup", (e) => {
  e.preventDefault();
  sendMouse("button", { button: BUTTON[e.button] ?? 0, down: false });
});
// Otherwise a right-click opens the *panel's* context menu instead of the remote machine's.
screenEl.addEventListener("contextmenu", (e) => e.preventDefault());
screenEl.addEventListener(
  "wheel",
  (e) => {
    e.preventDefault();
    sendMouse("scroll", { dx: Math.sign(-e.deltaX), dy: Math.sign(-e.deltaY) });
  },
  { passive: false }
);
// Leaving the canvas with a button held would strand it down on the other machine.
screenEl.addEventListener("mouseleave", () => release());

listen("mirror:frame", (e) => paint(e.payload));
listen("mirror:status", (e) => {
  const { state, detail } = e.payload;
  if (view === "mirror") setStatus(state, detail);
  if (state === "error" || state === "disconnected") {
    setInput(false, "");
    mir.grid.textContent = `${state}: ${detail}`;
    // An unenrolled certificate is a pairing problem, not a network one — offer the form again
    // rather than leaving the user staring at an error.
    if (/not enrolled|pairing/i.test(detail)) {
      mirrorStarted = false;
      mir.form.hidden = false;
      mir.addr.focus();
    }
  }
});

const targetSel = document.getElementById("target");

async function fillTargetSelector() {
  const cfg = await invoke("get_config");
  const list = cfg.agents || [];
  targetSel.replaceChildren(
    ...list.map((t, i) => {
      const o = document.createElement("option");
      o.value = String(i);
      o.textContent = t.name || t.addr;
      return o;
    })
  );
  targetSel.value = String(cfg.active_agent || 0);
  targetSel.hidden = list.length < 2; // no point offering a choice of one
}

targetSel.addEventListener("change", async () => {
  await invoke("set_active_agent", { index: Number(targetSel.value) }).catch(() => {});
  // A different machine is a different console: drop what we hold and start clean.
  release();
  mir.grid.textContent = "";
  setInput(false, "");
  mirrorStarted = false;
  await showView("mirror");
});

mir.form.addEventListener("submit", async (e) => {
  e.preventDefault();
  mir.error.textContent = "";
  try {
    const cfg = await invoke("get_config");
    const addr = mir.addr.value.trim();
    const fingerprint = mir.fp.value.trim();
    cfg.agents = cfg.agents || [];
    const existing = cfg.agents.findIndex((t) => t.addr === addr);
    if (existing >= 0) {
      cfg.agents[existing].fingerprint = fingerprint;
      cfg.active_agent = existing;
    } else {
      cfg.agents.push({ name: addr, addr, fingerprint });
      cfg.active_agent = cfg.agents.length - 1;
    }
    await invoke("save_config", { config: cfg });
    await invoke("set_agent_token", { token: mir.token.value });
    mir.token.value = "";
    mir.form.hidden = true;
    await invoke("mirror_connect");
  } catch (err) {
    mir.error.textContent = String(err);
  }
});

// ── settings ────────────────────────────────────────────────────────────────

const set = {
  pane: document.getElementById("settings"),
  hk: document.getElementById("hk"),
  hkApply: document.getElementById("hk-apply"),
  hkMsg: document.getElementById("hk-msg"),
  host: document.getElementById("s-host"),
  port: document.getElementById("s-port"),
  node: document.getElementById("s-node"),
  user: document.getElementById("s-user"),
  fp: document.getElementById("s-fp"),
  targets: document.getElementById("targets"),
  addTarget: document.getElementById("t-add"),
  save: document.getElementById("s-save"),
  forget: document.getElementById("s-forget"),
  msg: document.getElementById("s-msg"),
};

/// Turn a keypress into a Tauri accelerator. We read `code` (physical position) for letters and
/// digits so the recorded accelerator doesn't drift when you switch Windows layouts — the same
/// reasoning as D2, applied to the hotkey rather than to the console.
function accelerator(e) {
  const mods = [];
  if (e.ctrlKey) mods.push("Ctrl");
  if (e.altKey) mods.push("Alt");
  if (e.shiftKey) mods.push("Shift");
  if (e.metaKey) mods.push("Super");

  let key = null;
  if (/^Key[A-Z]$/.test(e.code)) key = e.code.slice(3);
  else if (/^Digit[0-9]$/.test(e.code)) key = e.code.slice(5);
  else if (/^F([1-9]|1[0-2])$/.test(e.code)) key = e.code;
  else if (["Space", "Enter", "Tab", "Escape", "Home", "End", "PageUp", "PageDown", "Insert", "Delete"].includes(e.code))
    key = e.code;
  else if (e.code.startsWith("Arrow")) key = e.code.slice(5);

  if (!key) return null; // modifiers alone are not an accelerator
  return [...mods, key].join("+");
}

set.hk.addEventListener("focus", () => {
  set.hk.classList.add("recording");
  set.hkMsg.textContent = "listening — press a combination";
});
set.hk.addEventListener("blur", () => set.hk.classList.remove("recording"));
set.hk.addEventListener("keydown", (e) => {
  e.preventDefault();
  const acc = accelerator(e);
  if (acc) {
    set.hk.value = acc;
    set.hkMsg.textContent = "press Apply to bind it";
  }
});

set.hkApply.addEventListener("click", async () => {
  try {
    await invoke("set_hotkey", { hotkey: set.hk.value });
    // Deliberately confirms the *old* binding is gone and the new one is live: a rebind that
    // silently half-worked is worse than one that failed.
    set.hkMsg.textContent = `bound — ${set.hk.value} now summons the panel`;
  } catch (err) {
    set.hkMsg.textContent = String(err);
  }
});

async function loadSettings() {
  const cfg = await invoke("get_config");
  set.hk.value = cfg.hotkey || "";
  set.host.value = cfg.host || "";
  set.port.value = cfg.port || 8006;
  set.node.value = cfg.node || "";
  set.user.value = cfg.user || "";
  set.fp.value = cfg.fingerprint || "";
  renderTargets(cfg.agents || []);
  set.hkMsg.textContent = "";
  set.msg.textContent = "";
}

function targetRow(t = { name: "", addr: "", fingerprint: "" }) {
  const row = document.createElement("div");
  row.className = "target";
  const name = document.createElement("input");
  name.placeholder = "name";
  name.value = t.name || "";
  const addr = document.createElement("input");
  addr.placeholder = "host:port";
  addr.spellcheck = false;
  addr.value = t.addr || "";
  const del = document.createElement("button");
  del.textContent = "×";
  del.title = "Remove";
  del.addEventListener("click", () => row.remove());
  const fp = document.createElement("input");
  fp.className = "fp";
  fp.placeholder = "certificate fingerprint";
  fp.spellcheck = false;
  fp.value = t.fingerprint || "";
  row.append(name, addr, del, fp);
  return row;
}

function renderTargets(list) {
  set.targets.replaceChildren(...list.map(targetRow));
  if (!list.length) set.targets.append(targetRow());
}

function readTargets() {
  return [...set.targets.querySelectorAll(".target")]
    .map((r) => {
      const [name, addr, , fp] = r.querySelectorAll("input");
      return { name: name.value.trim() || addr.value.trim(), addr: addr.value.trim(), fingerprint: fp.value.trim() };
    })
    .filter((t) => t.addr);
}

set.addTarget.addEventListener("click", () => set.targets.append(targetRow()));

set.save.addEventListener("click", async () => {
  try {
    const cfg = await invoke("get_config");
    cfg.host = set.host.value.trim();
    cfg.port = Number(set.port.value) || 8006;
    cfg.node = set.node.value.trim();
    cfg.user = set.user.value.trim();
    cfg.fingerprint = set.fp.value.trim();
    cfg.agents = readTargets();
    if (cfg.active_agent >= cfg.agents.length) cfg.active_agent = 0;
    await invoke("save_config", { config: cfg });
    await fillTargetSelector();
    set.msg.textContent = "saved — reconnect the tabs to use the new settings";
  } catch (err) {
    set.msg.textContent = String(err);
  }
});

set.forget.addEventListener("click", async () => {
  try {
    await invoke("forget_pve_credential");
    set.msg.textContent = "forgotten — the shell tab will ask again";
  } catch (err) {
    set.msg.textContent = String(err);
  }
});

// ── views ───────────────────────────────────────────────────────────────────

let view = "shell";
let mirrorStarted = false;

async function showView(next) {
  view = next;
  document.querySelectorAll(".tab").forEach((t) => {
    t.setAttribute("aria-selected", String(t.dataset.view === next));
  });
  el.term.hidden = next !== "shell";
  mir.pane.hidden = next !== "mirror";
  set.pane.hidden = next !== "settings";

  // Leaving the mirror means letting go of anything held there.
  if (next !== "mirror") release();

  if (next === "settings") {
    loadSettings();
    return;
  }
  if (next === "shell") {
    syncSize();
    term.focus();
    return;
  }

  checkLayout();
  await fillTargetSelector();
  if (mirrorStarted) {
    mir.grid.focus();
    return;
  }
  mirrorStarted = true;

  // Pairing is decided by whether we are configured, not by whether a token is stored: the token
  // is deleted once spent, so "no token" is the normal state of a paired panel.
  const cfg = await invoke("get_config");
  const active = (cfg.agents || [])[cfg.active_agent || 0];
  if (!active || !active.addr || !active.fingerprint) {
    mir.addr.value = active ? active.addr : "";
    mir.fp.value = active ? active.fingerprint : "";
    mir.form.hidden = false;
    mir.addr.focus();
    mirrorStarted = false;
    return;
  }
  try {
    await invoke("mirror_connect");
    mir.grid.focus();
  } catch (err) {
    mirrorStarted = false;
    mir.grid.textContent = String(err);
  }
}

document.querySelectorAll(".tab").forEach((t) => {
  t.addEventListener("click", () => showView(t.dataset.view));
});

// ── window chrome ───────────────────────────────────────────────────────────

el.bar.addEventListener("mousedown", (e) => {
  if (e.target.closest("button")) return;
  getCurrentWindow().startDragging();
});
el.hide.addEventListener("click", () => invoke("hide_panel"));
el.reconnect.addEventListener("click", () => start());

// ── startup ─────────────────────────────────────────────────────────────────

async function start() {
  const cfg = await invoke("get_config");
  el.gateWho.textContent = `${cfg.user} at ${cfg.host}:${cfg.port}, node ${cfg.node}`;

  if (!(await invoke("has_credential"))) {
    el.gate.hidden = false;
    el.gatePw.focus();
    return;
  }
  el.gate.hidden = true;
  try {
    await invoke("connect");
  } catch (err) {
    setStatus("error", String(err));
    term.writeln(`\r\n\x1b[38;5;203m${String(err)}\x1b[0m`);
  }
}

el.gateForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  el.gateError.textContent = "";
  try {
    await invoke("set_credential", { password: el.gatePw.value });
    el.gatePw.value = "";
    el.gate.hidden = true;
    await start();
  } catch (err) {
    el.gateError.textContent = String(err);
  }
});

start();
