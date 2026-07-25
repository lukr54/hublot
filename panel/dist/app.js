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
//
// One pane per machine on screen, up to two. Everything to do with a mirrored machine lives in a
// `Pane`: its grid or its canvas, its own cursor, its own input badge, its own idea of whether it
// is connected. Events arrive tagged with a target index, because once two sessions are live an
// untagged frame is a frame painted into the wrong pane.

const mir = {
  pane: document.getElementById("mirror"),
  panes: document.getElementById("panes"),
  chips: document.getElementById("chips"),
  pairNew: document.getElementById("pair-new"),
  form: document.getElementById("pair"),
  addr: document.getElementById("pair-addr"),
  fp: document.getElementById("pair-fp"),
  token: document.getElementById("pair-token"),
  error: document.getElementById("pair-error"),
};
const layoutWarn = document.getElementById("layout-warn");

function esc(s) {
  return s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
}

const BUTTON = { 0: 0, 2: 1, 1: 2 }; // browser order → left / right / middle

/// How wide one monospace character is, per pixel of font size.
///
/// The advance width of a monospace font scales linearly with its size, so a single measurement
/// converts "160 columns" into "this many pixels" at any size. Measured lazily against the font the
/// grid actually uses, rather than assumed — the fallbacks in that stack are not all the same shape.
let charRatio = null;
function advanceRatio(el) {
  if (charRatio) return charRatio;
  const probe = document.createElement("span");
  probe.textContent = "M".repeat(100);
  probe.style.cssText = "position:absolute;visibility:hidden;white-space:pre;font-size:100px";
  probe.style.fontFamily = getComputedStyle(el).fontFamily;
  document.body.append(probe);
  charRatio = probe.getBoundingClientRect().width / 100 / 100;
  probe.remove();
  return charRatio;
}

let targets = []; // every configured machine
let shown = []; // indices with a pane, in display order
let focused = null; // the one index keystrokes can reach
const panes = new Map(); // index → Pane

/// Let go of held keys on **every** machine. Cheap, and the failure it prevents — a modifier stuck
/// down on a root console — is the one worth being blunt about.
const release = () => invoke("mirror_release_all").catch(() => {});

class Pane {
  constructor(index, target) {
    this.index = index;
    this.inputEnabled = false;
    this.graphical = false;
    this.cols = 0;
    this.rows = 0;
    // The desktop is kept twice: once clean, once with the cursor drawn on it. Without the clean
    // copy there is nothing to paint back over the cursor's last position, and it leaves a trail.
    this.desk = document.createElement("canvas");
    this.deskCtx = this.desk.getContext("2d");
    this.cursor = { x: 0, y: 0, visible: false };
    this.cursorImg = null;
    this.cursorHot = { x: 0, y: 0 };
    this.lastCursorRect = null;
    this.pendingMove = null;
    this.aimedAt = { x: 0, y: 0 };
    this.build(target);
  }

  build(target) {
    const el = document.createElement("section");
    el.className = "pane";
    el.innerHTML = `
      <header class="pane-head">
        <span class="dot" data-state="idle"></span>
        <span class="pane-name"></span>
        <span class="badge input-badge" data-on="false">input off</span>
        <span class="pane-detail"></span>
        <span class="spacer"></span>
        <span class="vtrow"><span class="vtlabel">VT</span></span>
      </header>
      <div class="pane-body">
        <pre class="grid" tabindex="0" aria-label="Mirrored console"></pre>
        <canvas class="screen" hidden tabindex="0" aria-label="Mirrored desktop"></canvas>
      </div>`;
    this.el = el;
    this.dot = el.querySelector(".dot");
    this.name = el.querySelector(".pane-name");
    this.badge = el.querySelector(".input-badge");
    this.detail = el.querySelector(".pane-detail");
    this.vtrow = el.querySelector(".vtrow");
    this.body = el.querySelector(".pane-body");
    this.grid = el.querySelector(".grid");
    this.screen = el.querySelector(".screen");
    this.screenCtx = this.screen.getContext("2d");
    this.name.textContent = target.name || target.addr;

    // Switch console by ioctl, not by injecting Ctrl+Alt+Fn. Injecting the chord looks more
    // authentic and is a trap: a console whose keyboard is disabled ignores the very chord that
    // would take you off it (DECISIONS.md D13). These stay live even when input is off, which is
    // exactly when you need them.
    for (let vt = 1; vt <= 6; vt++) {
      const b = document.createElement("button");
      b.className = "vt";
      b.textContent = String(vt);
      b.addEventListener("click", async () => {
        await invoke("mirror_switch_vt", { target: this.index, vt }).catch(() => {});
        this.take();
      });
      this.vtrow.append(b);
    }

    // Clicking anywhere in a pane is how you choose which machine you are typing into.
    el.addEventListener("mousedown", () => this.take());
    this.wireMouse();
  }

  /// Take keyboard focus for this pane.
  take() {
    focusPane(this.index);
    (this.graphical ? this.screen : this.grid).focus();
  }

  /// Show the six digits the other machine is displaying while it waits for someone to approve us.
  ///
  /// Deliberately loud and in the pane itself: this is the one moment where the user is being asked
  /// to compare something, and a subtle status line is exactly how people learn to click Allow
  /// without looking.
  confirm(sas) {
    if (!sas) {
      this.el.querySelector(".confirm")?.remove();
      return;
    }
    let box = this.el.querySelector(".confirm");
    if (!box) {
      box = document.createElement("div");
      box.className = "confirm";
      this.body.prepend(box);
    }
    box.innerHTML =
      `<p>Waiting for approval on <b>${esc(this.name.textContent)}</b>.</p>` +
      `<div class="sas">${esc(sas)}</div>` +
      `<p class="fine">Allow it there only if these six digits are the ones on its screen.</p>`;
  }

  /// Say why the picture has stopped. Reuses the confirmation box, because it is the same job:
  /// something about this pane needs words, and a black rectangle provides none.
  notice(text) {
    if (!text) { this.el.querySelector(".notice")?.remove(); return; }
    let box = this.el.querySelector(".notice");
    if (!box) {
      box = document.createElement("div");
      box.className = "confirm notice";
      this.body.prepend(box);
    }
    box.innerHTML = `<p>${esc(text)}</p>`;
  }

  setStatus(state, detail) {
    this.dot.dataset.state = state;
    this.detail.textContent = detail || "";
    // Both of these truncate rather than wrap, so the full text lives in the tooltip.
    this.detail.title = detail || "";
    if (state === "error" || state === "disconnected") this.setInput(false, "");
  }

  setInput(enabled, reason) {
    this.inputEnabled = enabled;
    this.badge.dataset.on = String(enabled);
    const text = enabled ? "input live" : `input off${reason ? ` — ${reason}` : ""}`;
    this.badge.textContent = text;
    this.badge.title = text;
  }

  /// Paint a console frame. Cells are grouped into spans by attribute, so a row of plain text is
  /// one span rather than eighty — the difference between a repaint you notice and one you don't.
  paint(f) {
    if (f.cols !== this.cols || f.rows !== this.rows) {
      this.cols = f.cols;
      this.rows = f.rows;
      this.fitGrid();
    }
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
    this.grid.innerHTML = rows.join("\n");
  }

  /// This target mirrors pixels, not characters. The pane adapts rather than making you pick a
  /// tab, because from where you sit both are just "the other machine's screen".
  screenInfo(w, h) {
    this.graphical = true;
    this.screen.width = w;
    this.screen.height = h;
    this.desk.width = w;
    this.desk.height = h;
    this.screen.hidden = false;
    this.grid.hidden = true;
    this.vtrow.hidden = true; // a desktop has no VTs to switch between
    this.fit();
  }

  /// Scale the console text so a frame fits the pane it is in.
  ///
  /// A tty is 160 columns wide and half a window is not, so at a fixed 13px you would read a third
  /// of each line and scroll for the rest — with two consoles up, which is the entire point of the
  /// split view.
  ///
  /// **The floor is where this stops being worth it.** Two 160×50 consoles in a 1100px window works
  /// out at about six pixels per cell whatever you do, and six-pixel text is not text. Past the
  /// floor the pane scrolls instead — which costs little in practice, because a console line is
  /// mostly trailing blanks: 90 legible columns show you a login prompt, a boot message or a failed
  /// unit, and the empty right-hand half is what you give up.
  fitGrid() {
    if (this.graphical || !this.cols) return;
    const box = this.body.getBoundingClientRect();
    if (!box.width) return;
    const byWidth = (box.width - 14) / this.cols / advanceRatio(this.grid);
    const byHeight = (box.height - 10) / this.rows / 1.15; // 1.15 is the grid's line-height
    const size = Math.max(10, Math.min(13, Math.floor(Math.min(byWidth, byHeight))));
    this.grid.style.fontSize = `${size}px`;
  }

  /// Scale the canvas to the pane while preserving aspect, so a 1080p desktop stays legible in
  /// half a window. The backing store stays at native resolution — we downscale for display only.
  fit() {
    this.fitGrid();
    if (this.screen.hidden || !this.screen.width) return;
    const box = this.body.getBoundingClientRect();
    const scale = Math.min(
      Math.max(40, box.width - 12) / this.screen.width,
      Math.max(40, box.height - 12) / this.screen.height,
      1
    );
    this.screen.style.width = `${Math.floor(this.screen.width * scale)}px`;
    this.screen.style.height = `${Math.floor(this.screen.height * scale)}px`;
  }

  raster(x, y, url) {
    const img = new Image();
    // Decoding happens off the main thread; drawing a stale tile is harmless because the next one
    // for that region supersedes it.
    img.onload = () => {
      this.deskCtx.drawImage(img, x, y);
      this.screenCtx.drawImage(img, x, y);
      this.lastCursorRect = null; // that tile may have painted over the cursor
      this.drawCursor();
    };
    img.src = url;
  }

  pointer(p) {
    this.cursor = p;
    this.drawCursor();
  }

  shape(url, hotX, hotY) {
    const img = new Image();
    img.onload = () => {
      this.cursorImg = img;
      this.cursorHot = { x: hotX, y: hotY };
      this.drawCursor();
    };
    img.src = url;
  }

  /// Erase the cursor by repainting that rectangle from the clean copy, then draw it at its new
  /// place. Two small blits per move rather than one full-screen repaint.
  drawCursor() {
    if (this.lastCursorRect) {
      const r = this.lastCursorRect;
      this.screenCtx.drawImage(this.desk, r.x, r.y, r.w, r.h, r.x, r.y, r.w, r.h);
      this.lastCursorRect = null;
    }
    if (!this.cursor.visible || !this.cursorImg) return;
    const x = this.cursor.x - this.cursorHot.x;
    const y = this.cursor.y - this.cursorHot.y;
    this.screenCtx.drawImage(this.cursorImg, x, y);
    this.lastCursorRect = { x, y, w: this.cursorImg.width, h: this.cursorImg.height };
  }

  /// Canvas pixels → remote screen pixels. The canvas is displayed scaled to fit, so a click at
  /// the visible position must be undone by that same scale before it means anything remotely.
  toScreen(e) {
    const r = this.screen.getBoundingClientRect();
    const x = ((e.clientX - r.left) / r.width) * this.screen.width;
    const y = ((e.clientY - r.top) / r.height) * this.screen.height;
    return {
      x: Math.max(0, Math.min(this.screen.width - 1, Math.round(x))),
      y: Math.max(0, Math.min(this.screen.height - 1, Math.round(y))),
    };
  }

  mouse(kind, opts = {}) {
    if (!this.inputEnabled) return;
    invoke("mirror_mouse", {
      target: this.index,
      kind,
      x: opts.x ?? 0,
      y: opts.y ?? 0,
      button: opts.button ?? 0,
      down: opts.down ?? false,
      dx: opts.dx ?? 0,
      dy: opts.dy ?? 0,
    }).catch(() => {});
  }

  wireMouse() {
    const s = this.screen;
    // Coalesce motion to one message per animation frame. A mouse produces far more events than a
    // remote desktop can usefully consume, and only the newest position matters.
    s.addEventListener("mousemove", (e) => {
      this.aimedAt = this.toScreen(e);
      if (this.pendingMove) return;
      this.pendingMove = requestAnimationFrame(() => {
        this.pendingMove = null;
        // Only the position is sent; the drawn cursor comes back from the agent, so what you see
        // is where the pointer actually is rather than where we hoped it would go.
        this.mouse("move", this.aimedAt);
      });
    });
    s.addEventListener("mousedown", (e) => {
      e.preventDefault();
      this.take();
      this.mouse("move", this.toScreen(e));
      this.mouse("button", { button: BUTTON[e.button] ?? 0, down: true });
    });
    s.addEventListener("mouseup", (e) => {
      e.preventDefault();
      this.mouse("button", { button: BUTTON[e.button] ?? 0, down: false });
    });
    // Otherwise a right-click opens the *panel's* context menu instead of the remote machine's.
    s.addEventListener("contextmenu", (e) => e.preventDefault());
    s.addEventListener(
      "wheel",
      (e) => {
        e.preventDefault();
        this.mouse("scroll", { dx: Math.sign(-e.deltaX), dy: Math.sign(-e.deltaY) });
      },
      { passive: false }
    );
    // Leaving the canvas with a button held would strand it down on the other machine.
    s.addEventListener("mouseleave", () => release());
  }
}

// ── which pane owns the keyboard ────────────────────────────────────────────
//
// With one machine on screen this was a window-focus question (THREAT-MODEL R4). With two it is a
// choice, so it has to be visible: the focused pane is outlined, the other is dimmed, and only the
// focused one can receive a keystroke.

function focusPane(i) {
  if (focused === i) return;
  release(); // never carry a held key from one machine to another
  focused = i;
  for (const [j, p] of panes) p.el.classList.toggle("focused", j === i);
}

/// Keys are sent by *physical position* (`event.code`), never by character (`event.key`).
/// The remote console's keymap decides what appears — see DECISIONS.md D2. Sending the character
/// would mean translating twice and getting it wrong once.
function onKey(e, down) {
  if (view !== "mirror" || focused === null) return;
  if (!mir.form.hidden) return; // the pairing form owns the keyboard while it is up
  if (e.target && e.target.tagName === "INPUT") return;
  const pane = panes.get(focused);
  if (!pane || !pane.inputEnabled) return;
  e.preventDefault();
  invoke("mirror_key", { target: focused, code: e.code, down }).catch(() => {});
}

document.addEventListener("keydown", (e) => onKey(e, true));
document.addEventListener("keyup", (e) => onKey(e, false));

// Anything that means "you are no longer typing here" must let go of held keys.
window.addEventListener("blur", release);
document.addEventListener("visibilitychange", () => document.hidden && release());

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

// ── event routing ───────────────────────────────────────────────────────────

const to = (payload) => panes.get(payload.target);

listen("mirror:frame", (e) => to(e.payload)?.paint(e.payload));
listen("mirror:input", (e) => to(e.payload)?.setInput(e.payload.state === "enabled", e.payload.detail));
listen("mirror:screeninfo", (e) => to(e.payload)?.screenInfo(e.payload.w, e.payload.h));
listen("mirror:raster", (e) => to(e.payload)?.raster(e.payload.x, e.payload.y, e.payload.url));
listen("mirror:pointer", (e) => to(e.payload)?.pointer(e.payload));
listen("mirror:pointershape", (e) => to(e.payload)?.shape(e.payload.url, e.payload.hotX, e.payload.hotY));
listen("mirror:confirm", (e) => to(e.payload)?.confirm(e.payload.sas));
listen("mirror:notice", (e) => to(e.payload)?.notice(e.payload.text));

listen("mirror:status", (e) => {
  const { target, state, detail } = e.payload;
  const pane = panes.get(target);
  pane?.setStatus(state, detail);
  // The window's own light follows the pane you are typing into; the others speak for themselves
  // in their headers.
  if (view === "mirror" && target === focused) setStatus(state, detail);
  // An unenrolled certificate is a pairing problem, not a network one — offer the form again
  // rather than leaving the user staring at an error.
  if ((state === "error" || state === "disconnected") && /not enrolled|pairing/i.test(detail)) {
    openPairing(targets[target]);
  }
});

// ── layout ──────────────────────────────────────────────────────────────────

/// Rebuild the panes so they match `shown`, keeping the ones that are already up.
///
/// Reusing a live pane matters: recreating it would throw away the desktop it has painted and the
/// canvas would go black until the agent's next full frame.
function syncPanes() {
  for (const [i, p] of [...panes]) {
    if (!shown.includes(i)) {
      p.el.remove();
      panes.delete(i);
    }
  }
  for (const i of shown) {
    if (!panes.has(i)) panes.set(i, new Pane(i, targets[i] || { name: `#${i}`, addr: "" }));
  }
  // Append in `shown` order so the chips and the panes read left to right the same way.
  mir.panes.replaceChildren(...shown.map((i) => panes.get(i).el));
  if (focused === null || !shown.includes(focused)) {
    focused = shown[0] ?? null;
  }
  for (const [j, p] of panes) p.el.classList.toggle("focused", j === focused);
  layoutPanes();
}

/// Side by side normally, stacked when the window is too narrow for two to be worth looking at.
function layoutPanes() {
  const box = mir.panes.getBoundingClientRect();
  mir.panes.classList.toggle("stack", shown.length > 1 && box.width < box.height * 1.3);
  for (const p of panes.values()) p.fit();
}
new ResizeObserver(layoutPanes).observe(mir.pane);

// ── choosing machines ───────────────────────────────────────────────────────

function renderChips() {
  mir.chips.replaceChildren(
    ...targets.map((t, i) => {
      const b = document.createElement("button");
      b.className = "chip";
      b.setAttribute("aria-pressed", String(shown.includes(i)));
      b.title = shown.includes(i)
        ? `${t.addr} — click to put away`
        : `${t.addr} — click to show (two at a time)`;
      const dot = document.createElement("span");
      dot.className = "dot";
      dot.dataset.state = panes.get(i)?.dot.dataset.state || "idle";
      b.append(dot, document.createTextNode(t.name || t.addr));
      b.addEventListener("click", () => toggleTarget(i));
      return b;
    })
  );
}

/// Click a chip to show that machine; click it again to put it away. Two panes is the ceiling, and
/// asking for a third replaces the one you are *not* typing into — the focused pane is presumably
/// the one you meant to keep.
async function toggleTarget(i) {
  let next = shown.slice();
  if (next.includes(i)) {
    if (next.length === 1) return; // never leave the mirror empty
    next = next.filter((x) => x !== i);
  } else if (next.length < 2) {
    next.push(i);
  } else {
    const drop = next.find((x) => x !== focused) ?? next[0];
    next = next.map((x) => (x === drop ? i : x));
  }
  await applyShown(next);
}

async function applyShown(next) {
  shown = next;
  syncPanes();
  renderChips();
  try {
    // Saving and connecting are one call: a layout that persists but doesn't take effect is how
    // you end up with a pane that never fills in.
    await invoke("set_visible", { indices: shown });
  } catch (err) {
    panes.get(shown[0])?.setStatus("error", String(err));
  }
}

/// Load the configured machines and put the saved layout back on screen.
async function refreshTargets() {
  const cfg = await invoke("get_config");
  targets = cfg.agents || [];
  shown = (cfg.visible || []).filter((i) => i < targets.length);
  if (!shown.length && targets.length) shown = [0];
  syncPanes();
  renderChips();
  return cfg;
}

function openPairing(target) {
  mir.addr.value = target?.addr || "";
  mir.fp.value = target?.fingerprint || "";
  mir.token.value = "";
  mir.error.textContent = "";
  mir.form.hidden = false;
  mir.addr.focus();
}

mir.pairNew.addEventListener("click", () => openPairing(null));

mir.form.addEventListener("submit", async (e) => {
  e.preventDefault();
  mir.error.textContent = "";
  try {
    const cfg = await invoke("get_config");
    const addr = mir.addr.value.trim();
    if (!addr) {
      mir.error.textContent = "an address is needed — the other machine's share tab shows it";
      return;
    }
    // Empty is the normal case now: no fingerprint means "we have never met", which is what makes
    // the panel ask that machine to approve us instead of refusing.
    const fingerprint = mir.fp.value.trim();
    cfg.agents = cfg.agents || [];
    let index = cfg.agents.findIndex((t) => t.addr === addr);
    if (index >= 0) {
      if (fingerprint) cfg.agents[index].fingerprint = fingerprint;
    } else {
      cfg.agents.push({ name: addr, addr, fingerprint });
      index = cfg.agents.length - 1;
    }
    // A machine you just paired is one you want to look at.
    cfg.visible = [index, ...(cfg.visible || []).filter((i) => i !== index)].slice(0, 2);
    await invoke("save_config", { config: cfg });
    // Tokens are keyed by address, so pairing a second machine leaves the first one's alone. Only
    // stored when one was actually given — a console agent's way in, not a desktop's.
    if (mir.token.value.trim()) {
      await invoke("set_agent_token", { addr, token: mir.token.value.trim() });
    }
    mir.token.value = "";
    mir.form.hidden = true;
    await refreshTargets();
    await invoke("mirror_sync");
  } catch (err) {
    mir.error.textContent = String(err);
  }
});

// ── share this PC ───────────────────────────────────────────────────────────
//
// The same three operations the agent has always had on its command line — run, install at logon,
// open the firewall — with the terminal taken out. Nothing here is new capability; it is the
// difference between a tool you can set up and one you actually do.

const sh = {
  pane: document.getElementById("share"),
  dot: document.getElementById("sh-dot"),
  state: document.getElementById("sh-state"),
  start: document.getElementById("sh-start"),
  install: document.getElementById("sh-install"),
  msg: document.getElementById("sh-msg"),
  addrBox: document.getElementById("sh-addr-box"),
  displayBox: document.getElementById("sh-display-box"),
  display: document.getElementById("sh-display"),
  address: document.getElementById("sh-address"),
  detail: document.getElementById("sh-detail"),
};

async function refreshShare() {
  let st;
  try {
    st = await invoke("share_status");
  } catch (err) {
    sh.state.textContent = String(err);
    sh.dot.dataset.state = "error";
    return;
  }

  if (!st.agent) {
    // Worth being specific: this is the one failure the user cannot do anything about from here.
    sh.dot.dataset.state = "error";
    sh.state.textContent = "win-agent.exe is missing — reinstall hublot to restore it";
    sh.start.disabled = sh.install.disabled = true;
    return;
  }
  sh.start.disabled = false;
  sh.install.disabled = false;

  sh.dot.dataset.state = st.running ? "connected" : "idle";
  sh.state.textContent = st.running ? "sharing — this PC can be controlled" : "not sharing";
  sh.start.textContent = st.running ? "Sharing" : "Start sharing now";
  sh.start.disabled = st.running;

  sh.addrBox.hidden = !st.running || !st.addresses.length;
  sh.address.replaceChildren(
    ...st.addresses.map((a) => {
      const d = document.createElement("div");
      d.className = "sas addr";
      d.textContent = `${a}:${st.port}`;
      return d;
    })
  );

  // Only worth showing once there is a choice to make; one display is not a decision.
  const screens = await invoke("share_displays").catch(() => []);
  sh.displayBox.hidden = screens.length < 2;
  if (screens.length > 1) {
    sh.display.replaceChildren(
      ...screens.map(([name, chosen]) => {
        const o = document.createElement("option");
        o.value = name;
        o.textContent = name;
        o.selected = chosen;
        return o;
      })
    );
  }

  const bits = [];
  bits.push(st.installed ? "starts automatically at logon" : "does NOT start at logon yet");
  // Without the rule the agent runs and nothing can reach it, which looks exactly like a broken
  // agent — so it gets said plainly rather than left for the other machine to discover.
  bits.push(st.firewall ? "allowed through the firewall" : "NOT allowed through the firewall — nothing will connect");
  sh.detail.textContent = bits.join(" · ");
}

sh.display.addEventListener("change", async () => {
  sh.msg.textContent = "switching…";
  try {
    await invoke("share_use_display", { name: sh.display.value });
    // The agent re-reads the choice within a second, so there is nothing to restart.
    sh.msg.textContent = `now sharing ${sh.display.value}`;
  } catch (err) {
    sh.msg.textContent = String(err);
  }
});

sh.start.addEventListener("click", async () => {
  sh.msg.textContent = "starting…";
  try {
    await invoke("share_start");
    // The agent takes a moment to bind its port; polling once beats reporting success blindly.
    setTimeout(refreshShare, 700);
    sh.msg.textContent = "";
  } catch (err) {
    sh.msg.textContent = String(err);
  }
});

sh.install.addEventListener("click", async () => {
  sh.msg.textContent = "waiting for the administrator prompt…";
  try {
    // LocalSubnet rather than a typed address: it is the honest scope for a home network, it needs
    // nothing from the user, and it is still far tighter than opening the port to anything.
    await invoke("share_install", { allow: "LocalSubnet" });
    sh.msg.textContent = "done — this PC will share from every logon";
    setTimeout(refreshShare, 900);
  } catch (err) {
    sh.msg.textContent = String(err);
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
    // Editing the list can delete the machine a pane is showing; drop any layout that no longer
    // points at anything rather than leaving a pane that can never connect.
    cfg.visible = (cfg.visible || []).filter((i) => i < cfg.agents.length);
    await invoke("save_config", { config: cfg });
    await refreshTargets();
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

async function showView(next) {
  view = next;
  document.querySelectorAll(".tab").forEach((t) => {
    t.setAttribute("aria-selected", String(t.dataset.view === next));
  });
  el.term.hidden = next !== "shell";
  mir.pane.hidden = next !== "mirror";
  sh.pane.hidden = next !== "share";
  set.pane.hidden = next !== "settings";

  // Leaving the mirror means letting go of anything held there.
  if (next !== "mirror") release();

  if (next === "share") {
    refreshShare();
    return;
  }
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
  await refreshTargets();

  // Pairing is decided by whether we are configured, not by whether a token is stored: the token
  // is deleted once spent, so "no token" is the normal state of a paired panel.
  const unpaired = shown.map((i) => targets[i]).find((t) => !t || !t.addr || !t.fingerprint);
  if (!targets.length || unpaired) {
    openPairing(unpaired || null);
    return;
  }
  // `mirror_sync` is idempotent — it connects what is missing and leaves what is already up — so
  // re-entering the tab costs nothing and there is no "have we started yet" flag to get wrong.
  try {
    await invoke("mirror_sync");
    panes.get(focused)?.take();
  } catch (err) {
    panes.get(focused)?.setStatus("error", String(err));
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
// Reconnect what you are looking at, not always the shell.
el.reconnect.addEventListener("click", () => {
  if (view === "mirror") {
    for (const i of shown) panes.get(i)?.setStatus("connecting", "");
    invoke("mirror_sync").catch(() => {});
    return;
  }
  start();
});

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
