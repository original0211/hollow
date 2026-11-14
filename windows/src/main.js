// Electron main (M2-1…M2-3): single instance, tray-resident; the CoreBridge
// owns protocol state, SOCKS lifecycle follows connect/disconnect, every exit
// path disconnects the bridge (closing the SOCKS port) and restores the
// system proxy. Pairing/import (M2-3): every import payload — paste, file,
// QR, or an OS-delivered hollow:// link — is staged in memory only and
// applied solely after the in-app confirmation (red-team correction 4);
// payloads are never logged.
import { app, BrowserWindow, Tray, Menu, ipcMain, nativeImage, dialog, clipboard } from "electron";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { CoreBridge } from "./core-bridge.js";
import { loadConfig, saveConfig, loadOrCreatePsk, loadPsk, writePsk, tightenPskAcl, verifierHex, PskCorruptError, pskStatus, configDir } from "./config.js";
import { parseAnyPayload, previewOf, buildExportObject, buildLink, qrDataUrl, bgraToRgba, decodeQrFromPixels, validateWorkerUrl, validateHttpPath } from "./pairing.js";
import { BUILTIN_EDGES, fetchRemoteEdges, fetchMeta, measureEdges, bestEdge } from "./edges.js";
import { buildPac, startPacServer } from "./pac.js";
import * as sysproxy from "./sysproxy.js";
import { HelperClient } from "./helper-client.js";
import { HelperWatch } from "./helper-watch.js";
import { planTunEnable, planCandidateRefresh, edgeModeDisabledInTun } from "./tun-policy.js";
import { TunGraceSupervisor, createStaleRestoreHandler, tunStatusView, modeFamily } from "./tun-supervisor.js";
import { readNetcfgBackup } from "./netcfg-backup.js";
import { execFile } from "node:child_process";
import dns from "node:dns/promises";

const here = path.dirname(fileURLToPath(import.meta.url));
// One data home (NP-1114-35): Electron's userData (Chromium profile and
// caches) lives INSIDE the Hollow config dir — not in a second dir
// derived from package.json's name (%APPDATA%\hollow-windows), which is
// how the true-device run ended up with two homes. configDir() is the
// single source of truth. Pre-existing hollow-windows dirs hold only
// Chromium caches (Hollow data always lived in configDir()) and are
// ignored — no migration, and nothing is ever auto-deleted.
try { app.setPath("userData", configDir()); } catch { /* keep Electron default */ }
let cfg = loadConfig();
// Config persistence must never take the app down (M2-5 hardening): a locked
// or temporarily unwritable config dir logs and keeps the in-memory state.
function safeSave() {
  try { saveConfig(cfg); } catch (e) { log(`config save failed (continuing in-memory): ${e.message}`); }
}
const logs = [];
function log(m) {
  const line = `${new Date().toISOString()} ${m}`;
  logs.push(line); if (logs.length > 300) logs.shift();
  if (win && !win.isDestroyed()) win.webContents.send("hollow:log", line);
}

let win = null, tray = null, bridge = null, proxyOn = false, bridgeError = null;

function getBridge() {
  if (!bridge) {
    let psk;
    try { psk = loadOrCreatePsk(); }
    catch (e) {
      // Corrupt PSK: Error state, no silent regeneration (NP-1114-07).
      bridgeError = e instanceof PskCorruptError ? e.message : String(e.message || e);
      log(`PSK error: ${bridgeError}`);
      return null;
    }
    bridgeError = null;
    bridge = new CoreBridge({ workerUrl: cfg.workerUrl, psk, keyId: cfg.keyId, log, edgeIp: resolveEdgeIp() });
    let restoring = false;
    bridge.onEvent((ev) => {
      // RF-06-03: if the bridge lands in its Error terminal state while the
      // system proxy points at us, give the user's proxy back immediately —
      // a dead carrier must not blackhole their browsing. Reconnecting is
      // transient and deliberately does NOT restore.
      if (ev.type === "state" && tunOn) grace.noteBridgeStatus(ev.state);
      if (ev.type === "state" && ev.state === "error" && proxyOn && !restoring && modeFamily(cfg.proxyMode) === "sysproxy") {
        restoring = true;
        log("bridge entered Error terminal state — restoring system proxy");
        teardownProxy().finally(() => { restoring = false; });
      }
      // Landing identification (M2-4): on each fresh Connected, read /meta
      // through the same edge selection and surface where we landed.
      if (ev.type === "state" && ev.state === "connected") {
        if (!cfg.metaPath) { log("landing identification skipped: meta path not configured (pairing/config channel)"); return; }
        fetchMeta(cfg.workerUrl, { edgeIp: bridge ? bridge.edgeIp : null, path: cfg.metaPath })
          .then((m) => {
            log(`landing: colo ${m.colo || "?"} / country ${m.country || "?"}${bridge && bridge.edgeIp ? ` via edge ${bridge.edgeIp}` : " (default route)"}`);
            if (win && !win.isDestroyed()) win.webContents.send("hollow:meta", { ...m, edgeIp: bridge ? bridge.edgeIp : null });
          })
          .catch(() => log("landing identification failed (/meta unreachable) — continuing without it"));
      }
    });
    bridge.onEvent((ev) => {
      if (win && !win.isDestroyed()) win.webContents.send("hollow:event", ev);
      if (tray) tray.setToolTip(`Hollow — ${ev.state || bridge.state}`);
    });
  }
  return bridge;
}

async function restoreProxyQuietly() {
  if (process.platform !== "win32") return;
  try {
    const r = await sysproxy.restore(log);
    if (r.restored) log(`system proxy restored (mode=${r.mode})`);
    else if (r.mode === "snapshot" || r.mode === "degraded-corrupt-backup") log(`WARNING proxy restore incomplete: ${JSON.stringify(r)}`);
  } catch (e) { log(`proxy restore failed: ${e.message}`); }
  proxyOn = false;
}

// Wait until the bridge reports Connected (or a terminal/timeout outcome).
function waitConnected(b, ms = 30000) {
  if (b.state === "connected") return Promise.resolve(true);
  return new Promise((resolve) => {
    const to = setTimeout(() => { cleanup(); resolve(false); }, ms);
    const on = (ev) => {
      if (ev.type !== "state") return;
      if (ev.state === "connected") { cleanup(); resolve(true); }
      if (ev.state === "error") { cleanup(); resolve(false); }
    };
    const cleanup = () => { clearTimeout(to); };
    b.onEvent(on);
  });
}

async function doConnect() {
  const b = getBridge();
  if (!b) return; // PSK error already logged + surfaced via getState
  await b.startSocks(cfg.socksPort).catch((e) => log(`socks start failed: ${e.message}`));
  if (modeFamily(cfg.proxyMode) === "tun" && process.platform === "win32") {
    // TUN (T-4): helper takeover + bearer pin BEFORE the bridge dials, so
    // the carrier itself can only ever leave via its pinned /32.
    try {
      await enableTun(b);
    } catch (e) {
      log(`TUN enable failed: ${e.message} — not connecting (no silent fallback to a bare SOCKS)`);
      return;
    }
    await b.connect();
    const okTun = await waitConnected(b);
    if (!okTun) {
      log("TUN: carrier did not reach Connected — unwinding the takeover");
      await disableTun();
      return;
    }
    log("TUN mode active (system proxy untouched — routing takeover only)");
    return;
  }
  await b.connect();
  if ((cfg.proxyMode === "global" || cfg.proxyMode === "pac") && process.platform === "win32") {
    // Enable only once traffic can actually flow (M2-2): a proxy pointing at
    // a dead carrier would blackhole the user's browsing.
    const ok = await waitConnected(b);
    if (ok) {
      try {
        if (cfg.proxyMode === "global") {
          await sysproxy.enableGlobal(b.socksPort || cfg.socksPort, log);
          log(`system proxy enabled (global, 127.0.0.1:${b.socksPort || cfg.socksPort})`);
        } else {
          await startPac(b);
          await sysproxy.enablePac(pacServer.url, log);
          log(`system proxy enabled (PAC, ${pacServer.url})`);
        }
        proxyOn = true;
      } catch (e) { log(`system proxy enable failed: ${e.message}`); }
    } else {
      log("system proxy NOT enabled: carrier did not reach Connected");
    }
  }
}

// PAC endpoint (M2-4): serves the live PAC (SOCKS port + direct list are
// read per request, so edits apply without a restart). The URL carries a
// per-install random segment (H-15-01): a generic loopback /proxy.pac URL
// would be a weak fingerprint for the proxy self-heal judgement; the random
// segment makes our written AutoConfigURL installation-specific.
let pacServer = null;
function ensurePacSeg() {
  if (!cfg.pacSeg) {
    cfg = { ...cfg, pacSeg: crypto.randomBytes(8).toString("hex") };
    safeSave();
  }
  return cfg.pacSeg;
}
async function startPac(b) {
  if (pacServer) return pacServer;
  pacServer = await startPacServer({
    preferredPort: cfg.pacPort || 18080,
    log,
    pathSeg: ensurePacSeg(),
    getPac: () => buildPac({ socksPort: (bridge && bridge.socksPort) || cfg.socksPort, directHosts: cfg.directHosts || [] }),
  });
  return pacServer;
}
async function stopPac() {
  if (pacServer) { const s = pacServer; pacServer = null; await s.close().catch(() => {}); }
}
// One teardown for every exit path (disconnect, quit, RF-06-03 error path):
// stop serving PAC, then give the registry back.
async function teardownProxy() {
  await stopPac();
  if (proxyOn) await restoreProxyQuietly();
}
function resolveEdgeIp() {
  if (cfg.edgeMode === "manual") return cfg.preferredEdgeIp || null;
  if (cfg.edgeMode === "auto") return bestEdge(cfg.edgeResults || {});
  return null;
}

async function doDisconnect() {
  if (tunOn) await disableTun();
  await teardownProxy();
  if (bridge) await bridge.disconnect();
}

// ---- TUN mode (T-4 integration, NP-1114-25) ----
// The helper owns the routing takeover; this process owns the plan
// (tun-policy), the grace orchestration (tun-supervisor) and the stale
// action path. Mode families are mutually exclusive: proxyMode "tun"
// never touches the sysproxy path and vice versa.
let helperClient = null, helperWatch = null, helperStatusCache = null, tunOn = false;
const grace = new TunGraceSupervisor({
  monoNow: () => performance.now(),
  onAutoRestore: (reason) => {
    log(`TUN auto-restore: ${reason} — returning the system to its pre-TUN state`);
    disableTun().catch((e) => log(`TUN auto-restore failed: ${e.message}`));
  },
});
function helperExePath() {
  // Packaged: staged next to the app in dist/. Dev: same relative shape.
  return path.join(here, "..", "dist", "hollow-tun-helper.exe");
}
function runRestoreTunCli() {
  return new Promise((resolve) => {
    execFile(helperExePath(), ["--restore-tun"], { timeout: 30000 }, (err) => resolve(!err));
  });
}
function getHelper() {
  if (helperClient) return helperClient;
  helperWatch = new HelperWatch({
    wallNow: () => Date.now(),
    monoNow: () => performance.now(),
    onStale: () => {
      void staleRestoreHandler();
    },
  });
  const staleRestoreHandler = createStaleRestoreHandler({
    isStale: () => helperWatch.check() === "stale",
    pingIpc: () => helperClient ? helperClient.ping() : Promise.resolve(false),
    ipcRestore: async () => {
      if (!helperClient) return false;
      try { await helperClient.request("restore", null, 5000); return true; } catch { return false; }
    },
    spawnRestoreCli: runRestoreTunCli,
    log,
    onOutcome: (r) => { if (win && !win.isDestroyed()) win.webContents.send("hollow:event", { type: "tun-stale", ...r }); },
  });
  helperClient = new HelperClient({
    log,
    onHeartbeat: () => helperWatch.noteHeartbeat(),
    onClose: () => { helperStatusCache = null; },
  });
  return helperClient;
}
async function resolveWorkerIps() {
  try {
    const host = new URL(cfg.workerUrl).hostname;
    const addrs = await dns.resolve4(host);
    return addrs;
  } catch { return []; }
}
async function enableTun(b) {
  const h = getHelper();
  await h.connect();
  const plan = planTunEnable({
    edgeMode: cfg.edgeMode || "default",
    preferredEdgeIp: cfg.preferredEdgeIp || null,
    autoBestIp: bestEdge(cfg.edgeResults || {}),
    candidates: edgeList(),
    resolvedIps: cfg.edgeMode === "default" || !(cfg.edgeMode) ? await resolveWorkerIps() : [],
  });
  for (const s of plan.stripped ?? []) log(`TUN candidate stripped: ${s.ip} (${s.reason})`);
  if (!plan.ok) throw new Error(`TUN plan refused: ${plan.reason}`);
  await h.request("enable_tun", { socksPort: b.socksPort || cfg.socksPort, exclusions: plan.pins });
  b.setBearerLock(plan.pins);
  if (b.state === "connected" || b.state === "reconnecting") b.setEdgeIp(plan.bearerIp);
  tunOn = true;
  grace.noteTunActive(true);
  grace.noteBridgeStatus(b.state);
  log(`TUN enabled: bearer pinned to ${plan.bearerIp}, ${plan.pins.length} exclusions`);
}
async function disableTun() {
  grace.noteTunActive(false);
  tunOn = false;
  if (bridge) bridge.setBearerLock(null);
  const h = getHelper();
  try {
    if (h.connected) await h.request("disable_tun", null, 8000);
  } catch (e) { log(`helper disable_tun failed (${e.message}) — the helper dead-man switch remains as backstop`); }
}
setInterval(() => {
  if (tunOn) {
    grace.check();
    if (helperWatch && helperWatch.check() === "stale") { /* onStale fires inside check() */ }
    const h = getHelper();
    if (h.connected) h.request("status", null, 2000).then((f) => { helperStatusCache = f.result ?? null; }).catch(() => {});
  }
}, 1000);

function createWindow() {
  win = new BrowserWindow({
    width: 560, height: 760, show: false,
    webPreferences: { preload: path.join(here, "preload.cjs"), contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  // Renderer containment (NP-1114-07): no new windows, no navigation away.
  win.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  win.webContents.on("will-navigate", (e, url) => {
    if (!url.startsWith("file://")) e.preventDefault();
  });
  win.loadFile(path.join(here, "renderer", "index.html"));
  win.on("close", (e) => { if (!app.isQuitting) { e.preventDefault(); win.hide(); } }); // close = to tray (plan §4)
  win.once("ready-to-show", () => win.show());
}
function createTray() {
  const icon = nativeImage.createFromPath(path.join(here, "..", "assets", "tray.png"));
  tray = new Tray(icon);
  tray.setToolTip("Hollow — disconnected");
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: "连接", click: () => doConnect().catch((e) => log(`connect failed: ${e.message}`)) },
    { label: "断开", click: () => doDisconnect().catch((e) => log(`disconnect failed: ${e.message}`)) },
    { type: "separator" },
    { label: "显示主窗口", click: () => { if (win) { win.show(); win.focus(); } } },
    { label: "还原代理并退出", click: async () => { app.isQuitting = true; await doDisconnect(); await restoreProxyQuietly(); app.quit(); } },
  ]));
  tray.on("double-click", () => { if (win) win.isVisible() ? win.hide() : win.show(); });
}

// Emergency restore runs BEFORE the single-instance lock (NP-1114-05 side
// item): if the main instance is hung while holding the lock, this short
// process must still be able to put the user's proxy back.
if (process.argv.includes("--restore-proxy")) {
  app.whenReady().then(async () => {
    try {
      const r = await sysproxy.restore((m) => console.log(m));
      console.log(`restore-proxy: ${JSON.stringify(r)}`);
    } catch (e) { console.error(`restore-proxy failed: ${e.message}`); }
    app.quit();
  });
} else if (!app.requestSingleInstanceLock()) {
  app.quit();
}
else {
  app.on("second-instance", (_e, argv) => {
    if (win) { win.show(); win.focus(); }
    // An OS-delivered hollow:// link arrives here: stage it for the SAME
    // in-app confirmation as every other import (correction 4) — never
    // applied silently.
    const link = argv.find((a) => typeof a === "string" && a.startsWith("hollow://"));
    if (link) stageImport(link, "os-link");
  });
  app.on("open-url", (e, url) => { e.preventDefault(); if (url.startsWith("hollow://")) stageImport(url, "os-link"); });
  app.whenReady().then(async () => {
    try { app.setAsDefaultProtocolClient("hollow"); } catch { /* dev/unpacked may refuse */ }
    // First-run PSK (NP-1114-35, closing the NP-1114-23 note): create the
    // PSK at STARTUP when it is simply missing, so the verifier V is
    // copyable from the first frame. A CORRUPT psk.bin is never touched
    // here — loadOrCreatePsk's hard-error discipline stands (NP-1114-07).
    if (pskStatus().state === "missing") {
      try { loadOrCreatePsk(); log("PSK created on first run"); }
      catch (e) { log(`PSK creation failed: ${e.message}`); }
    }
    void tightenPskAcl(log); // startup ACL verification pass (NP-1114-07)
    const st = pskStatus();
    if (st.state === "corrupt") log(`PSK ERROR: psk.bin is corrupt (${st.bytes} bytes) — delete it or re-import a config to recover; nothing was regenerated`);
    if (process.platform === "win32") {
      try {
        const h = await sysproxy.selfHealOnStartup(log);
        if (h.mode && h.mode !== "none" && h.mode !== "not-windows") log(`startup proxy check: ${JSON.stringify(h)}`);
      } catch { /* ignore */ }
    }
    createWindow(); createTray();
    if (process.env.HOLLOW_UI_SMOKE === "1") void runUiSmoke();
    const link = process.argv.find((a) => typeof a === "string" && a.startsWith("hollow://"));
    if (link) setTimeout(() => stageImport(link, "os-link"), 600);
  });
  app.on("window-all-closed", (e) => { if (e) e.preventDefault?.(); }); // tray-resident
  app.on("before-quit", async () => { try { await doDisconnect(); } catch { /* ignore */ } });
}

// Packaged-state UI smoke (NP-1114-35): env-gated self-probe used by CI
// (tools/run-ui-smoke.mjs) against BOTH the source tree and the built
// artifact. Loads the real window, waits for the first render, then
// asserts the bridge is exposed and refresh() rewrote the placeholders.
// Exit code is the verdict; HOLLOW_UI_SMOKE_OUT optionally gets JSON.
async function runUiSmoke() {
  const finish = (code, verdict) => {
    console.log("UI-SMOKE " + JSON.stringify(verdict));
    if (process.env.HOLLOW_UI_SMOKE_OUT) { try { fs.writeFileSync(process.env.HOLLOW_UI_SMOKE_OUT, JSON.stringify(verdict)); } catch { /* ignore */ } }
    app.exit(code);
  };
  try {
    await new Promise((resolve, reject) => {
      const to = setTimeout(() => reject(new Error("did-finish-load timeout")), 20000);
      win.webContents.once("did-finish-load", () => { clearTimeout(to); resolve(); });
    });
    await new Promise((r) => setTimeout(r, 900)); // first refresh() settles
    const probe = await win.webContents.executeJavaScript(`({
      hollow: typeof window.hollow,
      state: document.getElementById("state").textContent,
      verifier: document.getElementById("verifier").textContent,
    })`);
    const healthy = probe.hollow === "object" && probe.state !== "状态：—" && probe.verifier !== "—";
    finish(healthy ? 0 : 1, { ...probe, healthy });
  } catch (e) {
    finish(2, { healthy: false, error: String((e && e.message) || e) });
  }
}

ipcMain.handle("hollow:getState", () => ({
  tun: tunStatusView({ proxyMode: cfg.proxyMode, helperAlive: !!(helperClient && helperClient.connected && helperWatch && !helperWatch.stale && helperWatch.gaps() !== null), helperStatus: helperStatusCache, graceRemainingMs: grace.graceRemainingMs() }),
  netcfgBackup: (() => { try { const r = readNetcfgBackup(configDir()); return { kind: r.kind, problems: r.problems }; } catch { return { kind: "corrupt", problems: ["read failed"] }; } })(),
  ...(bridge ? bridge.snapshot() : { state: bridgeError ? "error" : "disconnected", detail: bridgeError || "", connectedSince: null, socksPort: null, queuedNow: 0, stats: null }),
  logs: logs.slice(-80),
  settings: { workerUrl: cfg.workerUrl, socksPort: cfg.socksPort, proxyMode: cfg.proxyMode, configDir: configDir(), directHosts: cfg.directHosts || [], edgeMode: cfg.edgeMode || "default", preferredEdgeIp: cfg.preferredEdgeIp || null, metaPath: cfg.metaPath || "", edgesPath: cfg.edgesPath || "" },
  psk: pskStatus(),
  pskFileExists: fs.existsSync(path.join(configDir(), "psk.bin")),
}));
ipcMain.handle("hollow:connect", async () => { await doConnect(); return bridge.snapshot(); });
ipcMain.handle("hollow:disconnect", async () => { await doDisconnect(); return bridge ? bridge.snapshot() : { state: "disconnected" }; });
ipcMain.handle("hollow:saveSettings", async (_e, s) => {
  if (typeof s.workerUrl === "string" && s.workerUrl !== cfg.workerUrl) {
    // Same validation as the import path (NP-1114-12): wss only, ws only for
    // localhost — the settings page must not be a laxer door than pairing.
    try {
      validateWorkerUrl(s.workerUrl);
      cfg = { ...cfg, workerUrl: s.workerUrl };
      log(`settings saved: workerUrl=${s.workerUrl}`);
    } catch (e) { log(`settings workerUrl rejected: ${e.message} (kept ${cfg.workerUrl})`); }
  }
  if (["off", "global", "pac", "tun"].includes(s.proxyMode)) { cfg = { ...cfg, proxyMode: s.proxyMode }; log(`settings saved: proxyMode=${s.proxyMode}`); }
  if (Array.isArray(s.directHosts)) {
    cfg = { ...cfg, directHosts: s.directHosts.map((h) => String(h).trim().toLowerCase()).filter(Boolean).slice(0, 200) };
    log(`settings saved: ${cfg.directHosts.length} direct hosts`);
  }
  // Endpoint paths (NP-1114-15): manual entry is the other half of the
  // config channel (the pairing payload is the first). Values are validated
  // like payload paths and never echoed to the log.
  for (const key of ["metaPath", "edgesPath"]) {
    if (typeof s[key] === "string") {
      const v = s[key].trim();
      if (v === "") { cfg = { ...cfg, [key]: null }; log(`settings saved: ${key} cleared`); }
      else {
        try { validateHttpPath(v, key); cfg = { ...cfg, [key]: v }; log(`settings saved: ${key} set`); }
        catch (e) { log(`settings ${key} rejected: ${e.message}`); }
      }
    }
  }
  safeSave();
  // Apply on the next connect: drop a non-connected bridge so it rebuilds.
  if (bridge && (bridge.state === "disconnected" || bridge.state === "error")) bridge = null;
  return { workerUrl: cfg.workerUrl, proxyMode: cfg.proxyMode, directHosts: cfg.directHosts };
});

// ---- Edge-IP selection (M2-4) ----
function edgeList() { return cfg.edgeListCache || BUILTIN_EDGES; }
ipcMain.handle("hollow:getEdges", () => ({
  edges: edgeList(), results: cfg.edgeResults || {},
  edgeMode: cfg.edgeMode || "default", preferredEdgeIp: cfg.preferredEdgeIp || null,
  activeEdgeIp: bridge ? bridge.edgeIp : resolveEdgeIp(),
}));
ipcMain.handle("hollow:refreshEdges", async () => {
  try {
    const list = await fetchRemoteEdges(cfg.workerUrl, { path: cfg.edgesPath });
    cfg = { ...cfg, edgeListCache: list };
    safeSave();
    log(`edge list refreshed from /edges.json (${list.length} candidates)`);
    return { ok: true, edges: list };
  } catch (e) {
    log(`edge list refresh failed (${e.message}) — keeping the built-in list`);
    return { ok: false, error: e.message, edges: edgeList() };
  }
});
ipcMain.handle("hollow:measureEdges", async () => {
  let psk;
  try { psk = loadOrCreatePsk(); } catch (e) { return { ok: false, error: e.message }; }
  log("edge measurement started (3 handshakes per candidate)");
  const results = await measureEdges({
    workerUrl: cfg.workerUrl, psk, keyId: cfg.keyId, edges: edgeList(), metaPath: cfg.metaPath,
    onProgress: (ip, r) => { if (win && !win.isDestroyed()) win.webContents.send("hollow:edgeProgress", { ip, result: r }); },
  });
  cfg = { ...cfg, edgeResults: results };
  safeSave();
  if (bridge) bridge.setEdgeIp(resolveEdgeIp());
  log(`edge measurement done: best=${bestEdge(results) || "none"}`);
  return { ok: true, results };
});
ipcMain.handle("hollow:setEdgeSelection", (_e, { mode, ip }) => {
  if (["default", "auto", "manual"].includes(mode)) cfg = { ...cfg, edgeMode: mode };
  if (typeof ip === "string" && ip) cfg = { ...cfg, preferredEdgeIp: ip };
  safeSave();
  if (bridge) bridge.setEdgeIp(resolveEdgeIp());
  log(`edge selection: mode=${cfg.edgeMode}${cfg.edgeMode === "manual" ? ` ip=${cfg.preferredEdgeIp}` : ""} (applies to the next carrier)`);
  return { edgeMode: cfg.edgeMode, preferredEdgeIp: cfg.preferredEdgeIp, activeEdgeIp: resolveEdgeIp() };
});

// ---- Pairing & import (M2-3) ----
// The staged payload lives ONLY in this variable (never disk, never logs)
// until the user confirms in the UI. Applying writes the PSK (if any) and
// the config, then drops a non-connected bridge so the next connect uses it.
let pendingImport = null;
function currentPskExists() {
  try { return loadPsk() !== null; } catch { return true; } // corrupt counts as exists
}
function stageImport(text, source) {
  try {
    const parsed = parseAnyPayload(text);
    pendingImport = parsed;
    const preview = previewOf(parsed, { currentPskExists: currentPskExists(), verifierOf: verifierHex });
    if (win && !win.isDestroyed()) {
      win.webContents.send("hollow:import", { preview, source });
      win.show(); win.focus();
    }
    log(`import staged from ${source}: awaiting in-app confirmation`);
    return { ok: true, preview };
  } catch (e) {
    log(`import rejected (${source}): ${e.message}`); // message only — never the payload
    return { ok: false, error: e.message };
  }
}
function decodeImageToPayload(img) {
  if (!img || img.isEmpty()) throw new Error("no image");
  const size = img.getSize();
  const rgba = bgraToRgba(img.toBitmap());
  return decodeQrFromPixels(rgba, size.width, size.height);
}

ipcMain.handle("hollow:importPreview", (_e, { text }) => stageImport(String(text ?? ""), "paste"));
ipcMain.handle("hollow:importFromFile", async () => {
  const r = await dialog.showOpenDialog(win, { properties: ["openFile"], filters: [{ name: "Hollow config", extensions: ["json"] }] });
  if (r.canceled || !r.filePaths[0]) return { ok: false, error: "cancelled" };
  return stageImport(fs.readFileSync(r.filePaths[0], "utf8"), "file");
});
ipcMain.handle("hollow:importFromQrFile", async () => {
  const r = await dialog.showOpenDialog(win, { properties: ["openFile"], filters: [{ name: "Images", extensions: ["png", "jpg", "jpeg", "bmp", "webp"] }] });
  if (r.canceled || !r.filePaths[0]) return { ok: false, error: "cancelled" };
  try { return stageImport(decodeImageToPayload(nativeImage.createFromPath(r.filePaths[0])), "qr-file"); }
  catch (e) { return { ok: false, error: e.message }; }
});
ipcMain.handle("hollow:importFromClipboard", () => {
  try { return stageImport(decodeImageToPayload(clipboard.readImage()), "qr-clipboard"); }
  catch (e) { return { ok: false, error: e.message }; }
});
ipcMain.handle("hollow:importConfirm", async () => {
  if (!pendingImport) return { ok: false, error: "nothing staged" };
  const p = pendingImport; pendingImport = null;
  if (p.psk) { writePsk(p.psk); await tightenPskAcl(log); }
  cfg = { ...cfg, workerUrl: p.workerUrl, keyId: p.keyId };
  // Endpoint paths ride the pairing channel (NP-1114-15): applied when the
  // payload carries them, values never logged.
  if (p.metaPath) cfg = { ...cfg, metaPath: p.metaPath };
  if (p.edgesPath) cfg = { ...cfg, edgesPath: p.edgesPath };
  safeSave();
  if (bridge && (bridge.state === "disconnected" || bridge.state === "error")) bridge = null;
  bridgeError = null;
  log("import applied (payload not logged)");
  return { ok: true };
});
ipcMain.handle("hollow:importCancel", () => { pendingImport = null; log("import cancelled by user"); return { ok: true }; });
ipcMain.handle("hollow:exportToFile", async (_e, { includePsk }) => {
  let psk = null;
  if (includePsk) { try { psk = loadPsk(); } catch { return { ok: false, error: "PSK file is corrupt" }; } }
  const obj = buildExportObject({ workerUrl: cfg.workerUrl, keyId: cfg.keyId, psk, metaPath: cfg.metaPath, edgesPath: cfg.edgesPath });
  const r = await dialog.showSaveDialog(win, { defaultPath: includePsk ? "hollow-config-with-key.json" : "hollow-config.json", filters: [{ name: "Hollow config", extensions: ["json"] }] });
  if (r.canceled || !r.filePath) return { ok: false, error: "cancelled" };
  fs.writeFileSync(r.filePath, JSON.stringify(obj, null, 2) + "\n");
  log(`config exported (${includePsk ? "with" : "without"} PSK)`);
  return { ok: true, file: path.basename(r.filePath) };
});
ipcMain.handle("hollow:qrOwnConfig", async (_e, { includePsk }) => {
  let psk = null;
  if (includePsk) { try { psk = loadPsk(); } catch { return { ok: false, error: "PSK file is corrupt" }; } }
  const link = buildLink({ workerUrl: cfg.workerUrl, keyId: cfg.keyId, psk, metaPath: cfg.metaPath, edgesPath: cfg.edgesPath });
  return { ok: true, dataUrl: await qrDataUrl(link) };
});
ipcMain.handle("hollow:copyVerifier", () => {
  const st = pskStatus();
  if (st.verifier) clipboard.writeText(st.verifier);
  return { ok: !!st.verifier };
});
ipcMain.handle("hollow:testConnection", async () => {
  // A real handshake against the configured Worker with the current PSK —
  // the pairing acceptance probe. Uses a throwaway client, not the bridge.
  let psk;
  try { psk = loadOrCreatePsk(); } catch (e) { return { ok: false, error: e.message }; }
  const t0 = Date.now();
  let transport = null, client = null, timer = null;
  try {
    const { HollowClient } = await import("../vendor/shared/client-core.js");
    const { connectWs } = await import("../vendor/cli/src/ws-client.js");
    const work = (async () => {
      transport = await connectWs(cfg.workerUrl, { userAgent: "HollowClient/0.1" });
      client = new HollowClient({ transport, psk, keyId: cfg.keyId });
      await client.handshake();
    })();
    work.catch(() => {}); // the race owns the outcome; silence late rejections
    await Promise.race([
      work,
      new Promise((_, rej) => { timer = setTimeout(() => rej(new Error("handshake timeout (15s)")), 15000); }),
    ]);
    return { ok: true, ms: Date.now() - t0 };
  } catch (e) {
    return { ok: false, error: e.message, ms: Date.now() - t0 };
  } finally {
    clearTimeout(timer);
    // NP-1114-12: close the underlying connection on EVERY path — on timeout
    // the attempt may still be mid-flight and must not leave a dangling socket.
    try { client?.close(); } catch { /* ignore */ }
    try { transport?.close(); } catch { /* ignore */ }
  }
});
