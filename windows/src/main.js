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
import { fileURLToPath } from "node:url";
import { CoreBridge } from "./core-bridge.js";
import { loadConfig, saveConfig, loadOrCreatePsk, loadPsk, writePsk, tightenPskAcl, verifierHex, PskCorruptError, pskStatus, configDir } from "./config.js";
import { parseAnyPayload, previewOf, buildExportObject, buildLink, qrDataUrl, bgraToRgba, decodeQrFromPixels } from "./pairing.js";
import * as sysproxy from "./sysproxy.js";

const here = path.dirname(fileURLToPath(import.meta.url));
let cfg = loadConfig();
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
    bridge = new CoreBridge({ workerUrl: cfg.workerUrl, psk, keyId: cfg.keyId, log });
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
  await b.connect();
  if (cfg.proxyMode === "global" && process.platform === "win32") {
    // Enable only once traffic can actually flow (M2-2): a proxy pointing at
    // a dead carrier would blackhole the user's browsing.
    const ok = await waitConnected(b);
    if (ok) {
      try { await sysproxy.enableGlobal(b.socksPort || cfg.socksPort, log); proxyOn = true; log(`system proxy enabled (global, 127.0.0.1:${b.socksPort || cfg.socksPort})`); }
      catch (e) { log(`system proxy enable failed: ${e.message}`); }
    } else {
      log("system proxy NOT enabled: carrier did not reach Connected");
    }
  }
}
async function doDisconnect() {
  if (proxyOn) await restoreProxyQuietly();
  if (bridge) await bridge.disconnect();
}

function createWindow() {
  win = new BrowserWindow({
    width: 560, height: 760, show: false,
    webPreferences: { preload: path.join(here, "preload.js"), contextIsolation: true, nodeIntegration: false, sandbox: true },
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
    const link = process.argv.find((a) => typeof a === "string" && a.startsWith("hollow://"));
    if (link) setTimeout(() => stageImport(link, "os-link"), 600);
  });
  app.on("window-all-closed", (e) => { if (e) e.preventDefault?.(); }); // tray-resident
  app.on("before-quit", async () => { try { await doDisconnect(); } catch { /* ignore */ } });
}

ipcMain.handle("hollow:getState", () => ({
  ...(bridge ? bridge.snapshot() : { state: bridgeError ? "error" : "disconnected", detail: bridgeError || "", connectedSince: null, socksPort: null, queuedNow: 0, stats: null }),
  logs: logs.slice(-80),
  settings: { workerUrl: cfg.workerUrl, socksPort: cfg.socksPort, proxyMode: cfg.proxyMode, configDir: configDir() },
  psk: pskStatus(),
  pskFileExists: fs.existsSync(path.join(configDir(), "psk.bin")),
}));
ipcMain.handle("hollow:connect", async () => { await doConnect(); return bridge.snapshot(); });
ipcMain.handle("hollow:disconnect", async () => { await doDisconnect(); return bridge ? bridge.snapshot() : { state: "disconnected" }; });
ipcMain.handle("hollow:saveSettings", async (_e, { workerUrl }) => {
  if (typeof workerUrl === "string" && /^wss?:\/\//.test(workerUrl)) {
    cfg = { ...cfg, workerUrl };
    saveConfig(cfg);
    // Apply on the next connect: drop a non-connected bridge so it rebuilds.
    if (bridge && (bridge.state === "disconnected" || bridge.state === "error")) bridge = null;
    log(`settings saved: workerUrl=${workerUrl}`);
  }
  return { workerUrl: cfg.workerUrl };
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
  saveConfig(cfg);
  if (bridge && (bridge.state === "disconnected" || bridge.state === "error")) bridge = null;
  bridgeError = null;
  log("import applied (payload not logged)");
  return { ok: true };
});
ipcMain.handle("hollow:importCancel", () => { pendingImport = null; log("import cancelled by user"); return { ok: true }; });
ipcMain.handle("hollow:exportToFile", async (_e, { includePsk }) => {
  let psk = null;
  if (includePsk) { try { psk = loadPsk(); } catch { return { ok: false, error: "PSK file is corrupt" }; } }
  const obj = buildExportObject({ workerUrl: cfg.workerUrl, keyId: cfg.keyId, psk });
  const r = await dialog.showSaveDialog(win, { defaultPath: includePsk ? "hollow-config-with-key.json" : "hollow-config.json", filters: [{ name: "Hollow config", extensions: ["json"] }] });
  if (r.canceled || !r.filePath) return { ok: false, error: "cancelled" };
  fs.writeFileSync(r.filePath, JSON.stringify(obj, null, 2) + "\n");
  log(`config exported (${includePsk ? "with" : "without"} PSK)`);
  return { ok: true, file: path.basename(r.filePath) };
});
ipcMain.handle("hollow:qrOwnConfig", async (_e, { includePsk }) => {
  let psk = null;
  if (includePsk) { try { psk = loadPsk(); } catch { return { ok: false, error: "PSK file is corrupt" }; } }
  const link = buildLink({ workerUrl: cfg.workerUrl, keyId: cfg.keyId, psk });
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
  try {
    const { HollowClient } = await import("../vendor/shared/client-core.js");
    const { connectWs } = await import("../vendor/cli/src/ws-client.js");
    const transport = await connectWs(cfg.workerUrl, { userAgent: "HollowClient/0.1" });
    const client = new HollowClient({ transport, psk, keyId: cfg.keyId });
    await Promise.race([
      client.handshake(),
      new Promise((_, rej) => setTimeout(() => rej(new Error("handshake timeout (15s)")), 15000)),
    ]);
    client.close();
    return { ok: true, ms: Date.now() - t0 };
  } catch (e) {
    return { ok: false, error: e.message, ms: Date.now() - t0 };
  }
});
