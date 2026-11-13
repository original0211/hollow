// Electron main (M2-1, NP-1114-03): single instance, tray-resident; the
// CoreBridge owns protocol state, SOCKS lifecycle follows connect/disconnect,
// and every exit path disconnects the bridge (closing the SOCKS port) and
// restores the system proxy. Renderer gets state via IPC + pushed events.
import { app, BrowserWindow, Tray, Menu, ipcMain, nativeImage } from "electron";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CoreBridge } from "./core-bridge.js";
import { loadConfig, saveConfig, loadOrCreatePsk, pskStatus, configDir } from "./config.js";
import * as sysproxy from "./sysproxy.js";

const here = path.dirname(fileURLToPath(import.meta.url));
let cfg = loadConfig();
const logs = [];
function log(m) {
  const line = `${new Date().toISOString()} ${m}`;
  logs.push(line); if (logs.length > 300) logs.shift();
  if (win && !win.isDestroyed()) win.webContents.send("hollow:log", line);
}

let win = null, tray = null, bridge = null, proxyOn = false;

function getBridge() {
  if (!bridge) {
    bridge = new CoreBridge({ workerUrl: cfg.workerUrl, psk: loadOrCreatePsk(), keyId: cfg.keyId, log });
    bridge.onEvent((ev) => {
      if (win && !win.isDestroyed()) win.webContents.send("hollow:event", ev);
      if (tray) tray.setToolTip(`Hollow — ${ev.state || bridge.state}`);
    });
  }
  return bridge;
}

async function restoreProxyQuietly() {
  if (process.platform !== "win32") return;
  try { if (await sysproxy.restore()) log("system proxy restored"); } catch (e) { log(`proxy restore failed: ${e.message}`); }
  proxyOn = false;
}

async function doConnect() {
  const b = getBridge();
  await b.startSocks(cfg.socksPort).catch((e) => log(`socks start failed: ${e.message}`));
  await b.connect();
  if (cfg.proxyMode === "global" && process.platform === "win32") {
    try { await sysproxy.enableGlobal(b.socksPort || cfg.socksPort); proxyOn = true; log("system proxy enabled (global)"); }
    catch (e) { log(`system proxy enable failed: ${e.message}`); }
  }
}
async function doDisconnect() {
  if (proxyOn) await restoreProxyQuietly();
  if (bridge) await bridge.disconnect();
}

function createWindow() {
  win = new BrowserWindow({
    width: 560, height: 680, show: false,
    webPreferences: { preload: path.join(here, "preload.js"), contextIsolation: true, nodeIntegration: false },
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

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) { app.quit(); }
else {
  app.on("second-instance", () => { if (win) { win.show(); win.focus(); } });
  app.whenReady().then(async () => {
    if (process.argv.includes("--restore-proxy")) { await restoreProxyQuietly(); app.quit(); return; }
    if (process.platform === "win32") { try { if (await sysproxy.selfHealOnStartup()) log("startup self-heal: proxy restored"); } catch { /* ignore */ } }
    createWindow(); createTray();
  });
  app.on("window-all-closed", (e) => { if (e) e.preventDefault?.(); }); // tray-resident
  app.on("before-quit", async () => { try { await doDisconnect(); } catch { /* ignore */ } });
}

ipcMain.handle("hollow:getState", () => ({
  ...(bridge ? bridge.snapshot() : { state: "disconnected", detail: "", connectedSince: null, socksPort: null, queuedNow: 0, stats: null }),
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
