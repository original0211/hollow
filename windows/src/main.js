// Electron main (NP-1114-01 skeleton): single instance, tray-resident,
// main window is a status shell; all protocol work lives in CoreBridge.
// Exit exists only in the tray menu and always restores the system proxy.
import { app, BrowserWindow, Tray, Menu, ipcMain, nativeImage } from "electron";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CoreBridge } from "./core-bridge.js";
import { loadConfig, loadOrCreatePsk, verifierHex } from "./config.js";
import * as sysproxy from "./sysproxy.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const cfg = loadConfig();
const logs = [];
function log(m) {
  const line = `${new Date().toISOString()} ${m}`;
  logs.push(line); if (logs.length > 300) logs.shift();
  if (win && !win.isDestroyed()) win.webContents.send("hollow:log", line);
}

let win = null, tray = null, bridge = null, proxyOn = false;

async function restoreProxyQuietly() {
  if (process.platform !== "win32") return;
  try { if (await sysproxy.restore()) log("system proxy restored"); } catch (e) { log(`proxy restore failed: ${e.message}`); }
  proxyOn = false;
}

async function doConnect() {
  bridge = bridge || new CoreBridge({ workerUrl: cfg.workerUrl, psk: loadOrCreatePsk(), keyId: cfg.keyId, log });
  await bridge.connect();
  await bridge.startSocks(cfg.socksPort);
  if (cfg.proxyMode === "global") { await sysproxy.enableGlobal(cfg.socksPort); proxyOn = true; log("system proxy enabled (global)"); }
}
async function doDisconnect() {
  if (proxyOn) await restoreProxyQuietly();
  if (bridge) await bridge.disconnect();
}

function createWindow() {
  win = new BrowserWindow({
    width: 560, height: 640, show: false,
    webPreferences: { preload: path.join(here, "preload.js"), contextIsolation: true, nodeIntegration: false },
  });
  win.loadFile(path.join(here, "renderer", "index.html"));
  win.on("close", (e) => { if (!app.isQuitting) { e.preventDefault(); win.hide(); } }); // close = to tray (plan §4)
  win.once("ready-to-show", () => win.show());
}
function createTray() {
  const icon = nativeImage.createFromPath(path.join(here, "..", "assets", "tray.png"));
  tray = new Tray(icon);
  tray.setToolTip("Hollow");
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: "连接", click: () => doConnect().catch((e) => log(`connect failed: ${e.message}`)) },
    { label: "断开", click: () => doDisconnect().catch((e) => log(`disconnect failed: ${e.message}`)) },
    { type: "separator" },
    { label: "显示主窗口", click: () => { if (win) { win.show(); win.focus(); } } },
    { label: "还原代理并退出", click: async () => { app.isQuitting = true; await restoreProxyQuietly(); app.quit(); } },
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
  app.on("window-all-closed", (e) => { /* tray-resident: never quit from windows */ if (e) e.preventDefault?.(); });
}

ipcMain.handle("hollow:getState", () => ({ ...(bridge ? bridge.snapshot() : { state: "disconnected", socksPort: null, stats: null }), logs: logs.slice(-50), verifier: verifierHex(loadOrCreatePsk()) }));
ipcMain.handle("hollow:connect", async () => { await doConnect(); return bridge.snapshot(); });
ipcMain.handle("hollow:disconnect", async () => { await doDisconnect(); return bridge ? bridge.snapshot() : { state: "disconnected" }; });
