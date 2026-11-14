// NP-1114-35 repro harness: loads the REAL preload + renderer with the
// EXACT production webPreferences (main.js createWindow) and stub IPC
// handlers, then asserts bridge exposure + first-frame render.
// Usage: electron --no-sandbox repro-harness.mjs <windowsDir>
// Exit 0 = healthy, 1 = defect reproduced.
import { app, BrowserWindow, ipcMain } from "electron";
import path from "node:path";

const windowsDir = process.argv[process.argv.length - 1];
const stateStub = {
  state: "disconnected", detail: "", logs: [],
  settings: { workerUrl: "wss://example.invalid/", proxyMode: "off", directHosts: [], metaPath: "", edgesPath: "", configDir: "/stub" },
  psk: { exists: true, bytes: 32, verifier: "STUBVERIFIER", state: "ok" },
};
for (const ch of ["getState", "connect", "disconnect", "testConnection", "copyVerifier",
  "importPreview", "importFromFile", "importFromQrFile", "importFromClipboard",
  "importConfirm", "importCancel", "exportToFile", "qrOwnConfig",
  "refreshEdges", "measureEdges", "setEdgeSelection"]) {
  ipcMain.handle("hollow:" + ch, async () => (ch === "getState" ? stateStub : { ok: true }));
}
ipcMain.handle("hollow:getEdges", async () => ({ edges: [], results: {}, edgeMode: "default", preferredEdgeIp: null }));
ipcMain.handle("hollow:saveSettings", async (_e, s) => s);

const consoleErrors = [];
app.whenReady().then(async () => {
  const win = new BrowserWindow({
    width: 560, height: 760, show: false,
    webPreferences: { preload: path.join(windowsDir, "src", "preload.cjs"), contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  win.webContents.on("console-message", (_e, level, message) => {
    if (level >= 2) consoleErrors.push(message);
  });
  await win.loadFile(path.join(windowsDir, "src", "renderer", "index.html"));
  await new Promise((r) => setTimeout(r, 900));
  const probe = await win.webContents.executeJavaScript(`({
    hollowType: typeof window.hollow,
    stateText: document.getElementById("state").textContent,
    verifierText: document.getElementById("verifier").textContent,
  })`);
  // A click on the primary button must not throw into the void.
  await win.webContents.executeJavaScript(`document.getElementById("btn-connect").click()`);
  await new Promise((r) => setTimeout(r, 300));
  const verdict = {
    ...probe,
    consoleErrors,
    healthy: probe.hollowType === "object" && probe.stateText !== "状态：—",
  };
  console.log("REPRO-VERDICT " + JSON.stringify(verdict, null, 1));
  app.exit(verdict.healthy ? 0 : 1);
});
