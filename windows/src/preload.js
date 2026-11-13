// Preload whitelist bridge: exactly these actions plus log/event/import
// streams — no Node, no filesystem (plan §1).
import { contextBridge, ipcRenderer } from "electron";

contextBridge.exposeInMainWorld("hollow", {
  getState: () => ipcRenderer.invoke("hollow:getState"),
  connect: () => ipcRenderer.invoke("hollow:connect"),
  disconnect: () => ipcRenderer.invoke("hollow:disconnect"),
  saveSettings: (s) => ipcRenderer.invoke("hollow:saveSettings", s),
  // pairing & import (M2-3)
  testConnection: () => ipcRenderer.invoke("hollow:testConnection"),
  copyVerifier: () => ipcRenderer.invoke("hollow:copyVerifier"),
  importPreview: (text) => ipcRenderer.invoke("hollow:importPreview", { text }),
  importFromFile: () => ipcRenderer.invoke("hollow:importFromFile"),
  importFromQrFile: () => ipcRenderer.invoke("hollow:importFromQrFile"),
  importFromClipboard: () => ipcRenderer.invoke("hollow:importFromClipboard"),
  importConfirm: () => ipcRenderer.invoke("hollow:importConfirm"),
  importCancel: () => ipcRenderer.invoke("hollow:importCancel"),
  exportToFile: (includePsk) => ipcRenderer.invoke("hollow:exportToFile", { includePsk }),
  qrOwnConfig: (includePsk) => ipcRenderer.invoke("hollow:qrOwnConfig", { includePsk }),
  onLog: (cb) => ipcRenderer.on("hollow:log", (_e, line) => cb(line)),
  onEvent: (cb) => ipcRenderer.on("hollow:event", (_e, ev) => cb(ev)),
  onImport: (cb) => ipcRenderer.on("hollow:import", (_e, data) => cb(data)),
});
