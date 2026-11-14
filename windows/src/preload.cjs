// Preload whitelist bridge: exactly these actions plus log/event/import
// COMMONJS ON PURPOSE (NP-1114-35): with sandbox:true the preload loader
// parses this file as a classic script — an ESM `import` here is a
// SyntaxError that kills the whole preload, leaving window.hollow
// undefined and the UI dead. Never convert back to ESM; the ui-smoke
// guard (tools/run-ui-smoke.mjs) fails the build if this regresses.
// streams — no Node, no filesystem (plan §1).
const { contextBridge, ipcRenderer } = require("electron");

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
  // edge selection (M2-4)
  getEdges: () => ipcRenderer.invoke("hollow:getEdges"),
  refreshEdges: () => ipcRenderer.invoke("hollow:refreshEdges"),
  measureEdges: () => ipcRenderer.invoke("hollow:measureEdges"),
  setEdgeSelection: (sel) => ipcRenderer.invoke("hollow:setEdgeSelection", sel),
  onLog: (cb) => ipcRenderer.on("hollow:log", (_e, line) => cb(line)),
  onEvent: (cb) => ipcRenderer.on("hollow:event", (_e, ev) => cb(ev)),
  onImport: (cb) => ipcRenderer.on("hollow:import", (_e, data) => cb(data)),
  onMeta: (cb) => ipcRenderer.on("hollow:meta", (_e, data) => cb(data)),
  onEdgeProgress: (cb) => ipcRenderer.on("hollow:edgeProgress", (_e, data) => cb(data)),
});
