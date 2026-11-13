// Preload whitelist bridge: exactly these actions plus log/event streams —
// no Node, no filesystem (plan §1).
import { contextBridge, ipcRenderer } from "electron";

contextBridge.exposeInMainWorld("hollow", {
  getState: () => ipcRenderer.invoke("hollow:getState"),
  connect: () => ipcRenderer.invoke("hollow:connect"),
  disconnect: () => ipcRenderer.invoke("hollow:disconnect"),
  saveSettings: (s) => ipcRenderer.invoke("hollow:saveSettings", s),
  onLog: (cb) => ipcRenderer.on("hollow:log", (_e, line) => cb(line)),
  onEvent: (cb) => ipcRenderer.on("hollow:event", (_e, ev) => cb(ev)),
});
