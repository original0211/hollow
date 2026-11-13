// Preload whitelist bridge: the renderer gets exactly these three actions
// plus the log stream — no Node, no filesystem (plan §1).
import { contextBridge, ipcRenderer } from "electron";

contextBridge.exposeInMainWorld("hollow", {
  getState: () => ipcRenderer.invoke("hollow:getState"),
  connect: () => ipcRenderer.invoke("hollow:connect"),
  disconnect: () => ipcRenderer.invoke("hollow:disconnect"),
  onLog: (cb) => ipcRenderer.on("hollow:log", (_e, line) => cb(line)),
});
