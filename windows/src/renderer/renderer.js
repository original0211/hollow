// Renderer (M2-1): state card + duration ticker + counters + queue banner +
// minimal settings. All data arrives via the preload whitelist bridge.
const $ = (id) => document.getElementById(id);
const logEl = $("log");
let snapshot = { state: "disconnected", connectedSince: null, stats: null, socksPort: null, queuedNow: 0, detail: "" };

function appendLog(line) {
  logEl.textContent += line + "\n";
  logEl.scrollTop = logEl.scrollHeight;
}
function fmtDuration(ms) {
  const s = Math.floor(ms / 1000);
  const hh = String(Math.floor(s / 3600)).padStart(2, "0");
  const mm = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
  const ss = String(s % 60).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}
function render() {
  $("state").textContent = "状态：" + snapshot.state;
  $("detail").textContent = snapshot.detail || "";
  const parts = [];
  if (snapshot.connectedSince) parts.push("已连接 " + fmtDuration(Date.now() - snapshot.connectedSince));
  if (snapshot.socksPort) parts.push("SOCKS 127.0.0.1:" + snapshot.socksPort);
  if (snapshot.stats) parts.push(`今日 载体 ${snapshot.stats.carriers} · 流 ${snapshot.stats.streams}`);
  $("stats").textContent = parts.join(" · ");
  $("queued-banner").style.display = snapshot.queuedNow > 0 ? "block" : "none";
}
async function refresh() {
  const s = await window.hollow.getState();
  snapshot = { ...snapshot, ...s };
  if (Array.isArray(s.logs)) { logEl.textContent = ""; s.logs.forEach(appendLog); }
  if (s.settings) $("worker-url").value = s.settings.workerUrl || "";
  if (s.psk) {
    $("psk-status").textContent = s.psk.exists
      ? `PSK 文件：已存在（${s.psk.bytes} 字节，${s.settings ? s.settings.configDir : ""}）`
      : "PSK 文件：不存在（首次连接时生成；完整配对在 M2-3）";
    $("verifier").textContent = s.psk.verifier || "—";
  }
  render();
}
$("btn-connect").addEventListener("click", async () => { try { await window.hollow.connect(); } catch (e) { appendLog("connect error: " + e.message); } refresh(); });
$("btn-disconnect").addEventListener("click", async () => { try { await window.hollow.disconnect(); } catch (e) { appendLog("disconnect error: " + e.message); } refresh(); });
$("btn-save").addEventListener("click", async () => {
  const r = await window.hollow.saveSettings({ workerUrl: $("worker-url").value.trim() });
  appendLog("settings saved: " + r.workerUrl);
});
window.hollow.onLog(appendLog);
window.hollow.onEvent((ev) => {
  if (ev.type === "state") { snapshot.state = ev.state; snapshot.detail = ev.detail || ""; if (ev.state !== "connected") snapshot.connectedSince = null; refresh(); }
  if (ev.type === "stats") { snapshot.stats = ev.stats; render(); }
  if (ev.type === "socks") { snapshot.socksPort = ev.socksPort; render(); }
  if (ev.type === "queued") { snapshot.queuedNow = ev.queuedNow; render(); }
});
setInterval(render, 1000);
refresh();
