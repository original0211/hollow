// Renderer shell (NP-1114-01): render state, forward two actions, stream logs.
const $ = (id) => document.getElementById(id);
const logEl = $("log");
function appendLog(line) {
  logEl.textContent += line + "\n";
  logEl.scrollTop = logEl.scrollHeight;
}
async function refresh() {
  const s = await window.hollow.getState();
  $("state").textContent = "状态：" + s.state;
  $("stats").textContent = s.stats ? `今日 载体 ${s.stats.carriers} · SOCKS ${s.socksPort || "—"}` : "";
  $("verifier").textContent = s.verifier || "—";
  if (Array.isArray(s.logs)) { logEl.textContent = ""; s.logs.forEach(appendLog); }
}
$("btn-connect").addEventListener("click", async () => { try { await window.hollow.connect(); } catch (e) { appendLog("connect error: " + e.message); } refresh(); });
$("btn-disconnect").addEventListener("click", async () => { try { await window.hollow.disconnect(); } catch (e) { appendLog("disconnect error: " + e.message); } refresh(); });
window.hollow.onLog(appendLog);
refresh();
