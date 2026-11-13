// Renderer (M2-3): state card, pairing page, import/export with the in-app
// confirmation step. Untrusted strings (import previews, worker URLs) are
// rendered exclusively via textContent — never innerHTML.
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
    $("psk-status").textContent = s.psk.state === "corrupt"
      ? "⚠ PSK 文件已损坏——应用不会自动重建；请重新导入配置或删除 psk.bin 后重启"
      : s.psk.exists
        ? `PSK 文件：正常（${s.psk.bytes} 字节，${s.settings ? s.settings.configDir : ""}）`
        : "PSK 文件：不存在（首次连接或测试时生成）";
    $("verifier").textContent = s.psk.verifier || "—";
  }
  render();
}
// ---- import confirmation (correction 4): preview -> explicit click ----
function showImportConfirm(preview) {
  $("imp-worker").textContent = preview.workerUrl;
  $("imp-detail").textContent = `keyId ${preview.keyId} · ${preview.hasPsk ? "含新 PSK（配对 V：" + (preview.pskVerifier || "").slice(0, 12) + "…）" : "不含 PSK（只改地址）"}`;
  $("imp-warn").textContent = preview.overwritesPsk ? "⚠ 本机已有 PSK，确认后将被覆盖，现配对随即失效。" : "";
  $("import-confirm").style.display = "block";
}
function hideImportConfirm() { $("import-confirm").style.display = "none"; }
async function stageResult(r) {
  if (r && r.ok && r.preview) { showImportConfirm(r.preview); $("import-result").textContent = "已预览，等待你确认。"; }
  else if (r && !r.ok) { $("import-result").textContent = "导入未就绪：" + (r.error || "未知错误"); }
}
$("btn-imp-preview").addEventListener("click", async () => { stageResult(await window.hollow.importPreview($("import-text").value)); });
$("btn-imp-file").addEventListener("click", async () => { stageResult(await window.hollow.importFromFile()); });
$("btn-imp-qrfile").addEventListener("click", async () => { stageResult(await window.hollow.importFromQrFile()); });
$("btn-imp-clip").addEventListener("click", async () => { stageResult(await window.hollow.importFromClipboard()); });
$("btn-imp-confirm").addEventListener("click", async () => {
  const r = await window.hollow.importConfirm();
  hideImportConfirm();
  $("import-result").textContent = r.ok ? "导入已应用。" : "导入失败：" + (r.error || "");
  $("import-text").value = "";
  refresh();
});
$("btn-imp-cancel").addEventListener("click", async () => { await window.hollow.importCancel(); hideImportConfirm(); $("import-result").textContent = "已取消导入。"; });
window.hollow.onImport(({ preview, source }) => {
  showImportConfirm(preview);
  $("import-result").textContent = `收到导入（来源：${source}），等待你确认。`;
});
// ---- pairing actions ----
$("btn-copy-v").addEventListener("click", async () => {
  const r = await window.hollow.copyVerifier();
  $("test-result").textContent = r.ok ? "V 已复制到剪贴板" : "尚无可用 PSK";
});
$("btn-test").addEventListener("click", async () => {
  $("test-result").textContent = "握手测试中…";
  const r = await window.hollow.testConnection();
  $("test-result").textContent = r.ok ? `✓ 握手成功（${r.ms} ms）` : `✗ 握手失败：${r.error || ""}（${r.ms ?? "?"} ms）`;
  refresh();
});
$("btn-export").addEventListener("click", async () => {
  const r = await window.hollow.exportToFile(false);
  $("import-result").textContent = r.ok ? `已导出 ${r.file}（不含 PSK）` : "导出取消/失败：" + (r.error || "");
});
$("btn-export-psk").addEventListener("click", async () => {
  if (!window.confirm("导出文件将包含 PSK 本体——任何拿到文件的人都能冒充本机配对。只导出到你自己的可信介质，确认？")) return;
  const r = await window.hollow.exportToFile(true);
  $("import-result").textContent = r.ok ? `已导出 ${r.file}（含 PSK，请妥善保管）` : "导出取消/失败：" + (r.error || "");
});
$("btn-qr").addEventListener("click", async () => {
  const withPsk = $("chk-qr-psk").checked;
  if (withPsk && !window.confirm("二维码将包含 PSK 本体——只给自己的设备扫，确认生成？")) return;
  const r = await window.hollow.qrOwnConfig(withPsk);
  if (r.ok) { $("qr-img").src = r.dataUrl; $("qr-img").style.display = "block"; }
  else $("import-result").textContent = "二维码生成失败：" + (r.error || "");
});
// ---- connection & settings ----
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
