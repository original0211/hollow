// Renderer (NP-1118-01 rework): status hero first, settings that
// apply on change, plain-language errors, diagnostics in a drawer.
// Presentation only — every value shown comes from the bridge /
// main-process state, and untrusted strings (import previews, worker
// URLs) are rendered exclusively via textContent, never innerHTML.
const $ = (id) => document.getElementById(id);
// Bridge defense (NP-1114-35): if the preload failed to load, window
// .hollow is undefined and the old failure mode was total silent death
// (a TypeError at the first top-level subscription killed every later
// registration). Now: say so on the state card, then stop ALL further
// initialization — a loud, honest error beats a dead page.
if (!window.hollow) {
  $("state").textContent = "界面桥未就绪（preload 未加载）——请重启应用；若反复出现请更新到最新版";
  throw new Error("window.hollow missing — preload failed to load");
}
const logEl = $("log");
let snapshot = { state: "disconnected", connectedSince: null, stats: null, socksPort: null, queuedNow: 0, detail: "", liveCarriers: 0, poolSize: 0, slotEdges: {}, edgeCandidateRtts: {}, edgeIp: null, traffic: { up: 0, down: 0 } };
let trafficRates = { upRate: 0, downRate: 0 };
let landingInfo = null;

function appendLog(line) {
  logEl.textContent += line + "\n";
  logEl.scrollTop = logEl.scrollHeight;
}
function fmtDuration(ms) {
  const s = Math.max(0, Math.floor(ms / 1000)); // clock jumps must not render negative durations (M2-5)
  const hh = String(Math.floor(s / 3600)).padStart(2, "0");
  const mm = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
  const ss = String(s % 60).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}
function fmtRate(bps) {
  if (!Number.isFinite(bps) || bps <= 0) return "0 B/s";
  if (bps < 1024) return `${Math.round(bps)} B/s`;
  if (bps < 1024 * 1024) return `${(bps / 1024).toFixed(1)} KB/s`;
  return `${(bps / 1024 / 1024).toFixed(2)} MB/s`;
}
function fmtBytes(n) {
  if (!Number.isFinite(n) || n <= 0) return "0 B";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(2)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

// ---- (e) plain-language error mapping -------------------------------
// Known failure surfaces become a Chinese cause + a next step; the
// raw line always stays available under 详情. Unknown failures get
// the generic card, never a bare English code as the whole message.
function humanizeError(raw) {
  const s = String(raw || "");
  if (/psk\.bin is \d+ bytes|PSK_CORRUPT|corrupt/i.test(s) && /psk/i.test(s)) {
    return { title: "密钥文件已损坏", body: "本机保存的配对密钥文件不完整，应用不会自动重建（以免悄悄断开配对）。下一步：重新导入一份配置，或退出应用后删除配置目录里的 psk.bin 再启动（将生成新密钥，需要重新配对）。" };
  }
  if (/TUN 助手未运行|TUN.*尚未启用/.test(s)) {
    return { title: "TUN 模式尚未启用", body: "TUN 需要系统助手进程配合，助手拉起不在当前版本内。下一步：改用「全局」或「PAC 分流」模式。" };
  }
  if (/socks start failed/i.test(s)) {
    return { title: "本地 SOCKS 端口被占用", body: "设置里的 SOCKS 端口已被其他程序占用，连接未建立、系统代理也没有启用。下一步：在设置里换一个空闲端口（改完即生效），或关掉占用该端口的程序后重连。" };
  }
  if (/undecryptable|AeadUnavailable|X25519|fatal:|handshake.*(fail|reject)|Finished/i.test(s)) {
    return { title: "密钥不匹配，握手被拒绝", body: "本机密钥与服务端保存的配对值不一致，服务端拒绝了握手。下一步：把「配对」区的配对 V 复制到 Worker 的 secret PSK_V_HEX 后重试；或重新导入一份正确配置。" };
  }
  if (/ENOTFOUND|EAI_AGAIN|ECONNREFUSED|ECONNRESET|ETIMEDOUT|timed out|timeout|fetch failed|network|getaddrinfo/i.test(s)) {
    return { title: "无法连通 Worker", body: "连不上设置里的 Worker 地址。下一步：检查地址是否正确、本机网络是否正常；如果刚改过地址，确认无误后点「立即重连」。" };
  }
  return { title: "连接失败", body: "连接没有建立起来。可以点「立即重连」再试一次；如果反复失败，请展开下方详情或打开诊断日志查看原始信息。" };
}

// ---- (a) status hero --------------------------------------------------
function stateView() {
  const st = snapshot.state;
  if (st === "connected") {
    if (snapshot.poolSize > 0 && snapshot.liveCarriers < snapshot.poolSize) {
      return { label: "已降级", dot: "warn", detail: `承载 ${snapshot.liveCarriers}/${snapshot.poolSize} 在线，速度与稳定性会打折，系统会自动补齐。` };
    }
    return { label: "已连接", dot: "ok", detail: snapshot.detail || "" };
  }
  if (st === "reconnecting") return { label: "已降级 · 重连中", dot: "warn", detail: "连接中断，正在自动重连…" };
  if (st === "connecting") return { label: "连接中", dot: "busy", detail: "正在与服务端握手…" };
  if (st === "error") return { label: "连接失败", dot: "err", detail: "" };
  return { label: "未连接", dot: "", detail: snapshot.detail || "" };
}
function render() {
  const v = stateView();
  $("state").textContent = v.label;
  $("state-dot").className = "dot" + (v.dot ? " " + v.dot : "");
  $("detail").textContent = v.detail;
  // readings
  const connected = snapshot.state === "connected" || snapshot.state === "reconnecting";
  $("rate-down").textContent = connected ? fmtRate(trafficRates.downRate) : "—";
  $("rate-up").textContent = connected ? fmtRate(trafficRates.upRate) : "—";
  $("health").textContent = snapshot.poolSize ? `${snapshot.liveCarriers}/${snapshot.poolSize}` : "—";
  $("duration").textContent = snapshot.connectedSince ? fmtDuration(Date.now() - snapshot.connectedSince) : "—";
  const pins = Object.entries(snapshot.slotEdges || {}).sort((a, b) => Number(a[0]) - Number(b[0]));
  if (pins.length) {
    $("entries").textContent = pins.map(([, ip]) => {
      const rtt = (snapshot.edgeCandidateRtts || {})[ip];
      return Number.isFinite(rtt) ? `${ip} · ${Math.round(rtt)} ms` : String(ip);
    }).join("　");
  } else if (snapshot.edgeIp) {
    $("entries").textContent = String(snapshot.edgeIp);
  } else {
    $("entries").textContent = snapshot.state === "connected" ? "默认解析" : "—";
  }
  $("landing").textContent = landingInfo
    ? `${landingInfo.colo || "?"} / ${landingInfo.country || "?"}${landingInfo.edgeIp ? "（经优选 IP " + landingInfo.edgeIp + "）" : "（默认路由）"}`
    : "—";
  $("socks-addr").textContent = snapshot.socksPort ? `127.0.0.1:${snapshot.socksPort}` : "—";
  const t = snapshot.traffic || { up: 0, down: 0 };
  $("traffic-total").textContent = `↓ ${fmtBytes(t.down)} · ↑ ${fmtBytes(t.up)}`;
  $("day-stats").textContent = snapshot.stats ? `今日 载体 ${snapshot.stats.carriers} · 流 ${snapshot.stats.streams}` : "";
  const tunEl = $("tun-status");
  const tv = snapshot.tun;
  if (tv && tv.active) {
    tunEl.style.display = "block";
    const grace = tv.graceRemainingMs !== null && tv.graceRemainingMs !== undefined ? ` · 重连宽限剩余 ${Math.ceil(tv.graceRemainingMs / 1000)}s` : "";
    tunEl.textContent = `TUN：助手${tv.helperAlive ? "存活" : "未连接"} · 模式 ${tv.mode} · DNS 查询 ${tv.dns.queries}/解析 ${tv.dns.resolved}/SERVFAIL ${tv.dns.servfail}（连接 ${tv.dns.conns}） · UDP 丢弃 ${tv.droppedUdp}${grace} · ${tv.notices.join(" · ")}`;
  } else {
    tunEl.style.display = "none";
  }
  // main toggle button follows the state
  const btn = $("btn-toggle");
  if (snapshot.state === "connected" || snapshot.state === "reconnecting") { btn.textContent = "断开"; btn.disabled = false; }
  else if (snapshot.state === "connecting") { btn.textContent = "连接中…"; btn.disabled = true; }
  else { btn.textContent = "连接"; btn.disabled = false; }
  // error card
  const card = $("error-card");
  if (snapshot.state === "error") {
    const h = humanizeError(snapshot.detail);
    $("error-title").textContent = h.title;
    $("error-body").textContent = h.body;
    $("error-raw").textContent = snapshot.detail || "";
    card.hidden = false;
  } else {
    card.hidden = true;
  }
  renderBusyLine();
}

// (e) The busy banner is a formal status element now: it follows
// the live queued count, appearing at once and fading ~1 s after
// the queue drains (NP-1117-12 debounce kept).
let busyHideTimer = null;
function renderBusyLine() {
  const el = $("busy-line");
  if (snapshot.queuedNow > 0) {
    if (busyHideTimer) { clearTimeout(busyHideTimer); busyHideTimer = null; }
    el.style.display = "block";
  } else if (el.style.display === "block" && !busyHideTimer) {
    busyHideTimer = setTimeout(() => {
      busyHideTimer = null;
      if (snapshot.queuedNow <= 0) $("busy-line").style.display = "none";
    }, 1000);
  }
}

// ---- settings: apply on change (c) ------------------------------------
const FIELD_NOTES = { workerUrl: "note-workerUrl", proxyMode: "note-proxyMode", socksPort: "note-socksPort", directHosts: "note-directHosts", metaPath: "note-metaPath", edgesPath: "note-edgesPath", poolSize: "note-poolSize", pacPort: "note-pacPort" };
function setNote(field, text, kind) {
  const el = $(FIELD_NOTES[field]);
  if (!el) return;
  el.textContent = text || "";
  el.className = "field-note" + (kind ? " " + kind : "");
}
function fieldErrorText(field, raw) {
  const s = String(raw || "");
  if (field === "socksPort" || field === "pacPort") return "端口不合要求：须为 1–65535 的整数。";
  if (field === "poolSize") return "承载数不合要求：须为 1–8 的整数。";
  if (field === "workerUrl") return "地址不合要求（须为 wss:// 地址，本机调试才可用 ws://localhost）：" + s;
  if (field === "metaPath" || field === "edgesPath") return "路径不合要求：" + s;
  return s;
}
let reconnectNeeded = false;
function updateReconnectBar() { $("reconnect-bar").hidden = !reconnectNeeded; }
async function applySetting(field, value, control) {
  setNote(field, "应用中…", "");
  if (control) control.disabled = true;
  try {
    const r = await window.hollow.saveSettings({ [field]: value });
    if (r && r.errors && r.errors[field]) {
      setNote(field, fieldErrorText(field, r.errors[field]), "err");
      refresh(); // snap the control back to the value actually in force
      return;
    }
    if (r && r.needsReconnect) {
      reconnectNeeded = true; updateReconnectBar();
      setNote(field, "已保存，需重连后生效。", "warn");
    } else {
      setNote(field, "已生效", "ok");
      setTimeout(() => setNote(field, "", ""), 2500);
    }
  } catch (e) {
    setNote(field, "应用失败：" + e.message, "err");
  } finally {
    if (control) control.disabled = false;
  }
}
async function reconnectNow() {
  reconnectNeeded = false; updateReconnectBar();
  try { await window.hollow.disconnect(); } catch { /* not connected */ }
  try { await window.hollow.connect(); } catch (e) { appendLog("reconnect error: " + e.message); }
  refresh();
}
$("btn-reconnect").addEventListener("click", reconnectNow);
$("btn-reconnect2").addEventListener("click", reconnectNow);

// refresh() writes the in-force values into the controls — except
// the one being edited right now, so an in-progress edit is never
// snapped back under the user's fingers.
function setControlValue(id, value) {
  const el = $(id);
  if (document.activeElement === el) return;
  el.value = value;
}
async function refresh() {
  const s = await window.hollow.getState();
  snapshot = { ...snapshot, ...s };
  if (Array.isArray(s.logs)) { logEl.textContent = ""; s.logs.forEach(appendLog); }
  if (s.settings) {
    setControlValue("worker-url", s.settings.workerUrl || "");
    setControlValue("proxy-mode", s.settings.proxyMode || "off");
    setControlValue("direct-hosts", (s.settings.directHosts || []).join("\n"));
    setControlValue("meta-path", s.settings.metaPath || "");
    setControlValue("edges-path", s.settings.edgesPath || "");
    setControlValue("socks-port", s.settings.socksPort ?? "");
    setControlValue("pool-size", s.settings.poolSize ?? "");
    setControlValue("pac-port", s.settings.pacPort ?? "");
    $("pac-seg").textContent = s.settings.pacSeg || "（尚未生成，首次启用 PAC 时生成）";
    const tunMode = s.settings.proxyMode === "tun";
    const defRadio = $("edge-mode-default");
    if (defRadio) defRadio.disabled = tunMode;
    const note = $("edge-default-note");
    if (note) note.style.display = tunMode ? "block" : "none";
  }
  if (s.psk) {
    $("psk-status").textContent = s.psk.state === "corrupt"
      ? "⚠ PSK 文件已损坏——应用不会自动重建；请重新导入配置或删除 psk.bin 后重启"
      : s.psk.exists
        ? `PSK 文件：正常（${s.psk.bytes} 字节，${s.settings ? s.settings.configDir : ""}）`
        : "PSK 文件：不存在（首启自动生成未成功——请重启应用；若反复出现请看日志并反馈）";
    $("verifier").textContent = s.psk.verifier || "—";
  }
  render();
}

// ---- connection toggle --------------------------------------------------
$("btn-toggle").addEventListener("click", async () => {
  try {
    if (snapshot.state === "connected" || snapshot.state === "reconnecting") await window.hollow.disconnect();
    else await window.hollow.connect();
  } catch (e) { appendLog("toggle error: " + e.message); }
  refresh();
});

// ---- settings field wiring (change = apply) ------------------------------
$("worker-url").addEventListener("change", (e) => applySetting("workerUrl", e.target.value.trim(), e.target));
$("proxy-mode").addEventListener("change", (e) => applySetting("proxyMode", e.target.value, e.target));
$("socks-port").addEventListener("change", (e) => applySetting("socksPort", Number(e.target.value), e.target));
$("direct-hosts").addEventListener("change", (e) => applySetting("directHosts", e.target.value.split("\n"), e.target));
$("meta-path").addEventListener("change", (e) => applySetting("metaPath", e.target.value, e.target));
$("edges-path").addEventListener("change", (e) => applySetting("edgesPath", e.target.value, e.target));
$("pool-size").addEventListener("change", (e) => applySetting("poolSize", Number(e.target.value), e.target));
$("pac-port").addEventListener("change", (e) => applySetting("pacPort", Number(e.target.value), e.target));

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
  $("test-result").textContent = r.ok ? `✓ 握手成功（${r.ms} ms）` : `✗ ${humanizeError(r.error).title}：${humanizeError(r.error).body}（${r.ms ?? "?"} ms）`;
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
// ---- edge selection (M2-4) ----
let edgeState = { edges: [], results: {}, edgeMode: "default", preferredEdgeIp: null };
function renderEdges() {
  const list = $("edge-list");
  list.textContent = "";
  for (const e of edgeState.edges) {
    const r = edgeState.results[e.ip];
    const row = document.createElement("div");
    const label = document.createElement("span");
    label.textContent = `${e.ip} — ${r ? (r.ok ? `${r.colo || "?"} / ${r.country || "?"} · ${r.medianMs} ms · ${String(r.at).slice(0, 16).replace("T", " ")}` : "不可用（" + (r.error || "失败") + "）") : "未测速"}` + (edgeState.preferredEdgeIp === e.ip ? " · 已指定" : "");
    const btn = document.createElement("button");
    btn.textContent = "指定";
    btn.addEventListener("click", async () => {
      await window.hollow.setEdgeSelection({ mode: "manual", ip: e.ip });
      edgeState.edgeMode = "manual"; edgeState.preferredEdgeIp = e.ip;
      syncEdgeRadios(); renderEdges();
    });
    row.appendChild(label); row.appendChild(btn);
    list.appendChild(row);
  }
  $("edge-status").textContent = edgeState.edges.length ? "" : "名单为空";
}
function syncEdgeRadios() {
  document.querySelectorAll("input[name='edge-mode']").forEach((el) => { el.checked = el.value === edgeState.edgeMode; });
}
document.querySelectorAll("input[name='edge-mode']").forEach((el) => {
  el.addEventListener("change", async () => {
    await window.hollow.setEdgeSelection({ mode: el.value });
    edgeState.edgeMode = el.value;
    renderEdges();
  });
});
$("btn-measure").addEventListener("click", async () => {
  $("edge-status").textContent = "测速中（每候选 3 次握手，约需 1–3 分钟）…";
  const r = await window.hollow.measureEdges();
  if (r.ok) { edgeState.results = r.results; $("edge-status").textContent = "测速完成"; }
  else $("edge-status").textContent = "测速失败：" + (r.error || "");
  renderEdges();
});
$("btn-refresh-edges").addEventListener("click", async () => {
  const r = await window.hollow.refreshEdges();
  if (r.edges) edgeState.edges = r.edges;
  $("edge-status").textContent = r.ok ? "名单已从服务器刷新" : "刷新失败，已用内置名单：" + (r.error || "");
  renderEdges();
});
window.hollow.onEdgeProgress(({ ip, result }) => { edgeState.results[ip] = result; renderEdges(); });
window.hollow.onMeta((m) => {
  landingInfo = { colo: m.colo, country: m.country, edgeIp: m.edgeIp ?? null };
  render();
});
(async () => {
  const s = await window.hollow.getEdges();
  edgeState = { ...edgeState, ...s };
  syncEdgeRadios(); renderEdges();
})();
// ---- diagnostics drawer (g) ----
$("btn-copy-logs").addEventListener("click", async (e) => {
  e.preventDefault();
  const btn = $("btn-copy-logs");
  const r = await window.hollow.copyLogs();
  btn.textContent = r && r.ok ? "已复制" : "复制失败";
  setTimeout(() => { btn.textContent = "复制日志"; }, 2000);
});
window.hollow.onLog(appendLog);
window.hollow.onEvent((ev) => {
  if (ev.type === "state") { snapshot.state = ev.state; snapshot.detail = ev.detail || ""; if (ev.state !== "connected") snapshot.connectedSince = null; refresh(); }
  if (ev.type === "stats") { snapshot.stats = ev.stats; render(); }
  if (ev.type === "socks") { snapshot.socksPort = ev.socksPort; render(); }
  if (ev.type === "queued") { snapshot.queuedNow = ev.queuedNow; render(); }
  if (ev.type === "traffic") { trafficRates = { upRate: ev.upRate, downRate: ev.downRate }; snapshot.traffic = { up: ev.up, down: ev.down }; render(); }
});
setInterval(render, 1000);
refresh();
