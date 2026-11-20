// TUN helper auto-launch (NP-1118-38): the last mile between the
// app and hollow-tun-helper.exe. Until this module existed the app
// could only CONNECT to an already-running helper; enabling TUN
// with no helper resident surfaced "not running" and stopped
// (NP-1117-07 d4). Now the app resolves, pre-flights, launches
// (elevated, one UAC prompt) and readiness-checks the helper
// itself.
//
// Pure decision logic with injected effects, in the house style of
// tun-supervisor.js / helper-watch.js — main.js wires the real
// filesystem / PowerShell / pipe effects into these seams, and the
// unit tests + Electron smoke drive the same code with fakes.
//
// Failure codes (the caller maps them to honest UI copy; a TUN
// enable that fails here has changed NOTHING on the system — the
// takeover is only ever requested after readiness):
//   TUN_HELPER_MISSING  exe and/or wintun.dll not found anywhere
//   TUN_HELPER_BROKEN   --check-dll failed (dll missing/not pinned)
//   TUN_UAC_CANCELED    the user declined the elevation prompt
//   TUN_LAUNCH_FAILED   the elevated start itself failed
//   TUN_HELPER_DOWN     launched, but the pipe never answered

import path from "node:path";

export const HELPER_EXE = "hollow-tun-helper.exe";
export const WINTUN_DLL = "wintun.dll";

// resolveHelperFiles: the portable/loose layout puts the helper
// and wintun.dll next to the app exe; the dev layout stages them
// under dist/. The first directory holding BOTH files wins. The
// result reports what was found where, so a missing piece can be
// named in the UI instead of failing opaquely.
export function resolveHelperFiles({ appDir, fallbackDir, exists }) {
  const dirs = [appDir, fallbackDir].filter(Boolean);
  const seen = [];
  for (const dir of dirs) {
    const exe = path.join(dir, HELPER_EXE);
    const dll = path.join(dir, WINTUN_DLL);
    const hasExe = !!exists(exe);
    const hasDll = !!exists(dll);
    seen.push({ dir, hasExe, hasDll });
    if (hasExe && hasDll) return { ok: true, dir, exe, dll, seen };
  }
  return { ok: false, seen };
}

export function describeMissing(resolution) {
  const parts = [];
  for (const s of resolution.seen ?? []) {
    const missing = [];
    if (!s.hasExe) missing.push(HELPER_EXE);
    if (!s.hasDll) missing.push(WINTUN_DLL);
    if (missing.length) parts.push(`${s.dir}: 缺 ${missing.join("、")}`);
  }
  return parts.join("；") || "未找到助手文件";
}

// ensureHelperRunning: the full launch decision chain.
//   deps.resolveFiles()      -> resolveHelperFiles result
//   deps.pipeReady()         -> Promise<bool>: pipe connect + ping
//   deps.checkDll(exe)       -> Promise<bool>: --check-dll exit 0
//   deps.spawnElevated(exe)  -> Promise<{ok, canceled?, detail?}>
//   deps.waitReady(ms)       -> Promise<bool>: poll pipeReady
//   deps.readyTimeoutMs      -> readiness budget (default 20s)
//   deps.log(msg)
export async function ensureHelperRunning(deps) {
  const log = deps.log ?? (() => {});
  const readyTimeoutMs = deps.readyTimeoutMs ?? 20_000;

  // Already resident (a previous launch, or the app restarted
  // while the helper stayed up): no files, no prompt, no spawn.
  if (await deps.pipeReady()) {
    log("helper launch: already resident — no launch needed");
    return { ok: true, already: true, launched: false };
  }

  const files = deps.resolveFiles();
  if (!files.ok) {
    return { ok: false, code: "TUN_HELPER_MISSING", detail: describeMissing(files) };
  }

  // Pre-flight without elevation: a broken DLL must not cost the
  // user a UAC prompt.
  if (!(await deps.checkDll(files.exe))) {
    return { ok: false, code: "TUN_HELPER_BROKEN", detail: `${WINTUN_DLL} 缺失或非钉版构建（--check-dll 未通过）` };
  }

  const sp = await deps.spawnElevated(files.exe);
  if (!sp.ok) {
    if (sp.canceled) return { ok: false, code: "TUN_UAC_CANCELED", detail: "用户取消了管理员授权" };
    return { ok: false, code: "TUN_LAUNCH_FAILED", detail: sp.detail || "提权拉起失败" };
  }
  log(`helper launch: elevated start requested (${files.exe})`);

  if (!(await deps.waitReady(readyTimeoutMs))) {
    return { ok: false, code: "TUN_HELPER_DOWN", detail: `助手已拉起但 ${Math.round(readyTimeoutMs / 1000)} 秒内未在管道就绪` };
  }
  log("helper launch: helper is up and answering on its pipe");
  return { ok: true, already: false, launched: true, exe: files.exe };
}
