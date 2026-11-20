// NP-1118-38: helper-launch decision logic — resolution order and
// the ensureHelperRunning chain, driven with fake effects in the
// tun-supervisor/helper-watch test style. The real fs/PowerShell/
// pipe effects live in main.js; the Electron smoke replays these
// same grids inside the Electron runtime.
import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { resolveHelperFiles, ensureHelperRunning, describeMissing } from "../src/helper-launch.js";

const APP = "/app";
const DIST = "/app/dist";
const inDir = (dir) => ({
  [`${dir}/hollow-tun-helper.exe`]: true,
  [`${dir}/wintun.dll`]: true,
});
function existsFrom(map) { return (p) => !!map[p]; }

test("resolve: app dir wins when both files are there", () => {
  const r = resolveHelperFiles({ appDir: APP, fallbackDir: DIST, exists: existsFrom({ ...inDir(APP), ...inDir(DIST) }) });
  assert.equal(r.ok, true);
  assert.equal(r.dir, APP);
});

test("resolve: falls back to dist when the app dir lacks the pair", () => {
  const r = resolveHelperFiles({ appDir: APP, fallbackDir: DIST, exists: existsFrom({ ...inDir(DIST) }) });
  assert.equal(r.ok, true);
  assert.equal(r.dir, DIST);
});

test("resolve: a split pair does not count — both files must share a dir", () => {
  const r = resolveHelperFiles({
    appDir: APP, fallbackDir: DIST,
    exists: existsFrom({ [`${APP}/hollow-tun-helper.exe`]: true, [`${DIST}/wintun.dll`]: true }),
  });
  assert.equal(r.ok, false);
  assert.match(describeMissing(r), /hollow-tun-helper\.exe/);
  assert.match(describeMissing(r), /wintun\.dll/);
});

function fakeDeps(over = {}) {
  const calls = [];
  const deps = {
    resolveFiles: () => { calls.push("resolve"); return over.files ?? { ok: true, dir: APP, exe: `${APP}/hollow-tun-helper.exe`, dll: `${APP}/wintun.dll`, seen: [] }; },
    pipeReady: async () => { calls.push("probe"); return over.already ?? false; },
    checkDll: async () => { calls.push("checkDll"); return over.dllOk ?? true; },
    spawnElevated: async () => { calls.push("spawn"); return over.spawn ?? { ok: true }; },
    waitReady: async () => { calls.push("wait"); return over.ready ?? true; },
    readyTimeoutMs: 5000,
    log: () => {},
  };
  return { deps, calls };
}

test("ensure: already resident short-circuits — no resolve, no spawn", async () => {
  const { deps, calls } = fakeDeps({ already: true });
  const r = await ensureHelperRunning(deps);
  assert.equal(r.ok, true);
  assert.equal(r.already, true);
  assert.deepEqual(calls, ["probe"]);
});

test("ensure: missing files — named, no dll check, no spawn", async () => {
  const { deps, calls } = fakeDeps({ files: { ok: false, seen: [{ dir: APP, hasExe: false, hasDll: false }] } });
  const r = await ensureHelperRunning(deps);
  assert.equal(r.ok, false);
  assert.equal(r.code, "TUN_HELPER_MISSING");
  assert.deepEqual(calls, ["probe", "resolve"]);
});

test("ensure: broken dll stops before the UAC prompt", async () => {
  const { deps, calls } = fakeDeps({ dllOk: false });
  const r = await ensureHelperRunning(deps);
  assert.equal(r.code, "TUN_HELPER_BROKEN");
  assert.deepEqual(calls, ["probe", "resolve", "checkDll"]);
});

test("ensure: UAC cancel is its own outcome", async () => {
  const { deps } = fakeDeps({ spawn: { ok: false, canceled: true } });
  const r = await ensureHelperRunning(deps);
  assert.equal(r.code, "TUN_UAC_CANCELED");
});

test("ensure: launch failure carries the spawner detail", async () => {
  const { deps } = fakeDeps({ spawn: { ok: false, detail: "powershell exited 1" } });
  const r = await ensureHelperRunning(deps);
  assert.equal(r.code, "TUN_LAUNCH_FAILED");
  assert.match(r.detail, /powershell/);
});

test("ensure: spawned but never ready is TUN_HELPER_DOWN", async () => {
  const { deps, calls } = fakeDeps({ ready: false });
  const r = await ensureHelperRunning(deps);
  assert.equal(r.code, "TUN_HELPER_DOWN");
  assert.deepEqual(calls, ["probe", "resolve", "checkDll", "spawn", "wait"]);
});

test("ensure: happy path order is probe→resolve→checkDll→spawn→wait", async () => {
  const { deps, calls } = fakeDeps();
  const r = await ensureHelperRunning(deps);
  assert.equal(r.ok, true);
  assert.equal(r.launched, true);
  assert.equal(r.exe, path.join(APP, "hollow-tun-helper.exe"));
  assert.deepEqual(calls, ["probe", "resolve", "checkDll", "spawn", "wait"]);
});
