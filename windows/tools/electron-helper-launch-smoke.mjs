// Electron-runtime smoke for the NP-1118-38 helper-launch logic.
// The sandbox is not Windows: the real PowerShell/UAC/pipe effects
// cannot run here (they are Brody's TUN-01…34 real-machine
// volume). What CAN be proven in the Electron runtime is that the
// shipped helper-launch module loads and its decision chain
// behaves — with fake effects for a simulated helper PRESENT and
// a simulated helper ABSENT, plus the UAC-cancel branch.
// Run: ELECTRON_RUN_AS_NODE=1 ./node_modules/electron/dist/electron tools/electron-helper-launch-smoke.mjs
import assert from "node:assert/strict";
import { resolveHelperFiles, ensureHelperRunning } from "../src/helper-launch.js";

const APP = "/portable";
const filesInApp = (p) => p === `${APP}/hollow-tun-helper.exe` || p === `${APP}/wintun.dll`;

// Grid 1 — helper PRESENT: resolution finds the pair next to the
// app, the elevated spawn is requested for exactly that exe, and
// readiness completes the chain.
{
  const spawned = [];
  const r = await ensureHelperRunning({
    resolveFiles: () => resolveHelperFiles({ appDir: APP, fallbackDir: "/none", exists: filesInApp }),
    pipeReady: async () => false,
    checkDll: async () => true,
    spawnElevated: async (exe) => { spawned.push(exe); return { ok: true }; },
    waitReady: async () => true,
    log: () => {},
  });
  assert.equal(r.ok, true);
  assert.equal(r.launched, true);
  assert.deepEqual(spawned, [`${APP}/hollow-tun-helper.exe`]);
  console.log("grid present: launch chain ok, spawned the resolved exe");
}

// Grid 2 — helper ABSENT: the chain stops at resolution with the
// missing code and never reaches the spawner.
{
  let spawnCalls = 0;
  const r = await ensureHelperRunning({
    resolveFiles: () => resolveHelperFiles({ appDir: APP, fallbackDir: "/none", exists: () => false }),
    pipeReady: async () => false,
    checkDll: async () => { throw new Error("must not be called"); },
    spawnElevated: async () => { spawnCalls++; return { ok: true }; },
    waitReady: async () => true,
    log: () => {},
  });
  assert.equal(r.ok, false);
  assert.equal(r.code, "TUN_HELPER_MISSING");
  assert.equal(spawnCalls, 0);
  console.log("grid absent: TUN_HELPER_MISSING, spawner untouched");
}

// Grid 3 — UAC declined: its own code, no readiness wait.
{
  let waits = 0;
  const r = await ensureHelperRunning({
    resolveFiles: () => resolveHelperFiles({ appDir: APP, fallbackDir: "/none", exists: filesInApp }),
    pipeReady: async () => false,
    checkDll: async () => true,
    spawnElevated: async () => ({ ok: false, canceled: true }),
    waitReady: async () => { waits++; return true; },
    log: () => {},
  });
  assert.equal(r.code, "TUN_UAC_CANCELED");
  assert.equal(waits, 0);
  console.log("grid uac-cancel: TUN_UAC_CANCELED, no readiness wait");
}

console.log("HELPER_LAUNCH_SMOKE_OK");
