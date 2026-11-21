// Electron-runtime smoke for the NP-1118-42 deployment wizard.
// The Cloudflare API is faked (the real six-step sequence was
// proven against a one-time script on the test account in the
// sandbox drill); what this proves in the Electron runtime is
// that the shipped deploy-wizard module loads and its failure
// branches land on their named codes — one grid per step.
// Run: ELECTRON_RUN_AS_NODE=1 ./node_modules/electron/dist/electron tools/electron-wizard-smoke.mjs
import assert from "node:assert/strict";
import { runWizard } from "../src/deploy-wizard.js";

function baseDeps(over = {}) {
  let clock = 0;
  return {
    api: async (method, path) => {
      if (over.failVerify && path === "/user/tokens/verify") return { ok: false, status: 401 };
      if (path === "/accounts") return { ok: true, status: 200, result: [{ id: "acc", name: "Acct" }] };
      if (path.endsWith("/workers/subdomain") && method === "GET") {
        return over.failSubdomain ? { ok: false, status: 404, result: null } : { ok: true, status: 200, result: { subdomain: "acct" } };
      }
      if (method === "PUT" && path.endsWith("/workers/subdomain")) return { ok: false, status: 409 };
      return { ok: true, status: 200, result: {} };
    },
    deployScript: async () => over.failDeploy ? { ok: false, status: 400, errors: [{ message: "boom" }] } : { ok: true, status: 200 },
    getBundle: async () => "BUNDLE",
    randomBytes: (n) => new Uint8Array(n).fill(3),
    randomHex: (n) => "ef".repeat(n),
    deriveVerifierHex: async () => "ab".repeat(32),
    probeLiveness: async () => over.failLiveness ? { facade: true, meta: false, handshake: false } : { facade: true, meta: true, handshake: true },
    finalize: async () => {},
    now: () => clock,
    sleep: async (ms) => { clock += ms; },
    livenessWindowMs: 30_000, livenessPollMs: 15_000,
    progress: () => {},
  };
}

// Happy path inside the Electron runtime.
{
  const r = await runWizard(baseDeps(), { token: "t" });
  assert.equal(r.ok, true);
  assert.equal(r.workerUrl, "wss://hollow.acct.workers.dev");
  console.log("grid happy: ok, workerUrl formed");
}
// One failure grid per step.
{
  const r = await runWizard(baseDeps({ failVerify: true }), { token: "t" });
  assert.equal(r.code, "TOKEN_INVALID");
  console.log("grid verify-fail: TOKEN_INVALID");
}
{
  const r = await runWizard(baseDeps({ failDeploy: true }), { token: "t" });
  assert.equal(r.step, "deploy");
  assert.equal(r.code, "DEPLOY_FAILED");
  console.log("grid deploy-fail: DEPLOY_FAILED");
}
{
  const r = await runWizard(baseDeps({ failSubdomain: true }), { token: "t" });
  assert.equal(r.step, "subdomain");
  assert.equal(r.code, "SUBDOMAIN_FAILED");
  console.log("grid subdomain-fail: SUBDOMAIN_FAILED");
}
{
  const r = await runWizard(baseDeps({ failLiveness: true }), { token: "t" });
  assert.equal(r.step, "liveness");
  assert.equal(r.code, "LIVENESS_FAILED");
  assert.deepEqual(r.parts, { facade: true, meta: false, handshake: false });
  console.log("grid liveness-fail: LIVENESS_FAILED with parts");
}
console.log("WIZARD_SMOKE_OK");
