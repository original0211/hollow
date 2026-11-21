// NP-1118-42: deployment wizard orchestration — the six steps,
// their order, and every failure branch, with fake Cloudflare
// effects. The real API sequence itself was proven end-to-end
// in the sandbox drill (one-time script hollow-wizard-drill on
// the test account, deleted after); these grids pin the logic.
import { test } from "node:test";
import assert from "node:assert/strict";
import { runWizard, deleteDeployedWorker, buildDeployMetadata, subdomainCandidate, WIZARD_SCRIPT_NAME } from "../src/deploy-wizard.js";

function fakeDeps(over = {}) {
  const calls = [];
  let clock = 0;
  const apiTable = over.apiTable ?? {};
  const deps = {
    api: async (method, path, body) => {
      calls.push(`${method} ${path}`);
      const key = `${method} ${path}`;
      if (apiTable[key]) return apiTable[key];
      if (method === "GET" && path === "/user/tokens/verify") return { ok: true, status: 200, result: { status: "active" } };
      if (method === "GET" && path === "/accounts") return { ok: true, status: 200, result: over.accounts ?? [{ id: "acc1", name: "My Account" }] };
      if (method === "GET" && path.endsWith("/workers/subdomain")) return over.subdomainGet ?? { ok: true, status: 200, result: { subdomain: "myacct" } };
      if (method === "POST" && path.endsWith("/subdomain")) return { ok: true, status: 200, result: { enabled: true } };
      return { ok: true, status: 200, result: {} };
    },
    deployScript: async (args) => { calls.push("deployScript"); deps.__deployArgs = args; return over.deployResult ?? { ok: true, status: 200 }; },
    getBundle: async () => "BUNDLE",
    randomBytes: (n) => new Uint8Array(n).fill(7),
    randomHex: (n) => "ab".repeat(n),
    deriveVerifierHex: async () => "cd".repeat(32),
    probeLiveness: over.probeLiveness ?? (async () => { calls.push("liveness"); return { facade: true, meta: true, handshake: true }; }),
    finalize: async (pairing, account) => { calls.push("finalize"); deps.__final = { pairing, account }; if (over.finalizeThrows) throw new Error("disk full"); },
    onTokenVerified: async () => { calls.push("tokenVerified"); },
    now: () => clock,
    sleep: async (ms) => { clock += ms; calls.push("sleep"); },
    livenessWindowMs: over.livenessWindowMs ?? 180_000,
    livenessPollMs: 15_000,
    progress: () => {},
  };
  return { deps, calls };
}

test("happy path: six steps in order, config finalized with the deployed URL", async () => {
  const { deps, calls } = fakeDeps();
  const r = await runWizard(deps, { token: "tok" });
  assert.equal(r.ok, true);
  assert.equal(r.workerUrl, `wss://${WIZARD_SCRIPT_NAME}.myacct.workers.dev`);
  assert.deepEqual(calls.filter((c) => c !== "GET /user/tokens/verify" && c !== "GET /accounts"), [
    "tokenVerified",
    "deployScript",
    `GET /accounts/acc1/workers/subdomain`,
    `POST /accounts/acc1/workers/scripts/${WIZARD_SCRIPT_NAME}/subdomain`,
    "liveness",
    "finalize",
  ]);
  assert.equal(deps.__deployArgs.metadata.bindings[1].text, "cd".repeat(32)); // PSK_V_HEX = derived V
  assert.equal(deps.__deployArgs.metadata.bindings[0].name, "META_SEG");
  assert.equal(deps.__final.pairing.metaPath, `${"ab".repeat(16)}/meta`);
});

test("token rejected: stops at verify, nothing else runs", async () => {
  const { deps, calls } = fakeDeps({ apiTable: { "GET /user/tokens/verify": { ok: false, status: 401 } } });
  const r = await runWizard(deps, { token: "bad" });
  assert.equal(r.ok, false);
  assert.equal(r.step, "verify");
  assert.equal(r.code, "TOKEN_INVALID");
  assert.ok(!calls.includes("deployScript"));
});

test("accounts list forbidden: TOKEN_FORBIDDEN points at the missing read permission", async () => {
  const { deps } = fakeDeps({ apiTable: { "GET /accounts": { ok: false, status: 403 } } });
  const r = await runWizard(deps, { token: "tok" });
  assert.equal(r.code, "TOKEN_FORBIDDEN");
  assert.match(r.detail, /Account Settings: Read/);
});

test("multiple accounts without a choice: MULTI_ACCOUNT carries the list", async () => {
  const { deps } = fakeDeps({ accounts: [{ id: "a1", name: "One" }, { id: "a2", name: "Two" }] });
  const r = await runWizard(deps, { token: "tok" });
  assert.equal(r.code, "MULTI_ACCOUNT");
  assert.equal(r.accounts.length, 2);
  const r2 = await runWizard(deps, { token: "tok", accountId: "a2" });
  assert.equal(r2.ok, true);
  assert.equal(r2.accountId, "a2");
});

test("deploy refused with a not-enabled error: hint flag set", async () => {
  const { deps } = fakeDeps({ deployResult: { ok: false, status: 400, errors: [{ code: 10063, message: "workers is not enabled for this account" }] } });
  const r = await runWizard(deps, { token: "tok" });
  assert.equal(r.step, "deploy");
  assert.equal(r.code, "DEPLOY_FAILED");
  assert.equal(r.workersNotEnabled, true);
});

test("subdomain unset: the wizard claims a candidate, then enables the script", async () => {
  const { deps, calls } = fakeDeps({ subdomainGet: { ok: false, status: 404, result: null } });
  // the claim PUT is answered by the default table (ok) — but the
  // read-back still returns the canned subdomain; accept either
  // way: what matters is the claim attempt happened before enable.
  const r = await runWizard(deps, { token: "tok" });
  assert.equal(r.ok, true);
  const claimIdx = calls.findIndex((c) => c === "PUT /accounts/acc1/workers/subdomain");
  const enableIdx = calls.findIndex((c) => c.startsWith("POST /accounts/acc1/workers/scripts/"));
  assert.ok(claimIdx >= 0 && enableIdx > claimIdx, `calls: ${calls.join(" | ")}`);
});

test("subdomain claim impossible: SUBDOMAIN_FAILED with honest copy", async () => {
  const { deps } = fakeDeps({
    subdomainGet: { ok: false, status: 404, result: null },
    apiTable: { "PUT /accounts/acc1/workers/subdomain": { ok: false, status: 409 } },
  });
  const r = await runWizard(deps, { token: "tok" });
  assert.equal(r.step, "subdomain");
  assert.equal(r.code, "SUBDOMAIN_FAILED");
});

test("liveness rides out the lag: two bad probes then a good one", async () => {
  let probes = 0;
  const { deps, calls } = fakeDeps({
    probeLiveness: async () => { probes++; return probes < 3 ? { facade: false, meta: false, handshake: false } : { facade: true, meta: true, handshake: true }; },
  });
  const r = await runWizard(deps, { token: "tok" });
  assert.equal(r.ok, true);
  assert.equal(probes, 3);
  assert.equal(calls.filter((c) => c === "sleep").length, 2);
});

test("liveness never comes up: LIVENESS_FAILED with parts, finalize untouched", async () => {
  const { deps, calls } = fakeDeps({
    probeLiveness: async () => ({ facade: true, meta: false, handshake: false }),
    livenessWindowMs: 30_000,
  });
  const r = await runWizard(deps, { token: "tok" });
  assert.equal(r.code, "LIVENESS_FAILED");
  assert.deepEqual(r.parts, { facade: true, meta: false, handshake: false });
  assert.ok(!calls.includes("finalize"));
});

test("finalize failure: FINALIZE_FAILED, the deploy itself stands", async () => {
  const { deps } = fakeDeps({ finalizeThrows: true });
  const r = await runWizard(deps, { token: "tok" });
  assert.equal(r.step, "finalize");
  assert.equal(r.code, "FINALIZE_FAILED");
});

test("metadata + candidate shapes", () => {
  const m = buildDeployMetadata({ vHex: "vv", metaSeg: "ss" });
  assert.equal(m.main_module, "index.js");
  assert.deepEqual(m.bindings.map((b) => b.name), ["META_SEG", "PSK_V_HEX"]);
  assert.equal(subdomainCandidate("My Cool Account!", "ab12"), "my-cool-account-ab12");
  assert.equal(subdomainCandidate("!!!", "ab12"), "hollow-ab12");
});

test("deleteDeployedWorker passes through ok and failure", async () => {
  const okDeps = { api: async () => ({ ok: true, status: 200 }) };
  assert.equal((await deleteDeployedWorker(okDeps, { accountId: "a" })).ok, true);
  const badDeps = { api: async () => { throw new Error("net down"); } };
  const r = await deleteDeployedWorker(badDeps, { accountId: "a" });
  assert.equal(r.ok, false);
  assert.match(r.detail, /net down/);
});
