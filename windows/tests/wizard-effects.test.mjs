// NP-1118-66 grids for audit NP-1118-63 B3/B4: the wizard's real
// effects (windows/src/wizard-effects.js, extracted from main.js)
// must bound every wait. Blackhole grids use short injected
// budgets; the production defaults stay 30 s / 15 s.
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { cfApiFor, cfDeployScript, probeWizardLiveness, CF_API_TIMEOUT_MS, WIZARD_PROBE_TIMEOUT_MS } from "../src/wizard-effects.js";

function blackholeServer() {
  return new Promise((resolve) => {
    const srv = http.createServer(() => { /* accept, never answer */ });
    srv.listen(0, "127.0.0.1", () => resolve(srv));
  });
}

test("B3 defaults: the production budgets are 30 s / 15 s", () => {
  assert.equal(CF_API_TIMEOUT_MS, 30000);
  assert.equal(WIZARD_PROBE_TIMEOUT_MS, 15000);
});

test("B3: cfApiFor aborts a blackholed API call at the bound instead of hanging", async () => {
  const srv = await blackholeServer();
  const base = `http://127.0.0.1:${srv.address().port}`;
  const api = cfApiFor(fetch, "tok", { timeoutMs: 300, base });
  const t0 = Date.now();
  await assert.rejects(() => api("GET", "/accounts", null), /abort/i);
  assert.ok(Date.now() - t0 < 3000, "the abort, not the server, must end the call");
  srv.close();
});

test("B3: cfDeployScript aborts a blackholed deploy at the bound", async () => {
  const srv = await blackholeServer();
  const base = `http://127.0.0.1:${srv.address().port}`;
  const t0 = Date.now();
  await assert.rejects(
    () => cfDeployScript(fetch, "tok", { accountId: "a", scriptName: "s", bundle: "B", metadata: {} }, { timeoutMs: 300, base }),
    /abort/i,
  );
  assert.ok(Date.now() - t0 < 3000);
  srv.close();
});

test("B3 control: a healthy API call returns the parsed envelope", async () => {
  const srv = http.createServer((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ success: true, result: [{ id: "acc" }], errors: [] }));
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const api = cfApiFor(fetch, "tok", { timeoutMs: 2000, base: `http://127.0.0.1:${srv.address().port}` });
  const out = await api("GET", "/accounts", null);
  assert.equal(out.ok, true);
  assert.deepEqual(out.result, [{ id: "acc" }]);
  srv.close();
});

const PAIRING = { workerUrl: "wss://hollow.acct.workers.dev", metaPath: "seg/meta", psk: new Uint8Array(32), keyId: 1 };

function fakeFetch(facadeBody, metaObj) {
  return async (url) => {
    if (url.endsWith("/seg/meta")) {
      return { status: 200, ok: true, text: async () => JSON.stringify(metaObj), json: async () => metaObj };
    }
    return { status: 200, ok: true, text: async () => facadeBody, json: async () => { throw new Error("not json"); } };
  };
}

test("B4: a connect that never settles is cut by the probe race, both layers closed", async () => {
  let transportClosed = false;
  const connectWs = () => new Promise(() => {}); // never settles
  const t0 = Date.now();
  const parts = await probeWizardLiveness(PAIRING, {
    fetchImpl: fakeFetch("x".repeat(81), { colo: "DFW" }),
    connectWs,
    HollowClient: class { async handshake() {} close() {} },
    probeTimeoutMs: 300, fetchTimeoutMs: 1000,
  });
  assert.ok(Date.now() - t0 < 3000, "the race must end the probe");
  assert.deepEqual(parts, { facade: true, meta: true, handshake: false });
  assert.equal(transportClosed, false); // no transport ever existed to close
});

test("B4: a handshake that never settles is cut by the race and the transport is closed", async () => {
  let transportClosed = false, clientClosed = false;
  const transport = { close() { transportClosed = true; } };
  const connectWs = async () => transport;
  class FakeClient {
    async handshake() { return new Promise(() => {}); }
    close() { clientClosed = true; }
  }
  const t0 = Date.now();
  const parts = await probeWizardLiveness(PAIRING, {
    fetchImpl: fakeFetch("x".repeat(81), { colo: "DFW" }),
    connectWs, HollowClient: FakeClient,
    probeTimeoutMs: 300, fetchTimeoutMs: 1000,
  });
  assert.ok(Date.now() - t0 < 3000);
  assert.equal(parts.handshake, false);
  assert.equal(transportClosed, true, "the dangling transport must be closed");
  assert.equal(clientClosed, true, "the dangling client must be closed");
});

test("B4 control: a prompt handshake reports all three parts true", async () => {
  const transport = { close() {} };
  const connectWs = async () => transport;
  class FakeClient { async handshake() {} close() {} }
  const parts = await probeWizardLiveness(PAIRING, {
    fetchImpl: fakeFetch("x".repeat(81), { colo: "DFW" }),
    connectWs, HollowClient: FakeClient,
    probeTimeoutMs: 2000, fetchTimeoutMs: 1000,
  });
  assert.deepEqual(parts, { facade: true, meta: true, handshake: true });
});
