// NP-1118-66 grids for audit NP-1118-63 S1: the CLI establishment
// (cli/src/establish.js) must bound connect + handshake under one
// shared deadline, so a blackholed entry cannot park the CLI
// supervisor inside its first attempt forever. Short injected
// budgets; the production default is 20 s.
import { test } from "node:test";
import assert from "node:assert/strict";
import { establishClient, ESTABLISH_TIMEOUT_MS } from "../cli/src/establish.js";

test("S1 default: the production establishment budget is 20 s", () => {
  assert.equal(ESTABLISH_TIMEOUT_MS, 20000);
});

test("S1: a connect that never settles is cut by the shared deadline", async () => {
  const t0 = Date.now();
  await assert.rejects(
    () => establishClient({
      url: "wss://127.0.0.1:1", psk: new Uint8Array(32), keyId: 1,
      timeoutMs: 300,
      connectWsImpl: () => new Promise(() => {}),
    }),
    /establishment timed out/,
  );
  assert.ok(Date.now() - t0 < 3000);
});

test("S1: a handshake that never settles is cut, and both layers are closed", async () => {
  let transportClosed = false, clientClosed = false;
  const transport = { close() { transportClosed = true; } };
  class FakeClient {
    async handshake() { return new Promise(() => {}); }
    close() { clientClosed = true; }
  }
  const t0 = Date.now();
  await assert.rejects(
    () => establishClient({
      url: "wss://x", psk: new Uint8Array(32), keyId: 1,
      timeoutMs: 300,
      connectWsImpl: async () => transport,
      HollowClientImpl: FakeClient,
    }),
    /establishment timed out/,
  );
  assert.ok(Date.now() - t0 < 3000);
  assert.equal(transportClosed, true);
  assert.equal(clientClosed, true);
});

test("S1: a client completing after the deadline is closed on arrival, not leaked", async () => {
  let clientClosed = false;
  class LateClient {
    async handshake() { /* resolves immediately once constructed */ }
    close() { clientClosed = true; }
  }
  const transport = { close() {} };
  await assert.rejects(
    () => establishClient({
      url: "wss://x", psk: new Uint8Array(32), keyId: 1,
      timeoutMs: 200,
      connectWsImpl: () => new Promise((res) => setTimeout(() => res(transport), 500)),
      HollowClientImpl: LateClient,
    }),
    /establishment timed out/,
  );
  await new Promise((r) => setTimeout(r, 600)); // let the late work land
  assert.equal(clientClosed, true, "the late client must be closed by the leak guard");
});

test("S1 control: a prompt establishment returns the client", async () => {
  class FakeClient { async handshake() {} close() {} }
  const transport = { close() {} };
  const client = await establishClient({
    url: "wss://x", psk: new Uint8Array(32), keyId: 1,
    timeoutMs: 2000,
    connectWsImpl: async () => transport,
    HollowClientImpl: FakeClient,
  });
  assert.ok(client instanceof FakeClient);
});
