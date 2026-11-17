// §7.5 occupancy regression (NP-1117-08): spec v0.2.0 counts only
// IN-FLIGHT ESTABLISHMENTS. The pre-fix implementation counted each
// stream's whole lifetime, so 6 browser keep-alive streams wedged the
// session (OPEN_QUEUED -> 5,000 ms -> 0x01). Both cells below are red
// on the old implementation and green on the new one.
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { Readable, Writable } from "node:stream";
import { HollowClient } from "../shared/client-core.js";
import { HollowServer } from "../shared/server-core.js";
import { deriveVerifier, ERR } from "../shared/protocol.js";
import { randomBytes } from "../shared/crypto.js";

function memoryTransportPair() {
  const a = { cb: null, closeCb: null };
  const b = { cb: null, closeCb: null };
  a.send = (bytes) => setImmediate(() => b.cb && b.cb(bytes));
  b.send = (bytes) => setImmediate(() => a.cb && a.cb(bytes));
  a.close = () => setImmediate(() => b.closeCb && b.closeCb());
  b.close = () => setImmediate(() => a.closeCb && a.closeCb());
  a.closeCarrier = a.close; b.closeCarrier = b.close;
  a.onMessage = (cb) => { a.cb = cb; };
  b.onMessage = (cb) => { b.cb = cb; };
  a.onClose = (cb) => { a.closeCb = cb; };
  b.onClose = (cb) => { b.closeCb = cb; };
  return [a, b];
}
function nodeConnect({ port }) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, "127.0.0.1");
    sock.once("error", reject);
    sock.once("connect", () => resolve({
      readable: Readable.toWeb(sock), writable: Writable.toWeb(sock),
      opened: Promise.resolve(), close: () => sock.destroy(),
    }));
  });
}
async function startEcho() {
  const server = net.createServer((s) => s.pipe(s));
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { server, port: server.address().port };
}
async function makePair(connectFn) {
  const psk = randomBytes(32);
  const [ta, tb] = memoryTransportPair();
  const v = await deriveVerifier(psk);
  const server = new HollowServer({
    transport: tb, verifiers: new Map([[1, v]]),
    ownHost: "hollow.example.workers.dev", zoneSuffix: "example.workers.dev",
    connectFn,
    fetchFn: async () => { throw new Error("no fetch in occupancy harness"); },
  });
  const client = new HollowClient({ transport: ta, psk, keyId: 1 });
  await client.handshake();
  assert.equal(client.state, "open");
  return { client, server };
}

test("burst cell: 24 streams opened at once all establish, none rejected 0x01", async () => {
  const { server: echo, port } = await startEcho();
  const { client, server } = await makePair(nodeConnect);
  const N = 24;
  const streams = [];
  const results = [];
  for (let i = 0; i < N; i++) {
    const s = client.openStream({ host: "localhost", port, schemeHint: 0, gatePolicy: 0 });
    streams.push(s);
    results.push(s.opened.then(
      () => ({ ok: true }),
      (e) => ({ ok: false, code: e && e.code }),
    ));
  }
  const settled = await Promise.all(results);
  const rejected = settled.filter((r) => !r.ok);
  assert.equal(rejected.length, 0, `no stream may be rejected (got ${JSON.stringify(rejected)})`);
  assert.ok(!settled.some((r) => r.code === ERR.CONCURRENCY_LIMIT), "no 0x01 concurrency_limit");
  // keep-alive: all 24 stay open and usable
  assert.equal(server.streams.size, N);
  assert.equal(server.occupancy, 0); // every establishment has concluded
  const probe = streams[7];
  const echoed = new Promise((res) => {
    const chunks = [];
    probe.onData = (d) => { chunks.push(Buffer.from(d)); if (Buffer.concat(chunks).length >= 4) res(Buffer.concat(chunks).toString()); };
  });
  probe.write(new TextEncoder().encode("ping"));
  assert.equal(await echoed, "ping");
  client.close();
  echo.close();
});

test("dead-hold cell: 6 established keep-alive streams do not block a 7th", async () => {
  const { server: echo, port } = await startEcho();
  const { client, server } = await makePair(nodeConnect);
  const held = [];
  for (let i = 0; i < 6; i++) {
    const s = client.openStream({ host: "localhost", port, schemeHint: 0, gatePolicy: 0 });
    await s.opened;
    held.push(s); // established, deliberately kept alive and idle
  }
  assert.equal(server.occupancy, 0);
  const s7 = client.openStream({ host: "localhost", port, schemeHint: 0, gatePolicy: 0 });
  await s7.opened; // old implementation: queued 5,000 ms -> rejected 0x01
  const s8 = client.openStream({ host: "localhost", port, schemeHint: 0, gatePolicy: 0 });
  await s8.opened;
  assert.equal(server.streams.size, 8);
  client.close();
  echo.close();
});

test("pairing: occupancy tracks in-flight establishments and returns to 0 on success and on failure", async () => {
  const { server: echo, port } = await startEcho();
  // success side: establishments held in flight by a 300 ms connect delay
  const slowConnect = async (opts) => {
    await new Promise((r) => setTimeout(r, 300));
    return nodeConnect(opts);
  };
  {
    const { client, server } = await makePair(slowConnect);
    const pending = [0, 1, 2].map(() => client.openStream({ host: "localhost", port, schemeHint: 0, gatePolicy: 0 }));
    await new Promise((r) => setTimeout(r, 120)); // all three in flight
    assert.equal(server.occupancy, 3);
    await Promise.all(pending.map((s) => s.opened));
    assert.equal(server.occupancy, 0);
    client.close();
  }
  // failure side: every establishment is refused by the target side
  {
    const failConnect = async () => { throw new Error("connect ECONNREFUSED 127.0.0.1:9"); };
    const { client, server } = await makePair(failConnect);
    const attempts = [0, 1, 2].map(() => client.openStream({ host: "localhost", port: 9, schemeHint: 0, gatePolicy: 0 }));
    const codes = await Promise.all(attempts.map((s) => s.opened.then(() => null, (e) => e && e.code)));
    assert.ok(codes.every((c) => c === ERR.TARGET_UNREACHABLE), `expected target_unreachable, got ${JSON.stringify(codes)}`);
    assert.equal(server.occupancy, 0);
    client.close();
  }
  echo.close();
});
