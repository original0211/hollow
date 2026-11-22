// NP-1118-54: local OPEN-answer bound (client-core). Neither side's
// establishing phase had a timer, so an OPEN whose egress connect
// never settles hung the stream until the whole carrier died
// (NP-1118-52 assessment). The client now fails the stream locally
// after openTimeoutMs (default 20 s, §10.2 local parameter) —
// these cells pin: (1) a never-answered OPEN fails inside the
// bound with a non-retryable code, onFail fires, a RESET frees the
// server-side stream, and sibling streams are unaffected;
// (2) a slow-but-legitimate OPEN inside the bound is NOT killed;
// (3) openTimeoutMs 0 disables the bound (rollback switch).
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
async function makePair(connectFn, clientOpts = {}) {
  const psk = randomBytes(32);
  const [ta, tb] = memoryTransportPair();
  const v = await deriveVerifier(psk);
  const server = new HollowServer({
    transport: tb, verifiers: new Map([[1, v]]),
    ownHost: "hollow.example.workers.dev", zoneSuffix: "example.workers.dev",
    connectFn,
    fetchFn: async () => { throw new Error("no fetch in open-timeout harness"); },
  });
  const client = new HollowClient({ transport: ta, psk, keyId: 1, ...clientOpts });
  await client.handshake();
  assert.equal(client.state, "open");
  return { client, server };
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test("never-answered OPEN fails inside the bound; sibling stream and server bookkeeping unaffected", async () => {
  const { server: echo, port } = await startEcho();
  const connectFn = ({ hostname, port: p }) =>
    hostname === "hang.test" ? new Promise(() => {}) : nodeConnect({ port: p });
  const { client, server } = await makePair(connectFn, { openTimeoutMs: 300 });

  let failReason = null;
  const sHang = client.openStream({ host: "hang.test", port: 443, schemeHint: 0, gatePolicy: 0 });
  sHang.onFail = (r) => { failReason = r; };
  const t0 = Date.now();
  await assert.rejects(sHang.opened, (e) => e && e.code === ERR.STREAM_TIMEOUT);
  const elapsed = Date.now() - t0;
  assert.ok(elapsed >= 250 && elapsed < 5000, `bound fired at ${elapsed}ms`);
  assert.equal(failReason, "open timed out");
  assert.equal(sHang.state, "failed");

  // Sibling stream on the same carrier opens and echoes normally.
  const sOk = client.openStream({ host: "localhost", port, schemeHint: 0, gatePolicy: 0 });
  await sOk.opened;
  const echoed = new Promise((res) => { sOk.onData = (d) => res(Buffer.from(d).toString()); });
  sOk.write(new TextEncoder().encode("ping"));
  assert.equal(await echoed, "ping");

  // No leak on either side: the client forgot the timed-out
  // stream, and its RESET freed the server-side entry (whose
  // connect is still hanging).
  assert.equal(client.streams.size, 1);
  await sleep(150);
  assert.equal(server.streams.size, 1);
  assert.equal(client.opensSent, 2); // both OPENs were sent and counted; that is not a leak
  client.close();
  echo.close();
});

test("slow-but-legitimate OPEN inside the bound is not killed", async () => {
  const { server: echo, port } = await startEcho();
  const connectFn = async (opts) => { await sleep(700); return nodeConnect(opts); };
  const { client } = await makePair(connectFn, { openTimeoutMs: 5000 });
  const s = client.openStream({ host: "localhost", port, schemeHint: 0, gatePolicy: 0 });
  await s.opened; // ~700 ms, well inside the 5 s bound
  assert.equal(s.state, "open");
  client.close();
  echo.close();
});

test("openTimeoutMs 0 disables the bound (rollback switch)", async () => {
  const connectFn = () => new Promise(() => {});
  const { client } = await makePair(connectFn, { openTimeoutMs: 0 });
  const s = client.openStream({ host: "hang.test", port: 443, schemeHint: 0, gatePolicy: 0 });
  let settled = false;
  s.opened.then(() => { settled = true; }, () => { settled = true; });
  await sleep(600);
  assert.equal(settled, false); // still waiting, exactly the pre-NP-1118-54 behavior
  assert.equal(client.streams.size, 1);
  client.close();
});
