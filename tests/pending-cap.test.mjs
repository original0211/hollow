// NP-1118-66 grids for audit NP-1118-63 S4 (JS side): a stream's
// pending queue is capped. A peer that stops granting window
// must not let write() keep accepting data into unbounded memory
// while reporting success — overflow fails the stream and
// write() returns false. Harness mirrors tests/goaway.test.mjs.
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { Readable, Writable } from "node:stream";
import { HollowClient, STREAM_PENDING_MAX_BYTES } from "../shared/client-core.js";
import { HollowServer } from "../shared/server-core.js";
import { deriveVerifier } from "../shared/protocol.js";
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
async function makePair(clientOpts = {}) {
  const psk = randomBytes(32);
  const [ta, tb] = memoryTransportPair();
  const v = await deriveVerifier(psk);
  const server = new HollowServer({
    transport: tb, verifiers: new Map([[1, v]]),
    ownHost: "hollow.example.workers.dev", zoneSuffix: "example.workers.dev",
    connectFn: nodeConnect,
    fetchFn: async () => { throw new Error("no fetch in pending harness"); },
  });
  const client = new HollowClient({ transport: ta, psk, keyId: 1, ...clientOpts });
  await client.handshake();
  assert.equal(client.state, "open");
  return { client, server };
}

test("S4 default: the production pending cap is 4 MiB", () => {
  assert.equal(STREAM_PENDING_MAX_BYTES, 4 * 1024 * 1024);
});

test("S4: overflow fails the stream, write returns false, nothing is silently held", async () => {
  const echo = await startEcho();
  const { client, server } = await makePair({ streamPendingMaxBytes: 1024 });
  try {
    const s = client.openStream({ host: "localhost", port: echo.port });
    await s.opened;
    let failReason = null;
    s.onFail = (r) => { failReason = r; };
    // White-box stall: the peer grants no further window.
    s.sendWindow = 0;
    client.connSendWindow = 0;
    assert.equal(s.write(new Uint8Array(600)), true);
    assert.equal(s.pendingBytes, 600);
    assert.equal(s.write(new Uint8Array(600)), false, "the overflowing write must be refused");
    assert.equal(s.state, "failed");
    assert.match(String(failReason), /send queue overflow/);
    assert.equal(client.streams.has(s.id), false, "the failed stream is forgotten");
    await new Promise((r) => setTimeout(r, 30)); // the RESET rides the transport
    assert.equal(server.streams.has(s.id), false, "the RESET frees the server side too");
  } finally {
    client.close(); echo.server.close();
  }
});

test("S4 control: with window available, writes frame immediately and pending drains to zero", async () => {
  const echo = await startEcho();
  const { client } = await makePair({ streamPendingMaxBytes: 1024 });
  try {
    const s = client.openStream({ host: "localhost", port: echo.port });
    await s.opened;
    assert.equal(s.write(new Uint8Array(600)), true);
    assert.equal(s.pendingBytes, 0, "framing is synchronous when window allows");
    assert.equal(s.state, "open");
  } finally {
    client.close(); echo.server.close();
  }
});
