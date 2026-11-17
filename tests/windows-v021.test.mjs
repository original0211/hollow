// NP-1117-25 / spec v0.2.1: flow-control grant top-ups. The INIT
// windows stay the symmetric starting assumption; a v0.2.1 receiver
// grants up to the GRANT targets via an immediate WINDOW_UPDATE when
// the session/stream starts. These cells pin the mechanism and the
// mixed-version matrix: pre-v0.2.1 endpoints are emulated exactly by
// pinning their grants to the INIT values (top-up difference = 0).
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { Readable, Writable } from "node:stream";
import { HollowClient } from "../shared/client-core.js";
import { HollowServer } from "../shared/server-core.js";
import {
  deriveVerifier, STREAM_WINDOW_INIT, CONN_WINDOW_INIT,
  STREAM_WINDOW_GRANT, CONN_WINDOW_GRANT,
} from "../shared/protocol.js";
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
const LEGACY = { streamWindowGrant: STREAM_WINDOW_INIT, connWindowGrant: CONN_WINDOW_INIT };
const tick = (ms = 40) => new Promise((r) => setTimeout(r, ms));

let echoServer, echoPort;
async function echoTarget() {
  if (!echoServer) {
    echoServer = net.createServer((s) => s.pipe(s));
    await new Promise((r) => echoServer.listen(0, "127.0.0.1", r));
    echoPort = echoServer.address().port;
  }
  return echoPort;
}

async function makePair({ clientOpts = {}, serverOpts = {} } = {}) {
  const psk = randomBytes(32);
  const [ta, tb] = memoryTransportPair();
  const v = await deriveVerifier(psk);
  const server = new HollowServer({
    transport: tb, verifiers: new Map([[1, v]]),
    ownHost: "hollow.example.workers.dev", zoneSuffix: "example.workers.dev",
    connectFn: nodeConnect,
    fetchFn: async () => { throw new Error("no fetch in harness"); },
    ...serverOpts,
  });
  const client = new HollowClient({ transport: ta, psk, keyId: 1, ...clientOpts });
  await client.handshake();
  return { client, server };
}

function pattern(n) {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = i % 251;
  return b;
}
async function echoRoundTrip(client, port, bytes) {
  const s = client.openStream({ host: "localhost", port });
  await s.opened;
  const got = [];
  let len = 0;
  const done = new Promise((resolve, reject) => {
    const to = setTimeout(() => reject(new Error(`echo stalled at ${len}/${bytes.length}`)), 15000);
    s.onData = (d) => {
      got.push(Buffer.from(d)); len += d.length;
      if (len >= bytes.length) { clearTimeout(to); resolve(); }
    };
    s.onReset = (code) => { clearTimeout(to); reject(new Error(`stream reset: ${code}`)); };
  });
  s.write(bytes);
  await done;
  assert.ok(Buffer.concat(got).equals(Buffer.from(bytes)), "echo payload must be byte-identical");
  s.reset(0);
  return s;
}

test("v0.2.1 mechanism: top-ups land on both levels, both directions", async () => {
  const port = await echoTarget();
  const { client, server } = await makePair();
  await tick();
  // Connection level: each side's send window was topped up by the peer.
  assert.equal(client.connSendWindow, CONN_WINDOW_GRANT);
  assert.equal(server.connSendWindow, CONN_WINDOW_GRANT);
  // Stream level: the client's send window for a fresh stream reaches
  // the grant (server's top-up), and so does the server's (client's).
  const s = client.openStream({ host: "localhost", port });
  await s.opened;
  await tick();
  assert.equal(s.sendWindow, STREAM_WINDOW_GRANT);
  assert.equal(server.streams.get(s.id).sendWindow, STREAM_WINDOW_GRANT);
  s.reset(0);
  client.close();
});

test("v0.2.1 bulk: 2 MiB single-stream echo, byte-identical", async () => {
  const port = await echoTarget();
  const { client } = await makePair();
  await echoRoundTrip(client, port, pattern(2 * 1024 * 1024));
  client.close();
});

test("interop: legacy client x v0.2.1 server — 600 KiB echo both directions", async () => {
  const port = await echoTarget();
  const { client } = await makePair({ clientOpts: LEGACY });
  await echoRoundTrip(client, port, pattern(600 * 1024));
  client.close();
});

test("interop: v0.2.1 client x legacy server — 600 KiB echo both directions", async () => {
  const port = await echoTarget();
  const { client } = await makePair({ serverOpts: LEGACY });
  await echoRoundTrip(client, port, pattern(600 * 1024));
  client.close();
});

test("interop: legacy x legacy still works above the legacy window", async () => {
  const port = await echoTarget();
  const { client } = await makePair({ clientOpts: LEGACY, serverOpts: LEGACY });
  await echoRoundTrip(client, port, pattern(300 * 1024));
  client.close();
});
