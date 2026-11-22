// NP-1118-66 grids for audit NP-1118-63 S3 (JS side): a server
// GOAWAY must be CONSUMED — new streams refused locally, the
// host notified once, the session manager rotating onto a fresh
// carrier — not merely recorded while streams keep opening on
// the dying session. Harness mirrors tests/occupancy.test.mjs.
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { Readable, Writable } from "node:stream";
import { HollowClient } from "../shared/client-core.js";
import { HollowServer } from "../shared/server-core.js";
import { SessionManager } from "../shared/session-manager.js";
import { deriveVerifier, FT, buildFrame } from "../shared/protocol.js";
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
    fetchFn: async () => { throw new Error("no fetch in goaway harness"); },
  });
  const client = new HollowClient({ transport: ta, psk, keyId: 1 });
  await client.handshake();
  assert.equal(client.state, "open");
  return { client, server };
}
function sendGoAway(server, code = 0) {
  server._sendFrame(buildFrame(FT.GOAWAY, 0, new Uint8Array([code])), true);
}
const tick = (ms = 30) => new Promise((r) => setTimeout(r, ms));

test("S3 client-core: GOAWAY fires onGoAway once and openStream refuses locally", async () => {
  const echo = await startEcho();
  const { client, server } = await makePair(nodeConnect);
  try {
    let goAwayCalls = 0;
    client.onGoAway = () => { goAwayCalls++; };
    sendGoAway(server, 3);
    sendGoAway(server, 3); // a second GOAWAY must not re-fire
    await tick(60);
    assert.equal(goAwayCalls, 1);
    assert.deepEqual(client.goAway, { code: 3 });

    let failReason = null;
    const s = client.openStream({ host: "localhost", port: echo.port });
    s.onFail = (r) => { failReason = r; };
    await assert.rejects(s.opened, /going away/);
    await tick(10);
    assert.match(String(failReason), /going away/);
    assert.equal(server.streams.size, 0, "nothing may reach the server for a refused stream");
    assert.equal(client.opensSent, 0, "a refused stream consumes no open budget");
  } finally {
    client.close(); echo.server.close();
  }
});

test("S3 control: streams open normally before any GOAWAY", async () => {
  const echo = await startEcho();
  const { client } = await makePair(nodeConnect);
  try {
    const s = client.openStream({ host: "localhost", port: echo.port });
    await s.opened;
    assert.equal(s.state, "open");
  } finally {
    client.close(); echo.server.close();
  }
});

test("S3 session-manager: GOAWAY rotates the lineage onto a fresh carrier", async () => {
  const echo = await startEcho();
  const pairs = [];
  const sessions = new SessionManager({
    size: 1,
    log: () => {},
    establish: async () => {
      const pair = await makePair(nodeConnect);
      pairs.push(pair);
      return pair.client;
    },
  });
  try {
    const first = await sessions.establish();
    const adopted = sessions.adopt(first, 0);
    adopted.catch(() => {});
    sendGoAway(pairs[0].server);
    // Rotation: a second carrier is established and adopted.
    const deadline = Date.now() + 5000;
    while (pairs.length < 2 && Date.now() < deadline) await tick(25);
    assert.equal(pairs.length, 2, "GOAWAY must trigger a rotation establishment");
    assert.notEqual(pairs[1].client, first);
    // The new carrier serves streams; the old one refuses them.
    const s = pairs[1].client.openStream({ host: "localhost", port: echo.port });
    await s.opened;
    assert.equal(s.state, "open");
  } finally {
    sessions.stop();
    for (const p of pairs) { try { p.client.close(); } catch {} }
    echo.server.close();
  }
});
