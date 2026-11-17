// NP-1117-23: session pool (striping) — placement unit tests with fake
// clients, plus the live migration path: a stream whose carrier hits
// the open budget and starts refusing with 0x06 is retried AWAY from
// the failed session (onto the rotated replacement or another
// carrier), never back onto it.
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { Readable, Writable } from "node:stream";
import { HollowClient } from "../shared/client-core.js";
import { HollowServer } from "../shared/server-core.js";
import { SessionManager } from "../shared/session-manager.js";
import { deriveVerifier } from "../shared/protocol.js";
import { randomBytes } from "../shared/crypto.js";
import { startSocks } from "../cli/src/socks.js";

function fakeClient() {
  return {
    state: "open", streams: new Map(), opensSent: 0, budgetExhausted: false,
    onCarrierDead: null, onOpenThreshold: null,
    close() { this.state = "dead"; },
  };
}

test("pool pick: least-loaded placement balances; exclude is honored", () => {
  const sessions = new SessionManager({
    establish: async () => { throw new Error("not used in this test"); },
    size: 3, rotationMs: 0, log: () => {},
  });
  const a = fakeClient(), b = fakeClient(), c = fakeClient();
  sessions.adopt(a); sessions.adopt(b); sessions.adopt(c);
  // Six placements, each registering its stream: perfect balance.
  for (let i = 0; i < 6; i++) {
    const p = sessions.pick();
    p.streams.set(i, {});
  }
  assert.equal(a.streams.size, 2);
  assert.equal(b.streams.size, 2);
  assert.equal(c.streams.size, 2);
  // Least-loaded beats round-robin: drain a and c, b stays loaded.
  a.streams.clear(); c.streams.clear();
  const p1 = sessions.pick();
  assert.ok(p1 === a || p1 === c);
  // Exclusion: the excluded carrier is skipped while alternatives exist.
  a.streams.clear(); b.streams.clear(); c.streams.clear();
  assert.notEqual(sessions.pick(a), a);
  assert.equal(sessions.pick(a) === a, false);
  // ...but exclusion never starves placement when it is the only one left.
  b.state = "dead"; c.state = "dead";
  assert.equal(sessions.pick(a), a);
  sessions.stop();
});

test("pool adopt: more concurrent lineages than the pool size is a host bug", () => {
  const sessions = new SessionManager({
    establish: async () => { throw new Error("not used in this test"); },
    size: 2, rotationMs: 0, log: () => {},
  });
  sessions.adopt(fakeClient());
  sessions.adopt(fakeClient());
  assert.throws(() => sessions.adopt(fakeClient()), /session pool exhausted/);
  sessions.stop();
});

// ---- live migration over a real 2-carrier pool ----

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
function readBytes(sock, n, ms = 5000) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let len = 0;
    const to = setTimeout(() => { cleanup(); reject(new Error(`readBytes timeout: got ${len}/${n}`)); }, ms);
    const on = (d) => { chunks.push(d); len += d.length; if (len >= n) { cleanup(); resolve(Buffer.concat(chunks)); } };
    const cleanup = () => { clearTimeout(to); sock.off("data", on); };
    sock.on("data", on);
  });
}

test("pool migration: 0x06 at the budget retries away from the failed session", async () => {
  const echo = net.createServer((s) => s.pipe(s));
  await new Promise((r) => echo.listen(0, "127.0.0.1", r));
  const echoPort = echo.address().port;
  const psk = randomBytes(32);
  const verifier = await deriveVerifier(psk);

  const servers = [];
  const clients = [];
  let failFirstServer = false;
  const establish = async () => {
    const [ct, st] = memoryTransportPair();
    const idx = servers.length;
    const server = new HollowServer({
      transport: st, verifiers: new Map([[1, verifier]]),
      ownHost: "hollow.example.workers.dev", zoneSuffix: "example.workers.dev",
      connectFn: async (opts) => {
        if (idx === 0 && failFirstServer) throw new Error("simulated platform refusal");
        return nodeConnect(opts);
      },
      fetchFn: async () => { throw new Error("no fetch in harness"); },
    });
    servers.push(server);
    const client = new HollowClient({ transport: ct, psk, keyId: 1 });
    await client.handshake();
    clients.push(client);
    return client;
  };

  const sessions = new SessionManager({ establish, size: 2, rotationMs: 0, log: () => {} });
  const endA = sessions.adopt(await establish()); // carrier A (servers[0])
  const endB = sessions.adopt(await establish()); // carrier B (servers[1])
  endA.catch(() => {}); endB.catch(() => {});
  const clientA = clients[0];
  const clientB = clients[1];

  // Pin one long stream on B so placement prefers A (load 0 < 1).
  const longB = clientB.openStream({ host: "localhost", port: echoPort });
  await longB.opened;
  // Burn 39 of A's 40-open budget with short streams.
  for (let i = 0; i < 39; i++) {
    const s = clientA.openStream({ host: "localhost", port: echoPort });
    await s.opened;
    s.reset(0);
  }
  assert.equal(clientA.opensSent, 39);
  failFirstServer = true; // A's next open is refused 0x06 by the "platform"

  const socks = await startSocks({
    getClient: (exclude) => sessions.pick(exclude),
    openHooks: { onOutboundExhausted: (c) => sessions.noteOutboundFailure(c) },
    port: 0, host: "127.0.0.1",
  });
  const port = socks.address().port;
  try {
    const s = net.connect(port, "127.0.0.1");
    await new Promise((r) => s.once("connect", r));
    s.write(Buffer.from([0x05, 0x01, 0x00]));
    assert.deepEqual([...(await readBytes(s, 2))], [0x05, 0x00]);
    const dom = Buffer.from("localhost", "utf8");
    s.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, dom.length]), dom,
      Buffer.from([(echoPort >> 8) & 0xff, echoPort & 0xff])]));
    const rep = await readBytes(s, 10);
    assert.equal(rep[1], 0x00, "SOCKS CONNECT must succeed via the migration retry");
    s.write(Buffer.from("migrated!"));
    assert.equal((await readBytes(s, 9)).toString(), "migrated!");
    s.destroy();

    // The failing session rotated exactly once; a replacement was
    // established; the migrated stream is NOT on the failed session.
    assert.equal(sessions.rotations, 1);
    assert.equal(clients.length, 3);
    assert.equal(servers[0].streams.size, 0);
    // B kept only its long stream; the migrated stream rides the
    // rotated replacement (least loaded after the swap).
    assert.equal(servers[1].streams.size, 1);
    assert.equal(servers[2].streams.size, 1);
  } finally {
    longB.reset(0);
    sessions.stop();
    socks.close();
    echo.close();
  }
});
