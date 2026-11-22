// NP-1118-32: phoenix (pre-first-byte transparent reopen), JS
// mirror of the Go grids in android/core/session/phoenix_test.go.
// Driven through the real SOCKS pump + SessionManager pool over
// memory transports, with controllable fake targets server-side.
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { HollowClient } from "../shared/client-core.js";
import { HollowServer } from "../shared/server-core.js";
import { SessionManager } from "../shared/session-manager.js";
import { deriveVerifier } from "../shared/protocol.js";
import { randomBytes } from "../shared/crypto.js";
import { startSocks } from "../cli/src/socks.js";
import { wrapPhoenixStream, replayableFlight, PhoenixBreaker, phoenixShared } from "../shared/phoenix.js";

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

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(what, cond, ms = 12000) {
  const t0 = Date.now();
  for (;;) {
    if (cond()) return;
    if (Date.now() - t0 > ms) throw new Error(`timeout waiting for ${what}`);
    await sleep(20);
  }
}

async function makeRig() {
  const psk = randomBytes(32);
  const verifier = await deriveVerifier(psk);
  const targets = [];
  const transports = [];
  const rig = { targets, transports, killAll: false };
  // A memory pair's close() only notifies the PEER end, so killing
  // a carrier means closing both ends (client learns via st.close,
  // server via ct.close).
  rig.killCarrier = (idx) => {
    const [ct, st] = transports[idx];
    try { ct.closeCarrier(); } catch {}
    try { st.closeCarrier(); } catch {}
  };
  const establish = async () => {
    const [ct, st] = memoryTransportPair();
    const idx = transports.length;
    transports.push([ct, st]);
    new HollowServer({
      transport: st, verifiers: new Map([[1, verifier]]),
      ownHost: "hollow.example.workers.dev", zoneSuffix: "example.workers.dev",
      connectFn: async () => {
        const t = { carrier: idx, received: [], echoedBytes: 0, ctl: null, echo: false };
        const readable = new ReadableStream({ start(c) { t.ctl = c; } });
        const writable = new WritableStream({
          write(chunk) {
            const b = Buffer.from(chunk);
            t.received.push(b);
            if (t.echo) { t.ctl.enqueue(b); t.echoedBytes += b.length; }
          },
        });
        targets.push(t);
        if (rig.killAll) setTimeout(() => rig.killCarrier(idx), 60);
        return { readable, writable, opened: Promise.resolve(), close: () => { try { t.ctl.close(); } catch {} } };
      },
      fetchFn: async () => { throw new Error("no fetch in harness"); },
    });
    const client = new HollowClient({ transport: ct, psk, keyId: 1 });
    await client.handshake();
    return client;
  };
  rig.sessions = new SessionManager({ establish, size: 2, rotationMs: 0, log: () => {} });
  rig.endA = rig.sessions.adopt(await establish());
  rig.endB = rig.sessions.adopt(await establish());
  rig.endA.catch(() => {}); rig.endB.catch(() => {});
  rig.socks = await startSocks({
    getClient: (exclude) => rig.sessions.pick(exclude),
    openHooks: { onOutboundExhausted: (c) => rig.sessions.noteOutboundFailure(c) },
    port: 0, host: "127.0.0.1",
  });
  rig.socksPort = rig.socks.address().port;
  rig.close = async () => {
    rig.socks.close();
    rig.sessions.stop();
  };
  return rig;
}

function flushTarget(t) {
  const all = Buffer.concat(t.received);
  const rest = all.subarray(t.echoedBytes);
  if (rest.length > 0) {
    t.ctl.enqueue(rest);
    t.echoedBytes += rest.length;
  }
}

function readBytes(sock, n, ms = 12000) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let len = 0;
    const to = setTimeout(() => { cleanup(); reject(new Error(`readBytes timeout: got ${len}/${n}`)); }, ms);
    const on = (d) => { chunks.push(d); len += d.length; if (len >= n) { cleanup(); resolve(Buffer.concat(chunks)); } };
    const cleanup = () => { clearTimeout(to); sock.off("data", on); };
    sock.on("data", on);
  });
}

async function socksConnect(rig) {
  const s = net.connect(rig.socksPort, "127.0.0.1");
  await new Promise((r) => s.once("connect", r));
  s.write(Buffer.from([0x05, 0x01, 0x00]));
  assert.deepEqual([...(await readBytes(s, 2))], [0x05, 0x00]);
  const dom = Buffer.from("localhost", "utf8");
  s.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, dom.length]), dom, Buffer.from([0x01, 0xbb])]));
  const rep = await readBytes(s, 10);
  assert.equal(rep[1], 0x00, "SOCKS CONNECT must succeed");
  return s;
}

function socketClosed(sock, ms = 12000) {
  return new Promise((resolve, reject) => {
    if (sock.destroyed) return resolve();
    const to = setTimeout(() => reject(new Error("socket was not destroyed in time")), ms);
    sock.once("close", () => { clearTimeout(to); resolve(); });
  });
}

const GET_FLIGHT = Buffer.from("GET /page HTTP/1.1\r\nHost: example.test\r\n\r\n");

test("phoenix: kill after open, before write — flight replayed whole on a new carrier", async () => {
  const rig = await makeRig();
  const r0 = phoenixShared.reopens, s0 = phoenixShared.saved;
  try {
    const sock = await socksConnect(rig);
    await waitFor("target 0", () => rig.targets.length === 1);
    rig.killCarrier(rig.targets[0].carrier);
    sock.write(GET_FLIGHT);
    await waitFor("target 1", () => rig.targets.length === 2);
    await waitFor("target 1 got the flight", () => Buffer.concat(rig.targets[1].received).equals(GET_FLIGHT));
    assert.equal(Buffer.concat(rig.targets[0].received).length, 0, "dead target received nothing");
    flushTarget(rig.targets[1]);
    assert.ok((await readBytes(sock, GET_FLIGHT.length)).equals(GET_FLIGHT), "echo must be byte-exact");
    assert.equal(phoenixShared.reopens - r0, 1);
    assert.equal(phoenixShared.saved - s0, 1);
    sock.destroy();
  } finally { await rig.close(); }
});

test("phoenix: kill mid-flight (TLS-shaped, two writes) — spliced replay is byte-exact", async () => {
  const rig = await makeRig();
  try {
    const sock = await socksConnect(rig);
    await waitFor("target 0", () => rig.targets.length === 1);
    const part1 = Buffer.from([0x16, 0x03, 0x01, 0x00, 0x2a]);
    const part2 = Buffer.from([0x01, 0x00, 0x00, 0x26, 0x03, 0x03]);
    const full = Buffer.concat([part1, part2]);
    sock.write(part1);
    await waitFor("target 0 got part1", () => Buffer.concat(rig.targets[0].received).equals(part1));
    rig.killCarrier(rig.targets[0].carrier);
    sock.write(part2);
    await waitFor("target 1", () => rig.targets.length === 2);
    await waitFor("target 1 got the full flight", () => Buffer.concat(rig.targets[1].received).equals(full));
    flushTarget(rig.targets[1]);
    assert.ok((await readBytes(sock, full.length)).equals(full));
    sock.destroy();
  } finally { await rig.close(); }
});

test("phoenix: kill after full flight, before first byte — replay delivers exactly one copy", async () => {
  const rig = await makeRig();
  try {
    const sock = await socksConnect(rig);
    await waitFor("target 0", () => rig.targets.length === 1);
    sock.write(GET_FLIGHT);
    await waitFor("target 0 got the flight", () => Buffer.concat(rig.targets[0].received).equals(GET_FLIGHT));
    rig.killCarrier(rig.targets[0].carrier);
    await waitFor("target 1", () => rig.targets.length === 2);
    await waitFor("target 1 got the flight", () => Buffer.concat(rig.targets[1].received).equals(GET_FLIGHT));
    flushTarget(rig.targets[1]);
    assert.ok((await readBytes(sock, GET_FLIGHT.length)).equals(GET_FLIGHT));
    sock.destroy();
  } finally { await rig.close(); }
});

test("phoenix gate: POST and opaque flights are NOT replayed", async () => {
  for (const [name, flight] of [
    ["POST", Buffer.from("POST /x HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc")],
    ["opaque", Buffer.from([0x01, 0x02, 0x03, 0x04])],
  ]) {
    const rig = await makeRig();
    const r0 = phoenixShared.reopens;
    try {
      const sock = await socksConnect(rig);
      await waitFor("target 0", () => rig.targets.length === 1);
      sock.write(flight);
      await waitFor("target 0 got the flight", () => Buffer.concat(rig.targets[0].received).equals(flight));
      rig.killCarrier(rig.targets[0].carrier);
      await socketClosed(sock);
      await sleep(400);
      assert.equal(rig.targets.length, 1, `${name}: no reopen stream may be created`);
      assert.equal(phoenixShared.reopens - r0, 0, `${name}: reopens must stay 0`);
    } finally { await rig.close(); }
  }
});

test("phoenix: death AFTER the first byte is not reopened", async () => {
  const rig = await makeRig();
  try {
    const sock = await socksConnect(rig);
    await waitFor("target 0", () => rig.targets.length === 1);
    rig.targets[0].echo = true;
    sock.write(GET_FLIGHT);
    assert.ok((await readBytes(sock, GET_FLIGHT.length)).equals(GET_FLIGHT), "echo before kill");
    rig.killCarrier(rig.targets[0].carrier);
    await socketClosed(sock);
    await sleep(300);
    assert.equal(rig.targets.length, 1, "no reopen after first byte");
  } finally { await rig.close(); }
});

test("phoenix: kill-everything server — attempts and time stay bounded, flow fails", async () => {
  const rig = await makeRig();
  rig.killAll = true;
  const r0 = phoenixShared.reopens;
  try {
    const t0 = Date.now();
    const sock = await socksConnect(rig);
    sock.write(GET_FLIGHT);
    await socketClosed(sock, 25000);
    const elapsed = Date.now() - t0;
    assert.ok(rig.targets.length <= 3, `targets ${rig.targets.length} <= 3`);
    assert.ok(phoenixShared.reopens - r0 <= 2, "reopens capped at 2");
    assert.ok(elapsed < 25000, `failure bounded in time (${elapsed} ms)`);
  } finally { await rig.close(); }
});

test("phoenix: breaker open — no reopen is attempted", async () => {
  const rig = await makeRig();
  const prevUntil = phoenixShared.breaker.openUntil;
  phoenixShared.breaker.openUntil = Date.now() + 60000;
  const r0 = phoenixShared.reopens;
  try {
    const sock = await socksConnect(rig);
    await waitFor("target 0", () => rig.targets.length === 1);
    sock.write(GET_FLIGHT);
    await waitFor("target 0 got the flight", () => Buffer.concat(rig.targets[0].received).equals(GET_FLIGHT));
    rig.killCarrier(rig.targets[0].carrier);
    await socketClosed(sock);
    await sleep(300);
    assert.equal(rig.targets.length, 1, "breaker must block the reopen");
    assert.equal(phoenixShared.reopens - r0, 0);
    sock.destroy();
  } finally {
    phoenixShared.breaker.openUntil = prevUntil;
    phoenixShared.breaker.fastDeaths = 0;
    await rig.close();
  }
});

test("replayableFlight table (Go parity)", () => {
  const cases = [
    [Buffer.alloc(0), true],
    [Buffer.from([0x16]), true],
    [Buffer.from([0x16, 0x03, 0x01]), true],
    [Buffer.from([0x16, 0x02]), false],
    [Buffer.from("GET / HTTP/1.1\r\n\r\n"), true],
    [Buffer.from("HEAD / HTTP/1.1\r\n\r\n"), true],
    [Buffer.from("PUT /x HTTP/1.1\r\n\r\n"), true],
    [Buffer.from("DELETE /x HTTP/1.1\r\n\r\n"), true],
    [Buffer.from("POST /x HTTP/1.1\r\n\r\n"), false],
    [Buffer.from("PATCH /x HTTP/1.1\r\n\r\n"), false],
    [Buffer.from("G"), true],
    [Buffer.from("PO"), false],
    [Buffer.from([0x01, 0x02]), false],
    [Buffer.from("SSH-2.0-client"), false],
  ];
  for (const [buf, want] of cases) assert.equal(replayableFlight(buf), want, JSON.stringify(buf));
});

test("PhoenixBreaker state machine (Go parity)", () => {
  const b = new PhoenixBreaker();
  assert.ok(b.allow());
  for (let i = 0; i < 5; i++) b.noteFastDeath();
  assert.ok(!b.allow(), "breaker opens at the threshold");
  assert.equal(b.trips, 1);
  b.openUntil = Date.now() - 1;
  assert.ok(b.allow(), "breaker allows again after cooldown");
});

// --- NP-1118-48: cost-scaled window / fast-death (JS parity) ---

import { phoenixWindowFor, phoenixFastDeathFor } from "../shared/phoenix.js";

test("phoenix scaling formulas (Go parity table)", () => {
  const win = [[0, 15000], [1000, 15000], [2000, 15000], [4000, 17000], [6000, 23000], [10000, 35000], [20000, 45000], [60000, 45000]];
  for (const [cost, want] of win) assert.equal(phoenixWindowFor(cost), want, `window(${cost})`);
  const fast = [[0, 2000], [1000, 2000], [2000, 3000], [4000, 6000], [6000, 9000], [7000, 10000], [20000, 10000]];
  for (const [cost, want] of fast) assert.equal(phoenixFastDeathFor(cost), want, `fastDeath(${cost})`);
});

class FakeStream {
  constructor() {
    this.opened = Promise.resolve();
    this.id = 1; this.gate = null; this.state = "open"; this.pending = [];
    this.paused = false; this.written = [];
  }
  write(b) { this.written.push(Buffer.from(b)); return true; }
  reset() {} closeWrite() {} consume() {}
  die() { if (this.onFail) this.onFail("carrier dead"); }
}

function freshShared(costMs = 0) {
  const shared = { breaker: new PhoenixBreaker(), reopens: 0, saved: 0 };
  // Seed via the DIAL component: in production the bridge feeds
  // carrier-establishment durations there (the wrapper's own
  // attempt samples start at wrap time and cannot see the dial).
  if (costMs > 0) shared.breaker.noteDialCost(costMs);
  return shared;
}

const TLS_FLIGHT = Buffer.from([0x16, 0x03, 0x01, 0x00, 0x2e, 0xaa]);

test("NP-1118-48 window: a death 16s after dial reopens ONLY under the scaled window", async () => {
  // cost 0 -> window is the historical 15s: a death at 16s is final.
  {
    const shared = freshShared(0);
    let redials = 0;
    const s1 = new FakeStream();
    const w = wrapPhoenixStream(s1, async () => { redials++; return new FakeStream(); }, shared);
    w.write(TLS_FLIGHT);
    w._t0 = Date.now() - 16_000;
    s1.die();
    await sleep(30);
    assert.equal(redials, 0);
    assert.equal(w.state, "failed");
  }
  // cost 6s -> window 23s: the same death at 16s reopens.
  {
    const shared = freshShared(6000);
    let redials = 0;
    const s1 = new FakeStream();
    const w = wrapPhoenixStream(s1, async () => { redials++; return new FakeStream(); }, shared);
    w.write(TLS_FLIGHT);
    w._t0 = Date.now() - 16_000;
    s1.die();
    await waitFor("redial under scaled window", () => redials === 1);
    assert.equal(shared.reopens, 1);
  }
});

test("NP-1118-48 fast-death: deaths 3s after birth trip the breaker ONLY under the scaled bar", async () => {
  const run = async (costMs) => {
    const shared = freshShared(costMs);
    for (let flow = 0; flow < 5; flow++) {
      // The bridge re-seeds the dial component from real carrier
      // establishments continuously; model that per flow.
      if (costMs > 0) shared.breaker.noteDialCost(costMs);
      const s1 = new FakeStream();
      const streams = [s1];
      const w = wrapPhoenixStream(s1, async () => { await sleep(200); const s = new FakeStream(); streams.push(s); return s; }, shared);
      w.write(TLS_FLIGHT);
      s1.die(); // first death: earns the reopen
      await waitFor("reopen", () => streams.length === 2);
      w._curBorn = Date.now() - 3000; // the reopened stream dies 3s after birth
      streams[1].die();
      await sleep(20);
      w.reset(); // stop this flow's machinery (the fast-death was noted synchronously)
    }
    return shared;
  };
  // Old fixed bar (2s): a 3s-after-birth death is NOT fast -> no trip.
  const cold = await run(0);
  assert.equal(cold.breaker.trips, 0);
  // Scaled bar at cost 6s (9s): the same deaths are fast -> trips.
  const hot = await run(6000);
  assert.equal(hot.breaker.trips, 1);
  assert.equal(hot.breaker.allow(), false);
});

test("NP-1118-66 S5: a write in the redial gap after protection ended is refused, not dropped", () => {
  const shared = freshShared(0);
  // Unprotected gap (first byte already seen in production terms):
  // the chunk would be discarded — write must say so.
  const w1 = wrapPhoenixStream(new FakeStream(), async () => new FakeStream(), shared);
  w1._cur = null; w1._protected = false;
  assert.equal(w1.write(Buffer.from("lost?")), false);
  // Protected gap: the chunk is buffered for replay — accepted.
  const w2 = wrapPhoenixStream(new FakeStream(), async () => new FakeStream(), shared);
  w2._cur = null; w2._protected = true;
  assert.equal(w2.write(Buffer.from("held")), true);
  assert.equal(Buffer.concat(w2._buf).toString(), "held");
  // Live stream: forwarding unchanged.
  const s3 = new FakeStream();
  const w3 = wrapPhoenixStream(s3, async () => new FakeStream(), shared);
  assert.equal(w3.write(Buffer.from("live")), true);
  assert.equal(s3.written.length, 1);
});
