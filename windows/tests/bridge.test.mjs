// CoreBridge tests (M2-1, NP-1114-03): hermetic — a real HollowServer over
// in-memory transports (the M1 harness pattern), injected into the bridge
// through its transport factory. Covers the state machine, §8.4 backoff
// shape, rotation, the fatal-auth class, SOCKS port increment + lifecycle.
import { test as _test, before } from "node:test";
const test = (name, fn) => _test(name, { timeout: 20000 }, fn);
import assert from "node:assert/strict";
import net from "node:net";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { Readable, Writable } from "node:stream";
import path from "node:path";
import { fileURLToPath } from "node:url";

// The bridge imports the vendored core; prepare it (idempotent file copies).
const winDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
execFileSync("node", [path.join(winDir, "tools", "prepare-vendor.mjs")], { stdio: "ignore" });

const { CoreBridge, backoffDelay } = await import("../src/core-bridge.js");
const { HollowServer } = await import("../vendor/shared/server-core.js");
const { HollowClient } = await import("../vendor/shared/client-core.js");
const { SessionManager } = await import("../vendor/shared/session-manager.js");
const { deriveVerifier } = await import("../vendor/shared/protocol.js");

function memoryTransportPair() {
  const a = { cb: null, closeCb: null };
  const b = { cb: null, closeCb: null };
  a.send = (x) => setImmediate(() => b.cb && b.cb(x));
  b.send = (x) => setImmediate(() => a.cb && a.cb(x));
  a.close = () => setImmediate(() => b.closeCb && b.closeCb());
  b.close = () => setImmediate(() => a.closeCb && a.closeCb());
  a.closeCarrier = a.close; b.closeCarrier = b.close;
  a.onMessage = (cb) => { a.cb = cb; }; b.onMessage = (cb) => { b.cb = cb; };
  a.onClose = (cb) => { a.closeCb = cb; }; b.onClose = (cb) => { b.closeCb = cb; };
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

let echoServer, echoPort, PSK, VERIFIER;
before(async () => {
  echoServer = net.createServer((s) => s.pipe(s));
  await new Promise((r) => echoServer.listen(0, "127.0.0.1", r));
  echoPort = echoServer.address().port;
  PSK = new Uint8Array(crypto.randomBytes(32));
  VERIFIER = await deriveVerifier(PSK);
});

// Each factory call = a fresh carrier: new transport pair + new server.
function makeFactory(serverPskVerifier = VERIFIER, hooks = {}) {
  return async () => {
    const [ct, st] = memoryTransportPair();
    const server = new HollowServer({
      transport: st, verifiers: new Map([[1, serverPskVerifier]]),
      ownHost: "test.workers.dev", zoneSuffix: "workers.dev",
      connectFn: nodeConnect, fetchFn: async () => { throw new Error("no fetch in harness"); },
    });
    hooks.onCarrier?.(st, server);
    return ct;
  };
}
const waitFor = async (fn, ms = 8000) => {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { if (fn()) return; await new Promise((r) => setTimeout(r, 25)); }
  throw new Error("waitFor timeout");
};
const mkBridge = (opts = {}) => new CoreBridge({
  workerUrl: "wss://test.workers.dev/", psk: PSK, keyId: 1,
  makeTransport: makeFactory(), backoffBaseMs: 40, backoffCapMs: 200, poolSize: 1, ...opts,
});

test("backoffDelay: §8.4 shape (1s doubling, 60s cap, ±25% jitter)", () => {
  const mid = () => 0.5; // jitter factor exactly 1.0
  assert.equal(backoffDelay(1, 1000, 60000, mid), 1000);
  assert.equal(backoffDelay(2, 1000, 60000, mid), 2000);
  assert.equal(backoffDelay(3, 1000, 60000, mid), 4000);
  assert.equal(backoffDelay(7, 1000, 60000, mid), 60000);
  assert.equal(backoffDelay(20, 1000, 60000, mid), 60000);
  for (let i = 0; i < 50; i++) {
    const d = backoffDelay(1, 1000, 60000);
    assert.ok(d >= 750 && d <= 1250, `jitter bounds: ${d}`);
  }
});

test("connect -> connected; stream echoes; counters move", async () => {
  const b = mkBridge();
  await b.connect();
  await waitFor(() => b.state === "connected");
  const s = b.client.openStream({ host: "localhost", port: echoPort, schemeHint: 0, gatePolicy: 0 });
  await s.opened;
  const got = [];
  const done = new Promise((res) => { s.onData = (d) => { got.push(Buffer.from(d)); if (Buffer.concat(got).length >= 5) res(); }; });
  s.write(new TextEncoder().encode("hello"));
  await done;
  assert.equal(Buffer.concat(got).toString(), "hello");
  assert.equal(b.stats.carriers, 1);
  assert.equal(b.stats.streams, 1);
  await b.disconnect();
  assert.equal(b.state, "disconnected");
});

test("carrier death -> reconnecting -> connected on a fresh carrier", async () => {
  let serverTransport = null;
  const b = mkBridge({ makeTransport: makeFactory(VERIFIER, { onCarrier: (st) => { serverTransport = st; } }) });
  const states = [];
  b.onEvent((ev) => { if (ev.type === "state") states.push(ev.state); });
  await b.connect();
  await waitFor(() => b.state === "connected" && b.stats.carriers === 1);
  serverTransport.close(); // simulate the carrier dropping
  await waitFor(() => b.stats.carriers === 2 && b.state === "connected");
  assert.ok(states.includes("reconnecting"), `states seen: ${states.join(",")}`);
  await b.disconnect();
});

test("rotation: carrier is replaced at the rotation interval", async () => {
  const b = mkBridge({ rotationMs: 300 });
  await b.connect();
  await waitFor(() => b.stats.carriers >= 2, 10000);
  assert.equal(b.state, "connected");
  await b.disconnect();
});

test("wrong PSK -> Error terminal state, no retry", async () => {
  const bad = new CoreBridge({
    workerUrl: "wss://test.workers.dev/", psk: new Uint8Array(crypto.randomBytes(32)), keyId: 1,
    makeTransport: makeFactory(), backoffBaseMs: 40, backoffCapMs: 200,
  });
  await bad.connect();
  await waitFor(() => bad.state === "error");
  assert.match(bad.stateDetail, /fatal/i);
  const carriers = bad.stats.carriers;
  await new Promise((r) => setTimeout(r, 400));
  assert.equal(bad.state, "error");
  assert.equal(bad.stats.carriers, carriers);
  await bad.disconnect();
});

test("SOCKS: occupied port increments; traffic flows; stop closes the port", async () => {
  const dummy = net.createServer(() => {});
  await new Promise((r) => dummy.listen(0, "127.0.0.1", r));
  const occupied = dummy.address().port;
  const b = mkBridge();
  await b.connect();
  await waitFor(() => b.state === "connected");
  const port = await b.startSocks(occupied);
  assert.equal(port, occupied + 1);
  // Minimal SOCKS5 client: CONNECT to the echo server, relay a line.
  let clientSock = null;
  const reply = await new Promise((resolve, reject) => {
    const sock = net.connect(port, "127.0.0.1", () => sock.write(Buffer.from([5, 1, 0])));
    clientSock = sock;
    let stage = 0; let buf = Buffer.alloc(0);
    sock.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 0 && buf.length >= 2) {
        // Domain ATYP with "localhost": a literal 127.0.0.1 target is refused
        // by the server as a private/loop target (spec), as in production.
        const host = Buffer.from("localhost");
        sock.write(Buffer.concat([Buffer.from([5, 1, 0, 3, host.length]), host, Buffer.from([echoPort >> 8, echoPort & 0xff])]));
        stage = 1; buf = Buffer.alloc(0);
      } else if (stage === 1 && buf.length >= 10) {
        sock.write(Buffer.from("ping"));
        stage = 2; buf = Buffer.alloc(0);
      } else if (stage === 2 && buf.length >= 4) {
        resolve(buf.subarray(0, 4).toString());
      }
    });
    sock.on("error", reject);
    setTimeout(() => reject(new Error("socks test timeout")), 8000);
  });
  assert.equal(reply, "ping");
  clientSock.destroy();
  await b.stopSocks();
  await assert.rejects(new Promise((res, rej) => {
    const s = net.connect(port, "127.0.0.1");
    s.once("connect", () => res());
    s.once("error", rej);
  }), /ECONNREFUSED/);
  await b.disconnect();
  dummy.close();
});

test("edge ip fallback (NP-1117-07 d3): 3 consecutive failures -> domain fallback, dead IP not retried", async () => {
  const logs = [];
  let calls = 0;
  const b = mkBridge({
    edgeIp: "203.0.113.7",
    log: (m) => logs.push(m),
    makeTransport: async () => { calls++; throw new Error("dial tcp 203.0.113.7:443: connect: connection refused"); },
  });
  await b.connect();
  await waitFor(() => b.edgeIp === null);
  assert.ok(calls >= 3, `fallback only at the threshold (calls=${calls})`);
  assert.ok(logs.some((m) => m.includes("edge ip unreachable, fell back to domain")), "fallback must be logged with the agreed line");
  const callsAtFallback = calls;
  await new Promise((r) => setTimeout(r, 350));
  assert.equal(b.edgeIp, null); // the dead IP stays dropped for the session
  assert.ok(calls > callsAtFallback, "the loop keeps retrying on the domain route");
  await b.disconnect();
});

test("edge ip fallback (NP-1117-07 d3): bearer lock is exempt", async () => {
  const logs = [];
  const b = mkBridge({
    edgeIp: "203.0.113.7",
    log: (m) => logs.push(m),
    makeTransport: async () => { throw new Error("dial tcp 203.0.113.7:443: connect: connection refused"); },
  });
  b.setBearerLock(["203.0.113.7"]);
  await b.connect();
  await new Promise((r) => setTimeout(r, 600));
  assert.equal(b.edgeIp, "203.0.113.7"); // untouched under a lock
  assert.ok(!logs.some((m) => m.includes("fell back to domain")));
  await b.disconnect();
});

test("queued count follows the live queue: fades on establish, on carrier death, on local reset (NP-1117-12)", async () => {
  const b = mkBridge();
  const queuedEvents = [];
  b.onEvent((ev) => { if (ev.type === "queued") queuedEvents.push(ev.queuedNow); });
  // Minimal fake client/stream with client-core's surface: onQueued
  // callback slot, an `opened` promise, and a reset() method.
  const mkStream = (id) => {
    let res, rej;
    const opened = new Promise((r, j) => { res = r; rej = j; });
    return {
      id, state: "opening", onQueued: null, opened,
      _res: res, _rej: rej, resetCalls: 0,
      reset() { this.resetCalls++; this.state = "reset"; },
    };
  };
  let nextId = 1;
  const fakeClient = { openStream: () => mkStream(nextId++) };
  b._instrument(fakeClient);
  const tick = () => new Promise((r) => setTimeout(r, 10));

  // cell 1 (the required one): queued -> established -> count fades
  const s1 = fakeClient.openStream({});
  s1.onQueued({ position: 1, estWaitMs: 0, maxWaitMs: 5000 });
  assert.equal(b.queuedNow, 1);
  s1._res(0); // OPEN_OK
  await tick();
  assert.equal(b.queuedNow, 0);

  // cell 2 (the actual latch): queued -> carrier dies (client-core
  // _die rejects `opened` but never moves s.state out of "queued")
  const s2 = fakeClient.openStream({});
  s2.onQueued({ position: 1, estWaitMs: 0, maxWaitMs: 5000 });
  assert.equal(b.queuedNow, 1);
  s2._rej(new Error("carrier closed"));
  await tick();
  assert.equal(b.queuedNow, 0);

  // cell 3: queued -> local reset before any server answer
  const s3 = fakeClient.openStream({});
  s3.onQueued({ position: 2, estWaitMs: 0, maxWaitMs: 5000 });
  assert.equal(b.queuedNow, 1);
  s3.reset();
  assert.equal(b.queuedNow, 0);
  assert.equal(s3.resetCalls, 1);

  // repeated OPEN_QUEUED updates for one stream count once
  const s4 = fakeClient.openStream({});
  s4.onQueued({ position: 3, estWaitMs: 0, maxWaitMs: 5000 });
  s4.onQueued({ position: 1, estWaitMs: 0, maxWaitMs: 5000 });
  assert.equal(b.queuedNow, 1);
  s4._res(0);
  await tick();
  assert.equal(b.queuedNow, 0);
  assert.deepEqual(queuedEvents, [1, 0, 1, 0, 1, 0, 1, 0]);
});

// ---- NP-1117-16: session open budget — proactive rotation + drain + 0x06 migration ----
function echoRoundTrip(s, tag) {
  return new Promise((resolve, reject) => {
    const to = setTimeout(() => reject(new Error("echo timeout")), 5000);
    let buf = Buffer.alloc(0);
    s.onData = (d) => {
      buf = Buffer.concat([buf, Buffer.from(d)]);
      if (buf.length >= tag.length) { clearTimeout(to); resolve(buf.subarray(0, tag.length).toString()); }
    };
    s.onReset = () => { clearTimeout(to); reject(new Error("stream reset during echo")); };
    s.write(new TextEncoder().encode(tag));
  });
}
async function fillOpens(b, n) {
  for (let i = 0; i < n; i++) {
    const s = b.client.openStream({ host: "localhost", port: echoPort });
    await s.opened;
    s.reset();
  }
}
// Minimal SOCKS5 domain-CONNECT; resolves { rep, sock } once the reply lands.
function socksConnectDomain(port, host, targetPort) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, "127.0.0.1", () => sock.write(Buffer.from([5, 1, 0])));
    let stage = 0; let buf = Buffer.alloc(0);
    const to = setTimeout(() => reject(new Error("socks connect timeout")), 8000);
    sock.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 0 && buf.length >= 2) {
        const h = Buffer.from(host);
        sock.write(Buffer.concat([Buffer.from([5, 1, 0, 3, h.length]), h, Buffer.from([targetPort >> 8, targetPort & 0xff])]));
        stage = 1; buf = Buffer.alloc(0);
      } else if (stage === 1 && buf.length >= 10) {
        clearTimeout(to);
        resolve({ rep: buf[1], sock });
      }
    });
    sock.on("error", (e) => { clearTimeout(to); reject(e); });
  });
}

test("open budget (NP-1117-16 a): 150 streams across one lineage — rotations happen, state never flickers, kept streams intact", async () => {
  const b = mkBridge();
  await b.connect();
  await waitFor(() => b.state === "connected" && b.client);
  const kept = [];
  for (let i = 0; i < 150; i++) {
    const s = b.client.openStream({ host: "localhost", port: echoPort });
    await s.opened;
    if (i % 15 === 0) kept.push(s); else s.reset();
    assert.equal(b.state, "connected");
  }
  assert.ok(b.sessions.rotations >= 2, `expected >=2 budget rotations, got ${b.sessions.rotations}`);
  assert.ok(b.stats.carriers >= 3, `carriers=${b.stats.carriers}`);
  for (const [k, s] of kept.entries()) {
    assert.equal(await echoRoundTrip(s, `kept-${k}`), `kept-${k}`);
  }
  for (const s of kept) s.reset();
  await b.disconnect();
});

test("open budget (NP-1117-16 b): long streams cross a rotation alive, drain closes the retired session once empty", async () => {
  const b = mkBridge();
  await b.connect();
  await waitFor(() => b.state === "connected" && b.client);
  const firstClient = b.client;
  const longs = [];
  for (let i = 0; i < 3; i++) {
    const s = b.client.openStream({ host: "localhost", port: echoPort });
    await s.opened;
    longs.push(s);
  }
  assert.equal(await echoRoundTrip(longs[0], "before"), "before");
  await fillOpens(b, 40);
  await waitFor(() => b.stats.carriers === 2);
  assert.notEqual(b.client, firstClient);
  assert.equal(firstClient.state, "open"); // retired to drain, NOT killed
  for (const [k, s] of longs.entries()) {
    assert.equal(await echoRoundTrip(s, `after-${k}`), `after-${k}`);
  }
  for (const s of longs) s.reset();
  await waitFor(() => firstClient.state === "dead", 8000); // drained -> closed by the manager
  await b.disconnect();
});

test("open budget (NP-1117-16 c): target-level 0x06 under budget fails immediately — no rotation, no retry", async () => {
  let attempts = 0;
  const factory = makeFactory(VERIFIER, {
    onCarrier: (st, server) => {
      const orig = server.connectFn;
      server.connectFn = (a) => {
        if (a.hostname === "capped.example") { attempts++; throw new Error("simulated session cap"); }
        return orig(a);
      };
    },
  });
  const b = mkBridge({ makeTransport: factory });
  await b.connect();
  await waitFor(() => b.state === "connected" && b.client);
  const firstClient = b.client;
  const port = await b.startSocks(0 + 24100);
  const t0 = Date.now();
  const { rep, sock } = await socksConnectDomain(port, "capped.example", echoPort);
  const elapsed = Date.now() - t0;
  assert.equal(rep, 0x01); // REP.GENERAL for 0x06
  assert.ok(elapsed < 3000, `must be immediate, took ${elapsed} ms`);
  assert.equal(attempts, 1); // no retry
  assert.equal(b.client, firstClient); // no rotation
  assert.equal(b.sessions.rotations, 0);
  sock.destroy();
  await b.disconnect();
});

test("open budget (NP-1117-16 d): 0x06 at the budget rotates and retries once on the new session", async () => {
  let carrierNo = 0;
  const attemptsByCarrier = new Map();
  const factory = makeFactory(VERIFIER, {
    onCarrier: (st, server) => {
      carrierNo++;
      const mine = carrierNo;
      const orig = server.connectFn;
      server.connectFn = (a) => {
        if (a.hostname === "capped.example") {
          attemptsByCarrier.set(mine, (attemptsByCarrier.get(mine) || 0) + 1);
          if (mine === 1) throw new Error("simulated session cap");
        }
        return orig(a);
      };
    },
  });
  const b = mkBridge({ makeTransport: factory });
  await b.connect();
  await waitFor(() => b.state === "connected" && b.client);
  const firstClient = b.client;
  await fillOpens(b, 39); // one short of the threshold
  firstClient.onOpenThreshold = null; // isolate the REACTIVE path (proactive is covered by a/b)
  const port = await b.startSocks(24200);
  const { rep, sock } = await socksConnectDomain(port, "capped.example", echoPort);
  assert.equal(rep, 0x00); // success after migration
  assert.equal(attemptsByCarrier.get(1), 1); // exactly one failed attempt on the old session
  assert.equal(attemptsByCarrier.get(2), 1); // exactly one retry on the new session
  assert.notEqual(b.client, firstClient);
  assert.equal(b.sessions.rotations, 1);
  // the migrated stream actually carries data (echo at echoPort)
  const got = await new Promise((resolve, reject) => {
    const to = setTimeout(() => reject(new Error("echo timeout")), 5000);
    let buf = Buffer.alloc(0);
    sock.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= 7) { clearTimeout(to); resolve(buf.subarray(0, 7).toString()); }
    });
    sock.write(Buffer.from("migrate"));
  });
  assert.equal(got, "migrate");
  sock.destroy();
  await b.disconnect();
});

// ---------------------------------------------------------------------------
// NP-1117-23: session pool (striping). Placement = least-loaded healthy
// carrier; one carrier's death/rotation never touches the others.
test("pool (NP-1117-23): placement balances new streams across 4 carriers", async () => {
  const servers = [];
  const b = mkBridge({ poolSize: 4, makeTransport: makeFactory(VERIFIER, { onCarrier: (st, server) => servers.push(server) }) });
  await b.connect();
  await waitFor(() => b.sessions.healthyCount() === 4);
  assert.equal(servers.length, 4);
  const streams = [];
  for (let i = 0; i < 8; i++) {
    const s = b.sessions.pick().openStream({ host: "localhost", port: echoPort, schemeHint: 0, gatePolicy: 0 });
    await s.opened;
    streams.push(s);
  }
  assert.deepEqual(servers.map((s) => s.streams.size).sort(), [2, 2, 2, 2]);
  for (const s of streams) s.reset(0);
  await b.disconnect();
});

test("pool (NP-1117-23): a single stream is never split across carriers", async () => {
  const servers = [];
  const b = mkBridge({ poolSize: 4, makeTransport: makeFactory(VERIFIER, { onCarrier: (st, server) => servers.push(server) }) });
  await b.connect();
  await waitFor(() => b.sessions.healthyCount() === 4);
  const s = b.sessions.pick().openStream({ host: "localhost", port: echoPort, schemeHint: 0, gatePolicy: 0 });
  await s.opened;
  const payload = crypto.randomBytes(32 * 1024);
  const got = [];
  s.onData = (d) => got.push(Buffer.from(d));
  s.write(payload);
  await waitFor(() => Buffer.concat(got).length >= payload.length);
  assert.ok(Buffer.concat(got).equals(payload));
  assert.deepEqual(servers.map((x) => x.streams.size).sort(), [0, 0, 0, 1]);
  s.reset(0);
  await b.disconnect();
});

test("pool (NP-1117-23): one carrier's death is isolated; the pool replenishes it", async () => {
  const transports = [];
  const servers = [];
  const b = mkBridge({ poolSize: 4, makeTransport: makeFactory(VERIFIER, { onCarrier: (st, server) => { transports.push(st); servers.push(server); } }) });
  await b.connect();
  await waitFor(() => b.sessions.healthyCount() === 4);
  const streams = [];
  for (let i = 0; i < 4; i++) {
    const s = b.sessions.pick().openStream({ host: "localhost", port: echoPort, schemeHint: 0, gatePolicy: 0 });
    await s.opened;
    streams.push(s);
  }
  const dead = new Set();
  streams.forEach((s, i) => {
    const mark = () => dead.add(i);
    s.onEnd = mark; s.onReset = mark; s.onFail = mark;
  });
  transports[1].close(); // kill carrier #2's leg
  await waitFor(() => dead.size === 1);
  assert.equal(b.state, "connected"); // the pool never went down
  for (let i = 0; i < 4; i++) {
    if (!dead.has(i)) await echoRoundTrip(streams[i], `alive-${i}`);
  }
  // Replenishment: a fifth establishment restores 4 healthy carriers.
  await waitFor(() => servers.length >= 5 && b.sessions.healthyCount() === 4);
  for (const s of streams) { try { s.reset(0); } catch { /* already gone */ } }
  await b.disconnect();
});

test("pool (NP-1117-23): a budget rotation stays inside its own lineage", async () => {
  const servers = [];
  const establish = async () => {
    const [ct, st] = memoryTransportPair();
    const server = new HollowServer({
      transport: st, verifiers: new Map([[1, VERIFIER]]),
      ownHost: "test.workers.dev", zoneSuffix: "workers.dev",
      connectFn: nodeConnect, fetchFn: async () => { throw new Error("no fetch in harness"); },
    });
    servers.push(server);
    const client = new HollowClient({ transport: ct, psk: PSK, keyId: 1 });
    await client.handshake();
    return client;
  };
  const sessions = new SessionManager({ establish, size: 2, rotationMs: 0, log: () => {} });
  const cA = await establish();
  const endA = sessions.adopt(cA);
  const cB = await establish();
  const endB = sessions.adopt(cB);
  endA.catch(() => {}); endB.catch(() => {});
  // A long-lived stream on B, opened BEFORE A's rotation.
  const sB = cB.openStream({ host: "localhost", port: echoPort, schemeHint: 0, gatePolicy: 0 });
  await sB.opened;
  // Burn A's open budget (the client-core threshold, 40) with short
  // streams: rotation fires on A's lineage only.
  for (let i = 0; i < 40; i++) {
    const s = cA.openStream({ host: "localhost", port: echoPort, schemeHint: 0, gatePolicy: 0 });
    await s.opened;
    s.reset(0);
  }
  await waitFor(() => sessions.rotations === 1);
  assert.equal(servers.length, 3); // exactly one replacement, for A
  assert.equal(cB.state, "open"); // B's session untouched
  await echoRoundTrip(sB, "b-survives"); // B's in-flight stream intact
  sB.reset(0);
  sessions.stop();
});

// ---- NP-1117-27: entry dispersion — one pinned entry IP per carrier ----
function mkDispersed({ candidates = null, poolSize = 4, failIps = new Set(), edgeIp = null, ...bridgeOpts } = {}) {
  const logs = [];
  const dials = [];
  const makeTransport = async (dialIp) => {
    dials.push(dialIp);
    if (failIps.has(dialIp)) throw new Error("dial refused (test)");
    const [ct, st] = memoryTransportPair();
    new HollowServer({
      transport: st, verifiers: new Map([[1, VERIFIER]]),
      ownHost: "test.workers.dev", zoneSuffix: "workers.dev",
      connectFn: nodeConnect, fetchFn: async () => { throw new Error("no fetch in harness"); },
    });
    return ct;
  };
  const bridge = new CoreBridge({
    workerUrl: "wss://test.workers.dev/", psk: PSK, keyId: 1, log: (m) => logs.push(m),
    makeTransport, rotationMs: 60000, backoffBaseMs: 40, backoffCapMs: 200,
    poolSize, edgeIp, edgeCandidates: candidates, ...bridgeOpts,
  });
  return { bridge, logs, dials };
}
const CANDS = [
  { ip: "10.0.0.1", rttMs: 10 }, { ip: "10.0.0.2", rttMs: 20 },
  { ip: "10.0.0.3", rttMs: 30 }, { ip: "10.0.0.4", rttMs: 40 },
];

test("dispersion: four carriers pin the four ranked candidates, one per slot", async () => {
  const { bridge, logs, dials } = mkDispersed({ candidates: CANDS });
  await bridge.connect();
  await waitFor(() => bridge.sessions.healthyCount() === 4);
  assert.deepEqual(bridge.snapshot().slotEdges, { 0: "10.0.0.1", 1: "10.0.0.2", 2: "10.0.0.3", 3: "10.0.0.4" });
  assert.deepEqual([...dials].sort(), ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]);
  assert.ok(logs.some((m) => m.includes("entry 10.0.0.3, rtt 30ms")), "per-carrier entry+rtt log line");
  await bridge.disconnect();
});

test("dispersion: a short candidate list leaves the gap slots on domain resolution", async () => {
  const { bridge, dials } = mkDispersed({ candidates: CANDS.slice(0, 2) });
  await bridge.connect();
  await waitFor(() => bridge.sessions.healthyCount() === 4);
  assert.deepEqual(bridge.snapshot().slotEdges, { 0: "10.0.0.1", 1: "10.0.0.2" });
  assert.equal(dials.filter((d) => d === null).length, 2); // explicit domain dials
  await bridge.disconnect();
});

test("dispersion: no candidate list keeps the single-entry behavior (factory gets the bridge default)", async () => {
  const { bridge, dials } = mkDispersed({ candidates: null, edgeIp: "10.9.9.9", poolSize: 2 });
  await bridge.connect();
  await waitFor(() => bridge.sessions.healthyCount() === 2);
  assert.ok(dials.length >= 2 && dials.every((d) => d === undefined));
  assert.equal(bridge._pickSlotEdge(0), null);
  await bridge.disconnect();
});

test("dispersion: a candidate failing 3 establishments is demoted; its slot re-pins to the best unused candidate", async () => {
  const failIps = new Set(["10.0.0.1"]);
  const { bridge, logs, dials } = mkDispersed({ candidates: CANDS.slice(0, 3), poolSize: 2, failIps });
  await bridge.connect();
  await waitFor(() => bridge.sessions.healthyCount() === 2);
  assert.deepEqual(bridge.snapshot().slotEdges, { 0: "10.0.0.3", 1: "10.0.0.2" });
  assert.equal(dials.filter((d) => d === "10.0.0.1").length, 3); // exactly the d3 threshold
  assert.ok(logs.some((m) => m.includes("10.0.0.1") && m.includes("demoted")));
  await bridge.disconnect();
});

test("dispersion: a fresh measurement clears demotions — the candidate rises again on rebuild", async () => {
  const failIps = new Set(["10.0.0.1"]);
  const { bridge } = mkDispersed({ candidates: CANDS.slice(0, 2), poolSize: 1, failIps });
  await bridge.connect();
  await waitFor(() => bridge.sessions.healthyCount() === 1);
  assert.deepEqual(bridge.snapshot().slotEdges, { 0: "10.0.0.2" }); // fell over to the substitute
  failIps.clear();
  bridge.setEdgeCandidates(CANDS.slice(0, 2)); // periodic re-measurement
  assert.equal(bridge._edgeDisfavored.size, 0);
  bridge.sessions.pick().close(); // kill the live carrier; the slot rebuilds
  await waitFor(() => bridge.snapshot().slotEdges[0] === "10.0.0.1");
  // slotEdges registers at pick time; the new carrier may still be
  // handshaking — wait for health instead of racing it (NP-1117-28).
  await waitFor(() => bridge.sessions.healthyCount() === 1);
  await bridge.disconnect();
});

// NP-1118-01 (a): the wire byte counters behind the status view's
// rate readout actually count — an echo exchange over a pooled
// carrier moves both totals, and the snapshot exposes them.
test("traffic counters (NP-1118-01): an echo exchange moves up/down; snapshot exposes traffic", async () => {
  const bridge = mkBridge({ poolSize: 2 });
  try {
    await bridge.connect();
    await waitFor(() => bridge.sessions.healthyCount() === 2);
    const before = bridge.snapshot();
    assert.equal(typeof before.traffic.up, "number");
    assert.equal(typeof before.traffic.down, "number");
    const client = bridge.sessions.pick();
    const s = client.openStream({ host: "localhost", port: echoPort, schemeHint: 0, gatePolicy: 0 });
    await s.opened;
    const got = new Promise((res) => { let buf = ""; s.onData = (d) => { buf += Buffer.from(d).toString(); if (buf.length >= 4) res(buf); }; });
    s.write(new TextEncoder().encode("ping"));
    assert.equal(await got, "ping");
    const after = bridge.snapshot();
    assert.ok(after.traffic.up > before.traffic.up, "up counted the sent bytes");
    assert.ok(after.traffic.down > before.traffic.down, "down counted the echoed bytes");
  } finally { await bridge.disconnect(); }
});

// ---- NP-1118-49: establishment deadline (NP-1118-47 main fix) ----
// A blackholed attempt (dial or upgrade swallowed, handshake
// never answered) previously hung _establishClient forever, and
// every recovery mechanism keys off attempt completion, so the
// pool sat at 0/N indefinitely. The deadline turns the hang into
// an ordinary failure.

test("NP-1118-49 blackhole transport: attempts die at the deadline and the loop keeps cycling", async () => {
  const logs = [];
  const b = mkBridge({
    log: (m) => logs.push(m),
    makeTransport: () => new Promise(() => {}), // never settles
    establishTimeoutMs: 300,
  });
  const t0 = Date.now();
  await b.connect();
  await waitFor(() => logs.filter((m) => m.includes("establishment timed out (transport)")).length >= 3, 8000);
  assert.ok(Date.now() - t0 < 5000, "three timed-out attempts complete in bounded time");
  assert.equal(b.sessions.healthyCount(), 0);
  await b.disconnect();
});

test("NP-1118-49 blackhole handshake: the deadline closes the transport", async () => {
  const logs = [];
  let closes = 0;
  const b = mkBridge({
    log: (m) => logs.push(m),
    makeTransport: async () => {
      const [ct] = memoryTransportPair(); // no server: the hello is never answered
      const rawClose = ct.close.bind(ct);
      ct.close = () => { closes++; rawClose(); };
      return ct;
    },
    establishTimeoutMs: 300,
  });
  await b.connect();
  await waitFor(() => logs.filter((m) => m.includes("establishment timed out (handshake)")).length >= 2, 8000);
  assert.ok(closes >= 1, "the timed-out handshake's transport was closed");
  await b.disconnect();
});

test("NP-1118-49 blackhole pool: demotion cascades to domain dials; the pool self-heals when the domain path turns healthy", async () => {
  const dials = [];
  let domainHealthy = false;
  const makeTransport = async (dialIp) => {
    dials.push(dialIp);
    if (dialIp !== null || !domainHealthy) return new Promise(() => {}); // blackhole
    const [ct, st] = memoryTransportPair();
    new HollowServer({
      transport: st, verifiers: new Map([[1, VERIFIER]]),
      ownHost: "test.workers.dev", zoneSuffix: "workers.dev",
      connectFn: nodeConnect, fetchFn: async () => { throw new Error("no fetch in harness"); },
    });
    return ct;
  };
  const b = new CoreBridge({
    workerUrl: "wss://test.workers.dev/", psk: PSK, keyId: 1,
    makeTransport, rotationMs: 60000, backoffBaseMs: 40, backoffCapMs: 200,
    poolSize: 4, edgeCandidates: CANDS, establishTimeoutMs: 300,
  });
  await b.connect();
  // Every candidate blackholes: each slot burns its 3 failures per
  // candidate, demotions cascade, and slots end up dialing by
  // domain (dialIp === null is observable in the factory record).
  await waitFor(() => dials.includes(null), 30000);
  assert.equal(b.sessions.healthyCount(), 0);
  domainHealthy = true;
  await waitFor(() => b.sessions.healthyCount() === 4, 20000);
  await b.disconnect();
});

test("NP-1118-49 slow handshake inside the budget is not killed", async () => {
  const factory = async () => {
    const [ct, st] = memoryTransportPair();
    const rawSend = st.send.bind(st);
    // Uniform 1.5s latency on the server's sends (order preserved):
    // a slow handshake path, not a reordered one.
    st.send = (bytes) => { setTimeout(() => rawSend(bytes), 1500); };
    new HollowServer({
      transport: st, verifiers: new Map([[1, VERIFIER]]),
      ownHost: "test.workers.dev", zoneSuffix: "workers.dev",
      connectFn: nodeConnect, fetchFn: async () => { throw new Error("no fetch in harness"); },
    });
    return ct;
  };
  const b = mkBridge({ makeTransport: factory, establishTimeoutMs: 5000 });
  await b.connect();
  await waitFor(() => b.sessions.healthyCount() === 1, 8000);
  await b.disconnect();
});

// ---- NP-1118-53: edge self-healing (demotion cooldown + auto re-measure) ----

test("NP-1118-53 cooldown: a demoted candidate is probed after expiry and rehabilitated by a success", async () => {
  const down = new Set(["10.0.0.1"]); // .1 starts dead, .2 alive
  let domainDown = false;
  const dials = [];
  let livePair = null;
  const makeTransport = async (dialIp) => {
    dials.push(dialIp);
    if (dialIp === null ? domainDown : down.has(dialIp)) throw new Error("dial refused (test)");
    const [ct, st] = memoryTransportPair();
    livePair = [ct, st];
    new HollowServer({
      transport: st, verifiers: new Map([[1, VERIFIER]]),
      ownHost: "test.workers.dev", zoneSuffix: "workers.dev",
      connectFn: nodeConnect, fetchFn: async () => { throw new Error("no fetch in harness"); },
    });
    return ct;
  };
  const bridge = new CoreBridge({
    workerUrl: "wss://test.workers.dev/", psk: PSK, keyId: 1,
    makeTransport, rotationMs: 60000, backoffBaseMs: 40, backoffCapMs: 200,
    poolSize: 1, edgeCandidates: CANDS.slice(0, 2), edgeDemoteCooldownMs: 4000,
  });
  await bridge.connect();
  await waitFor(() => bridge.sessions.healthyCount() === 1);
  assert.deepEqual(bridge.snapshot().slotEdges, { 0: "10.0.0.2" }); // fell over to .2 after .1's demotion
  assert.deepEqual(bridge.snapshot().edgeDisfavored, ["10.0.0.1"]);
  // Flip the world: .1 revives, .2's path dies, domain is dead
  // too — and kill the live carrier, since a healthy lineage
  // never re-dials on its own. The slot demotes .2, finds .1
  // still inside its cooldown, falls to domain dials — and once
  // the cooldown expires it probes .1 and is rehabilitated by
  // the success.
  down.delete("10.0.0.1"); down.add("10.0.0.2"); domainDown = true;
  const dialMark = dials.length;
  try { livePair[0].closeCarrier(); } catch {}
  try { livePair[1].closeCarrier(); } catch {}
  await waitFor(() => bridge.snapshot().slotEdges[0] === "10.0.0.1" && bridge.sessions.healthyCount() === 1, 15000);
  assert.ok(dials.slice(dialMark).includes(null), "the slot sat on domain dials during the cooldown");
  assert.deepEqual(bridge.snapshot().edgeDisfavored, ["10.0.0.2"]); // .1 formally rehabilitated
  await bridge.disconnect();
});

test("NP-1118-53 tonight's shape: 1/4 floor holds, then the pool self-heals back to the ranked pin layout", async () => {
  const down = new Set(["10.0.0.1", "10.0.0.2", "10.0.0.3"]); // only .4 (slot 3's primary) lives
  let domainDown = true;
  const dials = [];
  let measureCalls = 0;
  const makeTransport = async (dialIp) => {
    dials.push(dialIp);
    if (dialIp === null ? domainDown : down.has(dialIp)) return new Promise(() => {}); // blackhole
    const [ct, st] = memoryTransportPair();
    new HollowServer({
      transport: st, verifiers: new Map([[1, VERIFIER]]),
      ownHost: "test.workers.dev", zoneSuffix: "workers.dev",
      connectFn: nodeConnect, fetchFn: async () => { throw new Error("no fetch in harness"); },
    });
    return ct;
  };
  const bridge = new CoreBridge({
    workerUrl: "wss://test.workers.dev/", psk: PSK, keyId: 1,
    makeTransport, rotationMs: 60000, backoffBaseMs: 40, backoffCapMs: 200,
    poolSize: 4, edgeCandidates: CANDS, establishTimeoutMs: 150,
    edgeDemoteCooldownMs: 60000, // long: phase-2 recovery must come from the re-measure, not the cooldown
    edgeRemeasureAfterMs: 3000, edgeRemeasureMinIntervalMs: 1500, remeasureTickMs: 100,
    measureEdgesFn: async () => { measureCalls++; return CANDS; },
  });
  await bridge.connect();
  // Phase 1: the cascade runs (demotions, then domain dials) and
  // the floor holds at exactly one healthy carrier — the slot
  // pinned to the surviving candidate.
  await waitFor(() => dials.includes(null), 30000);
  const t1 = Date.now();
  while (Date.now() - t1 < 1500) {
    assert.equal(bridge.sessions.healthyCount(), 1);
    assert.equal(bridge.snapshot().slotEdges[3], "10.0.0.4");
    await new Promise((r) => setTimeout(r, 150));
  }
  await waitFor(() => measureCalls >= 1, 15000); // degraded >= edgeRemeasureAfterMs, then the tick fires
  // The survivor's stream must flow now and keep flowing.
  const survivor = bridge.sessions.pick();
  const s = survivor.openStream({ host: "localhost", port: echoPort });
  await s.opened;
  const echoOnce = async (bytes) => {
    const got = await new Promise((res, rej) => {
      const chunks = [];
      const to = setTimeout(() => rej(new Error("echo timeout")), 6000);
      s.onData = (d) => { chunks.push(Buffer.from(d)); if (Buffer.concat(chunks).length >= bytes.length) { clearTimeout(to); res(Buffer.concat(chunks)); } };
      s.write(new Uint8Array(bytes));
    });
    assert.deepEqual([...got], bytes);
  };
  await echoOnce([1, 2, 3, 4]);
  // Phase 2: the candidate paths open (the domain landing stays
  // blackholed, as tonight). The next auto re-measure re-ranks,
  // drops the unhealthy slots' stale pins, and the pool returns
  // to the full ranked layout with no manual measurement and no
  // reconnect — while the survivor's stream never breaks.
  down.clear();
  await waitFor(() => bridge.sessions.healthyCount() === 4, 30000);
  assert.deepEqual(bridge.snapshot().slotEdges, { 0: "10.0.0.1", 1: "10.0.0.2", 2: "10.0.0.3", 3: "10.0.0.4" });
  await echoOnce([5, 6, 7, 8]);
  await bridge.disconnect();
});
