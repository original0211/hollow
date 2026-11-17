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
  makeTransport: makeFactory(), backoffBaseMs: 40, backoffCapMs: 200, ...opts,
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
