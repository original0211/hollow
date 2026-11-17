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
