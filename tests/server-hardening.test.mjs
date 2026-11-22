// NP-1118-65 server hardening grids (audit NP-1118-63 B1/B2/S7/S8
// + S6 log ride-along). Each grid names the unbounded wait or the
// silent failure it closes; the harness mirrors occupancy.test.mjs
// (real client <-> real server over a memory transport).
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { Readable, Writable } from "node:stream";
import { HollowClient } from "../shared/client-core.js";
import { HollowServer } from "../shared/server-core.js";
import { deriveVerifier, ERR, SCHEME, GATE } from "../shared/protocol.js";
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

const SPECIAL = "proxy request failed, cannot connect to the specified address";

async function makePair({ connectFn, fetchFn, serverOpts = {} }) {
  const psk = randomBytes(32);
  const [ta, tb] = memoryTransportPair();
  const v = await deriveVerifier(psk);
  const server = new HollowServer({
    transport: tb, verifiers: new Map([[1, v]]),
    ownHost: "hollow.example.workers.dev", zoneSuffix: "example.workers.dev",
    connectFn,
    fetchFn: fetchFn || (async () => { throw new Error("no fetch in this harness"); }),
    ...serverOpts,
  });
  const client = new HollowClient({ transport: ta, psk, keyId: 1 });
  await client.handshake();
  assert.equal(client.state, "open");
  return { client, server, ta, tb };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- B1: the open watchdog ----
test("B1: a connect() that never settles is rejected 0x05 by the watchdog and the slot releases", async () => {
  const { client, server } = await makePair({
    connectFn: () => new Promise(() => {}), // never settles
    serverOpts: { openWatchdogMs: 300 },
  });
  const s = client.openStream({ host: "localhost", port: 443, schemeHint: 0, gatePolicy: 0 });
  const t0 = Date.now();
  const err = await s.opened.then(() => null, (e) => e);
  assert.ok(err, "the OPEN must be answered, not left hanging");
  assert.equal(err.code, ERR.TARGET_UNREACHABLE, `watchdog failure must map via the existing §7.3 mapping (got ${err.code})`);
  assert.ok(Date.now() - t0 < 5000, "the watchdog, not the client's 20 s bound, must answer");
  assert.equal(server.occupancy, 0, "the in-flight slot must release");
  client.close();
});

test("B1: a socket that settles after the watchdog fired is closed on arrival (no leak)", async () => {
  let lateClosed = false;
  const lateSock = {
    readable: new ReadableStream(), writable: new WritableStream(),
    opened: Promise.resolve(), close: () => { lateClosed = true; },
  };
  const { client, server } = await makePair({
    connectFn: () => new Promise((res) => setTimeout(() => res(lateSock), 700)),
    serverOpts: { openWatchdogMs: 300 },
  });
  const s = client.openStream({ host: "localhost", port: 443, schemeHint: 0, gatePolicy: 0 });
  const err = await s.opened.then(() => null, (e) => e);
  assert.equal(err && err.code, ERR.TARGET_UNREACHABLE);
  await sleep(700); // let the late socket arrive
  assert.equal(lateClosed, true, "the late socket must be closed by the watchdog's settle handler");
  assert.equal(server.occupancy, 0);
  client.close();
});

test("B1 control: a slow-but-legitimate connect inside the watchdog still opens", async () => {
  const { server: echo, port } = await startEcho();
  const { client } = await makePair({
    connectFn: async (opts) => { await sleep(100); return nodeConnect(opts); },
    serverOpts: { openWatchdogMs: 300 },
  });
  // nodeConnect dials 127.0.0.1 regardless; the echo port comes from opts
  const s = client.openStream({ host: "localhost", port, schemeHint: 0, gatePolicy: 0 });
  await s.opened; // must not be watchdog-killed
  client.close();
  echo.close();
});

// ---- S7: handshake completion deadline ----
test("S7: a session that never completes the handshake is torn down at the deadline", async () => {
  const psk = randomBytes(32);
  const [, tb] = memoryTransportPair();
  const v = await deriveVerifier(psk);
  const server = new HollowServer({
    transport: tb, verifiers: new Map([[1, v]]),
    ownHost: "hollow.example.workers.dev", zoneSuffix: "example.workers.dev",
    connectFn: async () => { throw new Error("unused"); },
    fetchFn: async () => { throw new Error("unused"); },
    handshakeDeadlineMs: 300,
  });
  assert.equal(server.dead, false);
  await sleep(600);
  assert.equal(server.dead, true, "the parked pre-handshake session must be torn down");
});

test("S7 control: a completed handshake clears the deadline", async () => {
  const { client, server } = await makePair({
    connectFn: async () => { throw new Error("unused"); },
    serverOpts: { handshakeDeadlineMs: 300 },
  });
  await sleep(600);
  assert.equal(server.dead, false, "an open session must survive past the deadline");
  client.close();
});

// ---- B2: fetch gate abort + response cap ----
// Drive a stream into the fetch gate: connect fails with the CF
// special error, then the client sends a request head and CLOSEs.
async function openFetchStream(client, host = "example.org") {
  const s = client.openStream({ host, port: 443, schemeHint: SCHEME.HTTPS, gatePolicy: 0 });
  await s.opened;
  assert.equal(s.gate, GATE.FETCH, "the stream must land on the fetch gate");
  return s;
}

test("B2: a fetch that never answers is aborted at the bound and the transaction fails", async () => {
  let sawSignal = null;
  const { client, server } = await makePair({
    connectFn: async () => { throw new Error(SPECIAL); },
    fetchFn: (url, init) => {
      sawSignal = init && init.signal || null;
      return new Promise((_, rej) => {
        if (sawSignal) sawSignal.addEventListener("abort", () => rej(new Error("aborted")));
      });
    },
    serverOpts: { fetchTimeoutMs: 300 },
  });
  const s = await openFetchStream(client);
  const reset = new Promise((res) => { s.onReset = (c) => res(c); s.onFail = () => res(-1); });
  s.write(new TextEncoder().encode("GET / HTTP/1.1\r\nhost: example.org\r\n\r\n"));
  s.closeWrite();
  const code = await Promise.race([reset, sleep(5000).then(() => null)]);
  assert.equal(code, ERR.FETCH_FALLBACK_FAILED, `abort must fail the transaction (got ${code})`);
  assert.ok(sawSignal, "fetchFn must receive an abort signal");
  assert.equal(server.fetchActive, 0, "the fetch slot must release");
  assert.equal(server.occupancy, 0, "the §7.5 slot must release");
  client.close();
});

test("B2: a response body over the cap fails the transaction instead of buffering unbounded", async () => {
  const chunk = new Uint8Array(2048).fill(0x61);
  const { client, server } = await makePair({
    connectFn: async () => { throw new Error(SPECIAL); },
    fetchFn: async () => ({
      status: 200, statusText: "OK",
      headers: new Headers({ "content-type": "text/plain" }),
      body: new ReadableStream({
        start(c) { c.enqueue(chunk); c.enqueue(chunk); c.enqueue(chunk); c.close(); },
      }),
      arrayBuffer: async () => new Uint8Array(6144),
    }),
    serverOpts: { fetchRespMax: 4096 },
  });
  const s = await openFetchStream(client);
  const reset = new Promise((res) => { s.onReset = (c) => res(c); s.onFail = () => res(-1); });
  s.write(new TextEncoder().encode("GET / HTTP/1.1\r\nhost: example.org\r\n\r\n"));
  s.closeWrite();
  const code = await Promise.race([reset, sleep(5000).then(() => null)]);
  assert.equal(code, ERR.FETCH_BODY_TOO_LARGE, `over-cap response must fail as body-too-large (got ${code})`);
  assert.equal(server.fetchActive, 0);
  client.close();
});

test("B2 control: a small fetch response is delivered whole", async () => {
  const { client } = await makePair({
    connectFn: async () => { throw new Error(SPECIAL); },
    fetchFn: async () => ({
      status: 200, statusText: "OK",
      headers: new Headers({ "content-type": "text/plain" }),
      body: new ReadableStream({
        start(c) { c.enqueue(new TextEncoder().encode("hello-fetch")); c.close(); },
      }),
      arrayBuffer: async () => new TextEncoder().encode("hello-fetch"),
    }),
    serverOpts: { fetchRespMax: 4096 },
  });
  const s = await openFetchStream(client);
  const got = new Promise((res) => {
    const chunks = [];
    s.onData = (d) => chunks.push(Buffer.from(d));
    s.onEnd = () => res(Buffer.concat(chunks).toString("latin1"));
  });
  s.write(new TextEncoder().encode("GET / HTTP/1.1\r\nhost: example.org\r\n\r\n"));
  s.closeWrite();
  const text = await Promise.race([got, sleep(5000).then(() => "")]);
  assert.ok(text.includes("200 OK") && text.includes("hello-fetch"), `response must be synthesized and delivered (got ${JSON.stringify(text.slice(0, 80))})`);
  client.close();
});

// ---- S8: writer.close() bound (white-box: the branch's await) ----
test("S8: _onCloseFrame proceeds past a writer.close() that never settles", async () => {
  const { client, server } = await makePair({
    connectFn: async () => { throw new Error("unused"); },
    serverOpts: { writerCloseTimeoutMs: 200 },
  });
  const fake = {
    id: 99, gate: GATE.CONNECT,
    writer: { close: () => new Promise(() => {}) }, // never settles
    localClosed: false, outEof: false, remoteClosed: false,
  };
  server.streams.set(99, fake);
  const t0 = Date.now();
  await server._onCloseFrame({ streamId: 99, payload: new Uint8Array([0]) });
  assert.ok(Date.now() - t0 < 3000, "the close-frame handling must not hang on writer.close()");
  assert.equal(fake.remoteClosed, true);
  server.streams.delete(99);
  client.close();
});

// ---- S6: dispatch errors log one line ----
test("S6: a throwing dispatch handler produces exactly one log line, session survives", async () => {
  const { server: echo, port } = await startEcho();
  const { client, server } = await makePair({ connectFn: nodeConnect });
  const lines = [];
  const orig = console.error;
  console.error = (...args) => { lines.push(args.map(String).join(" ")); };
  try {
    server._onData = () => { throw new Error("boom-dispatch"); };
    const s = client.openStream({ host: "localhost", port, schemeHint: 0, gatePolicy: 0 });
    await s.opened;
    s.write(new TextEncoder().encode("x"));
    await sleep(400);
  } finally {
    console.error = orig;
  }
  assert.equal(lines.filter((l) => l.includes("dispatch error")).length, 1, `want one dispatch-error line, got ${JSON.stringify(lines)}`);
  assert.equal(server.dead, false, "logging must not change closing behavior");
  client.close();
  echo.close();
});
