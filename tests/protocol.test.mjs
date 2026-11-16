// Protocol unit tests (spec v0.1): frame parsing split rules (R-1113-05-01),
// record layer roundtrip + bucket wire sizes, full local client<->server E2E
// over an in-memory transport with a node:net echo as the connect() target.
import { test as _test } from "node:test";
const test = (name, fn) => _test(name, { timeout: 20000 }, fn);
import assert from "node:assert/strict";
import net from "node:net";
import { once } from "node:events";
import { Readable, Writable } from "node:stream";
import {
  FT, ERR, GATE, buildFrame, parseFrames, sealRecords, RecordReceiver,
  deriveVerifier, MAX_PAYLOAD, u32be,
} from "../shared/protocol.js";
import { randomBytes, chachaSeal } from "../shared/crypto.js";
import { HollowClient } from "../shared/client-core.js";
import { HollowServer } from "../shared/server-core.js";

test("parseFrames: oversize payload_len -> stream error, not record error", () => {
  const big = new Uint8Array(MAX_PAYLOAD + 1);
  const frame = buildFrame(FT.DATA, 7, big);
  const { frames, recordError, oversize } = parseFrames(frame);
  assert.equal(recordError, false);
  assert.equal(frames.length, 0);
  assert.deepEqual(oversize, [{ streamId: 7 }]);
});

test("parseFrames: overrun / trailing bytes -> record error", () => {
  const f = buildFrame(FT.DATA, 1, new Uint8Array([1, 2, 3]));
  const overrun = parseFrames(f.slice(0, f.length - 1));
  assert.equal(overrun.recordError, true);
  const trailing = parseFrames(new Uint8Array([...f, 0xaa]));
  assert.equal(trailing.recordError, true);
  const ok = parseFrames(f);
  assert.equal(ok.recordError, false);
  assert.equal(ok.frames.length, 1);
});

test("record layer: seal/open roundtrip, wire sizes are bucket+16", async () => {
  const key = randomBytes(32), iv = randomBytes(12);
  const frames = [buildFrame(FT.OPEN, 1, new Uint8Array(100))];
  const { records } = sealRecords(key, iv, 0, frames);
  assert.equal(records.length, 1);
  assert.equal(records[0].length, 512 + 16);
  const rx = new RecordReceiver(key, iv);
  const opened = rx.open(records[0]);
  assert.ok(opened);
  const parsed = parseFrames(opened.framesBlob);
  assert.equal(parsed.frames.length, 1);
  // tamper: flip one byte -> AEAD failure
  const bad = new Uint8Array(records[0]); bad[10] ^= 1;
  const rx2 = new RecordReceiver(key, iv);
  assert.equal(rx2.open(bad), null);
  assert.equal(rx2.consecFails, 1);
  // 16KiB bucket
  const bigFrame = buildFrame(FT.DATA, 1, randomBytes(16000));
  const r2 = sealRecords(key, iv, 0, [bigFrame]);
  assert.equal(r2.records[0].length, 16384 + 16);
});

// ---------- local E2E harness ----------
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

async function startEcho() {
  const server = net.createServer((s) => s.pipe(s));
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { server, port: server.address().port };
}
function nodeConnect({ port }) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, "127.0.0.1");
    sock.once("error", reject);
    sock.once("connect", () => {
      resolve({
        readable: Readable.toWeb(sock),
        writable: Writable.toWeb(sock),
        opened: Promise.resolve(),
        close: () => sock.destroy(),
      });
    });
  });
}

async function makePair(pskClient, pskServer, connectFn = nodeConnect) {
  const [ta, tb] = memoryTransportPair();
  const v = await deriveVerifier(pskServer);
  const server = new HollowServer({
    transport: tb,
    verifiers: new Map([[1, v]]),
    ownHost: "hollow.example.workers.dev",
    zoneSuffix: "example.workers.dev",
    connectFn,
    fetchFn: async () => { throw new Error("no fetch in local harness"); },
  });
  const client = new HollowClient({ transport: ta, psk: pskClient, keyId: 1 });
  return { client, server };
}

test("E2E: handshake + echo stream + close", async () => {
  const psk = randomBytes(32);
  const { server: echo, port } = await startEcho();
  const { client } = await makePair(psk, psk);
  await client.handshake();
  assert.equal(client.state, "open");
  const s = client.openStream({ host: "localhost", port, schemeHint: 0, gatePolicy: 0 });
  const gate = await s.opened;
  assert.equal(gate, GATE.CONNECT);
  const got = [];
  const doneP = new Promise((res) => {
    s.onData = (d) => { got.push(d); if (Buffer.concat(got).length >= 11) res(); };
  });
  s.write(new TextEncoder().encode("hello hollow"));
  await doneP;
  assert.equal(Buffer.concat(got).toString(), "hello hollow");
  s.closeWrite();
  client.close();
  echo.close();
});

test("E2E: wrong PSK fails the handshake (no data plane)", async () => {
  const { server: echo, port } = await startEcho();
  const { client } = await makePair(randomBytes(32), randomBytes(32));
  await assert.rejects(client.handshake());
  assert.equal(client.state, "dead");
  echo.close();
});

test("E2E: banned targets rejected with spec error codes", async () => {
  const psk = randomBytes(32);
  const { client } = await makePair(psk, psk);
  await client.handshake();
  const tryOpen = async (host, port) => {
    const s = client.openStream({ host, port });
    return s.opened.then(() => "opened", (e) => e.code);
  };
  assert.equal(await tryOpen("1.2.3.4", 25), ERR.PROHIBITED_PORT);
  assert.equal(await tryOpen("127.0.0.1", 80), ERR.PRIVATE_TARGET);
  assert.equal(await tryOpen("10.1.2.3", 80), ERR.PRIVATE_TARGET);
  assert.equal(await tryOpen("172.16.0.9", 80), ERR.PRIVATE_TARGET);
  assert.equal(await tryOpen("192.168.1.1", 80), ERR.PRIVATE_TARGET);
  assert.equal(await tryOpen("169.254.169.254", 80), ERR.PRIVATE_TARGET);
  assert.equal(await tryOpen("::1", 80), ERR.PRIVATE_TARGET);
  assert.equal(await tryOpen("hollow.example.workers.dev", 443), ERR.LOOP_TARGET);
  assert.equal(await tryOpen("other.example.workers.dev", 443), ERR.UNSUPPORTED_TARGET);
  client.close();
});

test("E2E: 7th stream queues with OPEN_QUEUED, released when a slot frees", async () => {
  const psk = randomBytes(32);
  const { server: echo, port } = await startEcho();
  const { client } = await makePair(psk, psk);
  await client.handshake();
  const streams = [];
  for (let i = 0; i < 6; i++) {
    const s = client.openStream({ host: "localhost", port });
    await s.opened;
    streams.push(s);
  }
  const s7 = client.openStream({ host: "localhost", port });
  const queuedP = new Promise((res) => { s7.onQueued = res; });
  const info = await queuedP;
  assert.equal(info.position, 1);
  assert.equal(info.maxWaitMs, 5000);
  // free a slot by resetting one stream
  streams[0].reset();
  const gate = await s7.opened;
  assert.equal(gate, GATE.CONNECT);
  client.close();
  echo.close();
});

test("E2E: closeWrite does not overtake queued DATA (ordering regression)", async () => {
  const psk = randomBytes(32);
  // half-close-correct echo peer: on FIN, end only after writes have flushed
  const echo = net.createServer({ allowHalfOpen: true }, (s) => {
    s.on("data", (d) => s.write(d));
    s.on("end", () => {
      const iv = setInterval(() => {
        if (s.writableLength === 0) { clearInterval(iv); s.end(); }
      }, 5);
    });
  });
  await new Promise((r) => echo.listen(0, "127.0.0.1", r));
  const port = echo.address().port;
  const { client } = await makePair(psk, psk);
  await client.handshake();
  const s = client.openStream({ host: "localhost", port });
  await s.opened;
  const total = 300 * 1024;
  const data = new Uint8Array(total);
  for (let off = 0; off < total; off += 65536) {
    data.set(randomBytes(Math.min(65536, total - off)), off);
  }
  let received = 0;
  const bufs = [];
  s.onData = (d) => { bufs.push(Buffer.from(d)); received += d.length; };
  const ended = new Promise((res) => { s.onEnd = res; });
  s.write(data);
  s.closeWrite(); // immediate close: must still deliver all 300KiB first
  await ended;
  // bytes may still be in flight records right at CLOSE; wait for full count
  const t0 = Date.now();
  while (received < total && Date.now() - t0 < 10000) {
    await new Promise((r) => setTimeout(r, 50));
  }
  assert.equal(received, total);
  assert.ok(Buffer.concat(bufs).equals(Buffer.from(data)));
  client.close();
  echo.close();
});

test("socks5: greeting+request pipelined in one chunk is parsed (reader regression)", async () => {
  // Regression: the original readN used sock.unshift() for leftover bytes,
  // which silently drops them on a flowing socket — a greeting and request
  // arriving in one TCP chunk hung forever. The buffered reader must parse
  // both, and bytes pipelined after the request must reach the stream.
  const { startSocks } = await import("../cli/src/socks.js");
  const fakeStream = {
    id: 1, gate: 0, pending: [], state: "open", paused: false,
    opened: Promise.resolve(0),
    written: [],
    write(d) { this.written.push(Buffer.from(d)); return true; },
    consume() {}, closeWrite() {}, reset() {},
  };
  const fakeClient = { state: "open", openStream: () => fakeStream };
  const server = await startSocks({ getClient: () => fakeClient, host: "127.0.0.1", port: 0, log: () => {} });
  const port = server.address().port;
  const c = net.connect(port, "127.0.0.1");
  await once(c, "connect");
  // greeting + request + first payload byte, all in ONE write
  const req = Buffer.concat([
    Buffer.from([0x05, 0x01, 0x00]),
    Buffer.from([0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x10, 0xe1]),
    Buffer.from("X"),
  ]);
  c.write(req);
  const replies = [];
  await new Promise((res, rej) => {
    const to = setTimeout(() => rej(new Error("socks replies timeout: " + JSON.stringify(replies))), 5000);
    c.on("data", (d) => {
      replies.push(...d);
      if (replies.length >= 12) { clearTimeout(to); res(); }
    });
  });
  assert.equal(replies[0], 0x05); assert.equal(replies[1], 0x00); // greeting ok
  assert.equal(replies[2], 0x05); assert.equal(replies[3], 0x00); // REP success
  assert.equal(Buffer.concat(fakeStream.written).toString(), "X"); // pipelined byte delivered
  c.destroy();
  server.close();
});

test("E2E: carrier death fails all streams; a fresh carrier works (§8.4)", async () => {
  const psk = randomBytes(32);
  const { server: echo, port } = await startEcho();
  const { client, server } = await makePair(psk, psk);
  await client.handshake();
  const s = client.openStream({ host: "localhost", port });
  await s.opened;
  const failed = new Promise((res) => { s.onFail = res; });
  server.transport.close(); // simulate platform killing the carrier
  const reason = await failed;
  assert.ok(reason);
  assert.equal(client.state, "dead");
  const pair2 = await makePair(psk, psk);
  await pair2.client.handshake();
  const s2 = pair2.client.openStream({ host: "localhost", port });
  assert.equal(await s2.opened, GATE.CONNECT);
  pair2.client.close();
  echo.close();
});

test("E2E: fetch gate fallback on the spec's special connect() error (§7.3-2, §7.4)", async () => {
  const psk = randomBytes(32);
  const [ta, tb] = memoryTransportPair();
  const v = await deriveVerifier(psk);
  const server = new HollowServer({
    transport: tb,
    verifiers: new Map([[1, v]]),
    ownHost: "hollow.example.workers.dev",
    zoneSuffix: "example.workers.dev",
    connectFn: async () => {
      throw new Error("proxy request failed, cannot connect to the specified address. It looks like you might be trying to connect to a HTTP-based service — consider using fetch instead");
    },
    fetchFn: async (url, init) => {
      assert.equal(url, "http://some-cf-host.example:80/index.html");
      assert.equal(init.method, "GET");
      assert.equal(init.redirect, "manual");
      return {
        status: 200, statusText: "OK",
        headers: new Map([["content-type", "text/plain"]]),
        arrayBuffer: async () => new TextEncoder().encode("fetch-gate-body").buffer,
      };
    },
  });
  const client = new HollowClient({ transport: ta, psk, keyId: 1 });
  await client.handshake();
  const s = client.openStream({ host: "some-cf-host.example", port: 80, schemeHint: 1, gatePolicy: 0 });
  const gate = await s.opened;
  assert.equal(gate, 1); // GATE.FETCH
  const chunks = [];
  const ended = new Promise((res) => { s.onEnd = res; });
  s.onData = (d) => chunks.push(Buffer.from(d));
  s.write(new TextEncoder().encode("GET /index.html HTTP/1.1\r\nHost: some-cf-host.example\r\n\r\n"));
  s.closeWrite();
  await ended;
  const text = Buffer.concat(chunks).toString("utf8");
  assert.match(text, /^HTTP\/1\.1 200 OK\r\n/);
  assert.ok(text.includes("content-length: 15"));
  assert.ok(text.endsWith("fetch-gate-body"));
  assert.equal(server.occupancy, 0); // slot released after the transaction
  assert.equal(server.fetchActive, 0);
  client.close();
});

test("E2E: fetch fallback refused when gate_policy=connect-only (§7.3)", async () => {
  const psk = randomBytes(32);
  const [ta, tb] = memoryTransportPair();
  const v = await deriveVerifier(psk);
  new HollowServer({
    transport: tb,
    verifiers: new Map([[1, v]]),
    ownHost: "hollow.example.workers.dev",
    zoneSuffix: "example.workers.dev",
    connectFn: async () => {
      throw new Error("proxy request failed, cannot connect to the specified address");
    },
    fetchFn: async () => { throw new Error("must not be called"); },
  });
  const client = new HollowClient({ transport: ta, psk, keyId: 1 });
  await client.handshake();
  const s = client.openStream({ host: "some-cf-host.example", port: 80, schemeHint: 1, gatePolicy: 1 });
  const err = await s.opened.then(() => null, (e) => e);
  assert.equal(err.code, ERR.CF_SEGMENT_NON_HTTP);
  client.close();
});

test("E2E: over-window DATA is RESET with flow_control_violation", async () => {
  const psk = randomBytes(32);
  // blackhole target: accepts the connection, never reads (writes never
  // complete), so the server cannot replenish the stream window (§6.5)
  const blackhole = async () => ({
    readable: new ReadableStream({ start() {} }),
    writable: new WritableStream({ write() { return new Promise(() => {}); } }),
    opened: Promise.resolve(),
    close() {},
  });
  const { client } = await makePair(psk, psk, blackhole);
  await client.handshake();
  const s = client.openStream({ host: "localhost", port: 9 });
  await s.opened;
  const resetP = new Promise((res) => { s.onReset = res; });
  // bypass the client's own flow control: raw DATA frames totaling over the
  // 256 KiB stream window (each frame within the per-frame cap)
  for (let i = 0; i < 20; i++) {
    client._sendFrame(buildFrame(FT.DATA, s.id, randomBytes(MAX_PAYLOAD)), true);
  }
  const code = await resetP;
  assert.equal(code, ERR.FLOW_CONTROL_VIOLATION);
  client.close();
});

test("occupancy wedge (NP-1116-01): remote EOF holds §7.5 slots until the app closes", async () => {
  // Fake target: first write is echoed, then the readable side EOFs —
  // the tcpbin idle-close shape that wedged the M4 soak for an hour.
  function fakeTarget() {
    let ctrl; let echoed = false;
    const readable = new ReadableStream({ start(c) { ctrl = c; } });
    const writable = new WritableStream({
      write(chunk) {
        if (!echoed) {
          echoed = true;
          ctrl.enqueue(new Uint8Array(chunk));
          setTimeout(() => { try { ctrl.close(); } catch {} }, 20);
        }
      },
    });
    return { readable, writable, opened: Promise.resolve(), close() { try { ctrl.close(); } catch {} } };
  }
  const psk = randomBytes(32);
  const { client, server } = await makePair(psk, psk, async () => fakeTarget());
  await client.handshake();
  const streams = [];
  for (let i = 0; i < 6; i++) {
    const s = client.openStream({ host: "target.example", port: 4242, schemeHint: 0, gatePolicy: 0 });
    await s.opened;
    const ended = new Promise((res) => { s.onEnd = res; });
    s.onData = () => {};
    s.write(new Uint8Array(300).fill(0x61));
    await ended; // server CLOSE arrived; app deliberately does NOT close
    streams.push(s);
  }
  assert.equal(server.occupancy, 6);
  const s7 = client.openStream({ host: "target.example", port: 4242, schemeHint: 0, gatePolicy: 0 });
  await assert.rejects(s7.opened, (e) => e.code === ERR.CONCURRENCY_LIMIT);
  assert.equal(server.occupancy, 6);
  // The app fulfils its CLOSE obligation -> slots release (§6.3).
  for (const s of streams) s.closeWrite();
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(server.occupancy, 0);
  const s8 = client.openStream({ host: "target.example", port: 4242, schemeHint: 0, gatePolicy: 0 });
  await s8.opened;
  assert.equal(server.occupancy, 1);
  client.close();
});
