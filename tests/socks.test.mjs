// NP-1116-02 (P1): the SOCKS pump must fulfil the CLOSE obligation when
// the server half-closes (stream onEnd) — regression for NP-1116-01.
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { startSocks } from "../cli/src/socks.js";

function fakeStream() {
  return {
    id: 7, gate: 1, state: "open", pending: [], paused: false,
    opened: Promise.resolve(1),
    onData: null, onEnd: null, onReset: null, onFail: null, onDrain: null,
    closeWriteCalls: 0, resetCalls: 0,
    write() { return true; },
    consume() {},
    closeWrite() { this.closeWriteCalls += 1; },
    reset() { this.resetCalls += 1; },
  };
}

test("socks pump: onEnd ends the local socket AND closeWrites the stream", async () => {
  const stream = fakeStream();
  const fakeClient = { state: "open", openStream: () => stream };
  const server = await startSocks({ getClient: () => fakeClient, port: 0, host: "127.0.0.1" });
  const port = server.address().port;
  const sock = net.connect(port, "127.0.0.1");
  await new Promise((r) => sock.once("connect", r));
  const recv = [];
  sock.on("data", (d) => recv.push(d));
  sock.write(Buffer.from([0x05, 0x01, 0x00])); // greeting: no-auth
  await new Promise((r) => setTimeout(r, 50));
  // CONNECT 1.2.3.4:80
  sock.write(Buffer.from([0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80]));
  await new Promise((r) => setTimeout(r, 100));
  const bytes = Buffer.concat(recv);
  assert.equal(bytes[bytes.length - 10 + 1], 0x00); // REP.SUCCESS in the reply
  assert.equal(stream.closeWriteCalls, 0);
  const finP = new Promise((r) => sock.once("end", r));
  stream.onEnd(); // server half-close arrives
  await finP; // local socket got its FIN (sock.end())
  assert.equal(stream.closeWriteCalls, 1); // and the obligation was fulfilled
  sock.destroy();
  server.close();
});

// NP-1117-07 live self-test: ONE real listening port must serve BOTH
// dialects end-to-end (real Hollow client/server pair, local echo
// target) — SOCKS5 (0x05) and HTTP CONNECT ('C'). This is the live
// check that would have caught the global-mode protocol mismatch:
// settings written for one dialect, listener speaking only the other.
import { HollowClient } from "../shared/client-core.js";
import { HollowServer } from "../shared/server-core.js";
import { deriveVerifier, GATE } from "../shared/protocol.js";
import { randomBytes } from "../shared/crypto.js";
import { Readable, Writable } from "node:stream";

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

test("live dual-protocol: SOCKS5 and HTTP CONNECT both carry a stream on one port", async () => {
  const echo = net.createServer((s) => s.pipe(s));
  await new Promise((r) => echo.listen(0, "127.0.0.1", r));
  const echoPort = echo.address().port;
  const psk = randomBytes(32);
  const [ta, tb] = memoryTransportPair();
  const v = await deriveVerifier(psk);
  new HollowServer({
    transport: tb, verifiers: new Map([[1, v]]),
    ownHost: "hollow.example.workers.dev", zoneSuffix: "example.workers.dev",
    connectFn: nodeConnect,
    fetchFn: async () => { throw new Error("no fetch in live self-test"); },
  });
  const client = new HollowClient({ transport: ta, psk, keyId: 1 });
  await client.handshake();
  assert.equal(client.state, "open");
  const server = await startSocks({ getClient: () => client, port: 0, host: "127.0.0.1" });
  const port = server.address().port;
  try {
    // --- dialect 1: SOCKS5 ---
    {
      const s = net.connect(port, "127.0.0.1");
      await new Promise((r) => s.once("connect", r));
      s.write(Buffer.from([0x05, 0x01, 0x00]));
      const greet = await readBytes(s, 2);
      assert.deepEqual([...greet], [0x05, 0x00]);
      // domain form: a literal 127.0.0.1 target is (correctly) refused
      // by the server's private-target guard; "localhost" is how local
      // targets are addressed in the protocol tests.
      const dom = Buffer.from("localhost", "utf8");
      s.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, dom.length]), dom, Buffer.from([(echoPort >> 8) & 0xff, echoPort & 0xff])]));
      const rep = await readBytes(s, 10);
      assert.equal(rep[1], 0x00, "SOCKS5 CONNECT must succeed");
      s.write(Buffer.from("via-socks5"));
      const echoed = await readBytes(s, 10);
      assert.equal(echoed.toString(), "via-socks5");
      s.destroy();
    }
    // --- dialect 2: HTTP CONNECT ---
    {
      const s = net.connect(port, "127.0.0.1");
      await new Promise((r) => s.once("connect", r));
      s.write(`CONNECT localhost:${echoPort} HTTP/1.1\r\nHost: localhost:${echoPort}\r\n\r\n`);
      const head = await readBytes(s, 39);
      assert.ok(head.toString("latin1").startsWith("HTTP/1.1 200"), `CONNECT must be answered 200, got: ${head.toString("latin1")}`);
      s.write(Buffer.from("via-connect"));
      const echoed = await readBytes(s, 11);
      assert.equal(echoed.toString(), "via-connect");
      s.destroy();
    }
    // --- neither dialect: destroyed, no answer ---
    {
      const s = net.connect(port, "127.0.0.1");
      await new Promise((r) => s.once("connect", r));
      const closedP = new Promise((r) => s.once("close", r));
      s.write("GET http://example.com/ HTTP/1.1\r\n\r\n");
      await closedP;
      s.destroy();
    }
  } finally {
    client.close();
    server.close();
    echo.close();
  }
});
