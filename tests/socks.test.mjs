// NP-1116-02 (P1): the SOCKS pump must fulfil the CLOSE obligation when
// the server half-closes (stream onEnd) — regression for NP-1116-01.
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import http from "node:http";
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
    // (Origin-form requests are neither CONNECT nor absolute form.
    // Absolute form itself became a supported dialect in NP-1117-21
    // and is covered by the four-way live test below.)
    {
      const s = net.connect(port, "127.0.0.1");
      await new Promise((r) => s.once("connect", r));
      const closedP = new Promise((r) => s.once("close", r));
      s.write("GET /origin-form HTTP/1.1\r\nHost: example.com\r\n\r\n");
      await closedP;
      s.destroy();
    }
  } finally {
    client.close();
    server.close();
    echo.close();
  }
});

// ---- NP-1117-14: bounded 0x01 retry at the SOCKS layer ----
import { ERR } from "../shared/protocol.js";

function rejectingStream(code) {
  const e = new Error("open rejected " + code);
  e.code = code; e.retryAfterMs = 0;
  const s = fakeStream();
  s.opened = Promise.reject(e);
  return s;
}
async function socksConnect(port, payloadAfter = null) {
  const sock = net.connect(port, "127.0.0.1");
  await new Promise((r) => sock.once("connect", r));
  const recv = [];
  sock.on("data", (d) => recv.push(d));
  sock.write(Buffer.from([0x05, 0x01, 0x00])); // greeting: no-auth
  await new Promise((r) => setTimeout(r, 30));
  const t0 = Date.now();
  sock.write(Buffer.from([0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80])); // CONNECT 1.2.3.4:80
  // wait for the 10-byte request reply (after the 2-byte greeting reply)
  for (;;) {
    const bytes = Buffer.concat(recv);
    if (bytes.length >= 12) {
      const rep = bytes[2 + 1];
      if (payloadAfter) sock.write(payloadAfter);
      return { sock, rep, elapsed: Date.now() - t0, bytes };
    }
    if (Date.now() - t0 > 8000) throw new Error("no SOCKS reply");
    await new Promise((r) => setTimeout(r, 10));
  }
}

test("0x01 retry (c): two concurrency_limit rejects then success — SOCKS succeeds, exactly one live stream", async () => {
  const created = [];
  const good = fakeStream();
  const writes = [];
  good.write = (d) => { writes.push(Buffer.from(d)); return true; };
  const fakeClient = {
    state: "open",
    openStream: () => {
      const s = created.length < 2 ? rejectingStream(ERR.CONCURRENCY_LIMIT) : good;
      created.push(s);
      return s;
    },
  };
  const server = await startSocks({ getClient: () => fakeClient, port: 0, host: "127.0.0.1", openRetry: { baseMs: 20, capMs: 2000 } });
  const port = server.address().port;
  const { sock, rep } = await socksConnect(port, Buffer.from("ping"));
  assert.equal(rep, 0x00); // REP.SUCCESS after the retries
  assert.equal(created.length, 3); // 2 rejected attempts + 1 success
  assert.equal(created[0].onData, null); // rejected streams were never pumped
  assert.equal(created[1].onData, null);
  assert.ok(good.onData !== null); // only the surviving stream is attached
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(Buffer.concat(writes).toString(), "ping");
  sock.destroy();
  server.close();
});

test("0x01 retry (d): persistent concurrency_limit fails only after the budget, near the cap", async () => {
  let calls = 0;
  const fakeClient = {
    state: "open",
    openStream: () => { calls++; return rejectingStream(ERR.CONCURRENCY_LIMIT); },
  };
  const server = await startSocks({ getClient: () => fakeClient, port: 0, host: "127.0.0.1", openRetry: { baseMs: 20, capMs: 300 } });
  const port = server.address().port;
  const { sock, rep, elapsed } = await socksConnect(port);
  assert.equal(rep, 0x05); // REP.REFUSED (repForOpenError for 0x01)
  assert.ok(calls >= 3, `expected several attempts, got ${calls}`);
  assert.ok(elapsed >= 250 && elapsed < 2500, `elapsed ${elapsed} ms should sit near the 300 ms cap`);
  sock.destroy();
  server.close();
});

test("0x01 retry (e): target_unreachable (0x05) fails immediately, never retried", async () => {
  let calls = 0;
  const fakeClient = {
    state: "open",
    openStream: () => { calls++; return rejectingStream(ERR.TARGET_UNREACHABLE); },
  };
  const server = await startSocks({ getClient: () => fakeClient, port: 0, host: "127.0.0.1", openRetry: { baseMs: 20, capMs: 300 } });
  const port = server.address().port;
  const { sock, rep, elapsed } = await socksConnect(port);
  assert.equal(rep, 0x05); // REP.REFUSED for target_unreachable
  assert.equal(calls, 1); // no retry
  assert.ok(elapsed < 250, `elapsed ${elapsed} ms must be immediate`);
  sock.destroy();
  server.close();
});

test("live four-way (NP-1117-21): SOCKS5 + CONNECT + absolute GET + absolute POST share one port without cross-talk", async () => {
  // HTTP target that reports exactly what arrived (method, origin-form
  // url, body, and whether proxy headers leaked through).
  const target = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (d) => chunks.push(d));
    req.on("end", () => {
      const payload = JSON.stringify({
        method: req.method, url: req.url, body: Buffer.concat(chunks).toString(),
        proxyauth: req.headers["proxy-authorization"] ?? null,
        proxyconn: req.headers["proxy-connection"] ?? null,
      });
      res.writeHead(200, { "content-type": "application/json", "content-length": Buffer.byteLength(payload) });
      res.end(payload);
    });
  });
  await new Promise((r) => target.listen(0, "127.0.0.1", r));
  const httpPort = target.address().port;
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
  const server = await startSocks({ getClient: () => client, port: 0, host: "127.0.0.1" });
  const port = server.address().port;

  const readAll = (s) => new Promise((resolve, reject) => {
    const chunks = [];
    const to = setTimeout(() => reject(new Error("readAll timeout")), 10000);
    s.on("data", (d) => chunks.push(d));
    s.on("end", () => { clearTimeout(to); resolve(Buffer.concat(chunks)); });
    s.on("error", (e) => { clearTimeout(to); reject(e); });
  });
  const parseResp = (buf) => {
    const txt = buf.toString("latin1");
    const status = Number((txt.match(/^HTTP\/1\.[01] (\d+)/) || [])[1] || 0);
    const body = txt.slice(txt.indexOf("\r\n\r\n") + 4);
    return { status, json: JSON.parse(body) };
  };
  // Stepwise helpers over raw sockets (small replies, readBytes exists above).
  async function socks5Flow() {
    const s = net.connect(port, "127.0.0.1");
    await new Promise((r) => s.once("connect", r));
    s.write(Buffer.from([0x05, 0x01, 0x00]));
    await readBytes(s, 2);
    const dom = Buffer.from("localhost", "utf8");
    s.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, dom.length]), dom, Buffer.from([(httpPort >> 8) & 0xff, httpPort & 0xff])]));
    const rep = await readBytes(s, 10);
    assert.equal(rep[1], 0x00);
    const all = readAll(s);
    s.write(`GET /via-socks HTTP/1.1\r\nHost: localhost:${httpPort}\r\nConnection: close\r\n\r\n`);
    const { status, json } = parseResp(await all);
    s.destroy();
    return { status, json };
  }
  async function connectFlow() {
    const s = net.connect(port, "127.0.0.1");
    await new Promise((r) => s.once("connect", r));
    s.write(`CONNECT localhost:${httpPort} HTTP/1.1\r\nHost: localhost:${httpPort}\r\n\r\n`);
    const head = await readBytes(s, 39);
    assert.ok(head.toString("latin1").startsWith("HTTP/1.1 200"));
    const all = readAll(s);
    s.write(`GET /via-connect HTTP/1.1\r\nHost: localhost:${httpPort}\r\nConnection: close\r\n\r\n`);
    const { status, json } = parseResp(await all);
    s.destroy();
    return { status, json };
  }
  async function absoluteFlow(raw) {
    const s = net.connect(port, "127.0.0.1");
    await new Promise((r) => s.once("connect", r));
    const all = readAll(s);
    s.write(raw);
    const { status, json } = parseResp(await all);
    s.destroy();
    return { status, json };
  }
  try {
    const [r1, r2, r3, r4] = await Promise.all([
      socks5Flow(),
      connectFlow(),
      absoluteFlow(`GET http://localhost:${httpPort}/abs-get?x=1 HTTP/1.1\r\nHost: localhost:${httpPort}\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic Zm9v\r\nConnection: close\r\n\r\n`),
      absoluteFlow(`POST http://localhost:${httpPort}/abs-post HTTP/1.1\r\nHost: localhost:${httpPort}\r\nContent-Type: text/plain\r\nContent-Length: 10\r\nConnection: close\r\n\r\nhello-body`),
    ]);
    assert.equal(r1.status, 200); assert.equal(r1.json.url, "/via-socks");
    assert.equal(r2.status, 200); assert.equal(r2.json.url, "/via-connect");
    // Absolute GET: the request line arrived in origin form (rewrite),
    // and the proxy headers were stripped before forwarding.
    assert.equal(r3.status, 200);
    assert.equal(r3.json.method, "GET");
    assert.equal(r3.json.url, "/abs-get?x=1");
    assert.equal(r3.json.proxyauth, null);
    assert.equal(r3.json.proxyconn, null);
    // Absolute POST: the body arrived verbatim.
    assert.equal(r4.status, 200);
    assert.equal(r4.json.method, "POST");
    assert.equal(r4.json.url, "/abs-post");
    assert.equal(r4.json.body, "hello-body");
  } finally {
    client.close();
    server.close();
    target.close();
  }
});

test("characterization (NP-1117-21 c): a SOCKS4 greeting is destroyed unanswered — known deterministic behavior, not support", async () => {
  // Chromium under the old WinINET "socks=" form spoke exactly this
  // (proxy_config.cc maps "socks" to SOCKS4). The listener never
  // speaks SOCKS4; the fix was on the registry side (http=/https=),
  // not here. This test pins the behavior so it is a decision on
  // record, not an accident.
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
  const server = await startSocks({ getClient: () => client, port: 0, host: "127.0.0.1" });
  const port = server.address().port;
  try {
    const s = net.connect(port, "127.0.0.1");
    await new Promise((r) => s.once("connect", r));
    let received = 0;
    s.on("data", (d) => { received += d.length; });
    const closedP = new Promise((r) => s.once("close", r));
    s.write(Buffer.from([0x04, 0x01, 0x00, 0x50, 1, 2, 3, 4, 0x00])); // VN=4 CD=1 port 80, 1.2.3.4, no userid
    await closedP;
    assert.equal(received, 0);
    s.destroy();
  } finally {
    client.close();
    server.close();
  }
});
