// §7.5 occupancy regression (NP-1117-08): spec v0.2.0 counts only
// IN-FLIGHT ESTABLISHMENTS. The pre-fix implementation counted each
// stream's whole lifetime, so 6 browser keep-alive streams wedged the
// session (OPEN_QUEUED -> 5,000 ms -> 0x01). Both cells below are red
// on the old implementation and green on the new one.
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { Readable, Writable } from "node:stream";
import { HollowClient } from "../shared/client-core.js";
import { HollowServer } from "../shared/server-core.js";
import { deriveVerifier, ERR } from "../shared/protocol.js";
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
    fetchFn: async () => { throw new Error("no fetch in occupancy harness"); },
  });
  const client = new HollowClient({ transport: ta, psk, keyId: 1 });
  await client.handshake();
  assert.equal(client.state, "open");
  return { client, server };
}

test("burst cell: 24 streams opened at once all establish, none rejected 0x01", async () => {
  const { server: echo, port } = await startEcho();
  const { client, server } = await makePair(nodeConnect);
  const N = 24;
  const streams = [];
  const results = [];
  for (let i = 0; i < N; i++) {
    const s = client.openStream({ host: "localhost", port, schemeHint: 0, gatePolicy: 0 });
    streams.push(s);
    results.push(s.opened.then(
      () => ({ ok: true }),
      (e) => ({ ok: false, code: e && e.code }),
    ));
  }
  const settled = await Promise.all(results);
  const rejected = settled.filter((r) => !r.ok);
  assert.equal(rejected.length, 0, `no stream may be rejected (got ${JSON.stringify(rejected)})`);
  assert.ok(!settled.some((r) => r.code === ERR.CONCURRENCY_LIMIT), "no 0x01 concurrency_limit");
  // keep-alive: all 24 stay open and usable
  assert.equal(server.streams.size, N);
  assert.equal(server.occupancy, 0); // every establishment has concluded
  const probe = streams[7];
  const echoed = new Promise((res) => {
    const chunks = [];
    probe.onData = (d) => { chunks.push(Buffer.from(d)); if (Buffer.concat(chunks).length >= 4) res(Buffer.concat(chunks).toString()); };
  });
  probe.write(new TextEncoder().encode("ping"));
  assert.equal(await echoed, "ping");
  client.close();
  echo.close();
});

test("dead-hold cell: 6 established keep-alive streams do not block a 7th", async () => {
  const { server: echo, port } = await startEcho();
  const { client, server } = await makePair(nodeConnect);
  const held = [];
  for (let i = 0; i < 6; i++) {
    const s = client.openStream({ host: "localhost", port, schemeHint: 0, gatePolicy: 0 });
    await s.opened;
    held.push(s); // established, deliberately kept alive and idle
  }
  assert.equal(server.occupancy, 0);
  const s7 = client.openStream({ host: "localhost", port, schemeHint: 0, gatePolicy: 0 });
  await s7.opened; // old implementation: queued 5,000 ms -> rejected 0x01
  const s8 = client.openStream({ host: "localhost", port, schemeHint: 0, gatePolicy: 0 });
  await s8.opened;
  assert.equal(server.streams.size, 8);
  client.close();
  echo.close();
});

test("pairing: occupancy tracks in-flight establishments and returns to 0 on success and on failure", async () => {
  const { server: echo, port } = await startEcho();
  // success side: establishments held in flight by a 300 ms connect delay
  const slowConnect = async (opts) => {
    await new Promise((r) => setTimeout(r, 300));
    return nodeConnect(opts);
  };
  {
    const { client, server } = await makePair(slowConnect);
    const pending = [0, 1, 2].map(() => client.openStream({ host: "localhost", port, schemeHint: 0, gatePolicy: 0 }));
    await new Promise((r) => setTimeout(r, 120)); // all three in flight
    assert.equal(server.occupancy, 3);
    await Promise.all(pending.map((s) => s.opened));
    assert.equal(server.occupancy, 0);
    client.close();
  }
  // failure side: every establishment is refused by the target side
  {
    const failConnect = async () => { throw new Error("connect ECONNREFUSED 127.0.0.1:9"); };
    const { client, server } = await makePair(failConnect);
    const attempts = [0, 1, 2].map(() => client.openStream({ host: "localhost", port: 9, schemeHint: 0, gatePolicy: 0 }));
    const codes = await Promise.all(attempts.map((s) => s.opened.then(() => null, (e) => e && e.code)));
    assert.ok(codes.every((c) => c === ERR.TARGET_UNREACHABLE), `expected target_unreachable, got ${JSON.stringify(codes)}`);
    assert.equal(server.occupancy, 0);
    client.close();
  }
  echo.close();
});

// ---- NP-1117-10 red-team gap cells (must-fixes A / B / C) ----
import { buildFrame, buildOpenPayload, resetPayload, FT, GATE } from "../shared/protocol.js";

const waitFor = async (fn, ms = 4000) => {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { if (fn()) return; await new Promise((r) => setTimeout(r, 10)); }
  throw new Error("waitFor timeout");
};
function fakeSocket({ writerThrows = false } = {}) {
  const s = {
    readable: new ReadableStream({ start() {} }),
    writable: writerThrows
      ? { getWriter() { throw new Error("socket dead in the writer window"); } }
      : new WritableStream({ write() {} }),
    opened: Promise.resolve(),
    closeCalls: 0,
    close() { s.closeCalls++; },
  };
  return s;
}

test("must-fix A: writer-acquisition failure releases the slot and cleans the stream", async () => {
  const { server: echo, port } = await startEcho();
  const bad = fakeSocket({ writerThrows: true });
  let first = true;
  const connectFn = async (opts) => {
    if (first) { first = false; return bad; }
    return nodeConnect(opts);
  };
  const { client, server } = await makePair(connectFn);
  const s = client.openStream({ host: "localhost", port, schemeHint: 0, gatePolicy: 0 });
  await assert.rejects(s.opened, (e) => e && e.code === ERR.TARGET_UNREACHABLE);
  assert.equal(server.occupancy, 0); // no leaked slot
  assert.equal(server.streams.size, 0); // no leaked stream entry
  assert.equal(bad.closeCalls, 1); // the dead socket was closed
  // the session is healthy afterwards
  const s2 = client.openStream({ host: "localhost", port, schemeHint: 0, gatePolicy: 0 });
  await s2.opened;
  client.close();
  echo.close();
});

test("must-fix B: id reuse mid-establishment — the old establishment cannot cross-wire", async () => {
  const sockA = fakeSocket();
  const sockB = fakeSocket();
  let releaseA = null;
  let calls = 0;
  const connectFn = () => {
    calls++;
    if (calls === 1) return new Promise((res) => { releaseA = () => res(sockA); });
    return Promise.resolve(sockB);
  };
  const { client, server } = await makePair(connectFn);
  const open41 = () => client._sendFrame(buildFrame(FT.OPEN, 41,
    buildOpenPayload({ host: "target.example", port: 4242, schemeHint: 0, gatePolicy: 0 })), true);
  open41(); // establishment #1 starts and stays in flight
  await waitFor(() => server.occupancy === 1);
  // client resets the stream mid-establishment, then reuses the id
  client._sendFrame(buildFrame(FT.RESET, 41, resetPayload(0)), true);
  await waitFor(() => !server.streams.has(41));
  open41(); // establishment #2 under the same id — completes at once
  await waitFor(() => server.streams.has(41) && server.occupancy === 1);
  const s2ref = server.streams.get(41);
  assert.equal(s2ref.socket, sockB);
  // the old establishment finally connects: identity check must make
  // it discard its socket and release its slot, touching nothing else
  releaseA();
  await waitFor(() => server.occupancy === 0);
  assert.equal(sockA.closeCalls, 1); // discarded, not adopted
  assert.equal(server.streams.get(41), s2ref); // same object, untouched
  assert.equal(s2ref.socket, sockB);
  client.close();
});

test("must-fix C: fetch gate holds its slot until response headers arrive (slow headers)", async () => {
  const psk = randomBytes(32);
  const [ta, tb] = memoryTransportPair();
  const v = await deriveVerifier(psk);
  let resolveFetch = null;
  let fetchCalled = false;
  const server = new HollowServer({
    transport: tb, verifiers: new Map([[1, v]]),
    ownHost: "hollow.example.workers.dev", zoneSuffix: "example.workers.dev",
    connectFn: async () => { throw new Error("proxy request failed, cannot connect to the specified address"); },
    fetchFn: () => {
      fetchCalled = true;
      return new Promise((res) => {
        resolveFetch = () => res({
          status: 200, statusText: "OK",
          headers: new Map([["content-type", "text/plain"]]),
          arrayBuffer: async () => new TextEncoder().encode("fetch-body").buffer,
        });
      });
    },
  });
  const client = new HollowClient({ transport: ta, psk, keyId: 1 });
  await client.handshake();
  const s = client.openStream({ host: "some-cf-host.example", port: 80, schemeHint: 1, gatePolicy: 0 });
  const gate = await s.opened;
  assert.equal(gate, GATE.FETCH);
  assert.equal(server.occupancy, 1); // held past gate selection (frozen letter)
  const ended = new Promise((res) => { s.onEnd = res; });
  s.onData = () => {};
  s.write(new TextEncoder().encode("GET / HTTP/1.1\r\nHost: some-cf-host.example\r\n\r\n"));
  s.closeWrite();
  await waitFor(() => fetchCalled);
  assert.equal(server.occupancy, 1); // headers not yet arrived — still held
  resolveFetch();
  await waitFor(() => server.occupancy === 0); // headers arrived — released
  await ended; // the body transfer completes without holding the slot
  assert.equal(server.fetchActive, 0);
  client.close();
});

test("burst cell x48 (NP-1117-14): 48 at once under the tuned admission (16 in flight + 64 queue), zero rejected, zero timeouts", async () => {
  const { server: echo, port } = await startEcho();
  const { client, server } = await makePair(nodeConnect);
  const N = 48;
  const streams = [];
  const t0 = Date.now();
  for (let i = 0; i < N; i++) {
    streams.push(client.openStream({ host: "localhost", port, schemeHint: 0, gatePolicy: 0 }));
  }
  const settled = await Promise.all(streams.map((s) => s.opened.then(
    () => ({ ok: true }),
    (e) => ({ ok: false, code: e && e.code }),
  )));
  const elapsed = Date.now() - t0;
  assert.ok(settled.every((r) => r.ok), `all 48 must open (failures: ${JSON.stringify(settled.filter((r) => !r.ok))})`);
  assert.equal(server.streams.size, N);
  assert.equal(server.occupancy, 0);
  assert.ok(elapsed < 5000, `no stream may ride the 5,000 ms queue timeout (took ${elapsed} ms)`);
  client.close();
  echo.close();
});
