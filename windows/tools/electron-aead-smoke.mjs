// Electron runtime AEAD handshake smoke (NP-1117-04).
// Run with the Electron binary as Node:
//   ELECTRON_RUN_AS_NODE=1 ./node_modules/.bin/electron tools/electron-aead-smoke.mjs
// (after `npm run prepare-vendor`; imports the vendored shared/ copy the
// packaged app actually loads.)
//
// Why: Electron 34's BoringSSL node:crypto has no chacha20-poly1305, and
// the packaged-app smoke only proved the app starts — the M2 build could
// never complete a handshake. This smoke runs a full client<->server
// handshake + echo round-trip against the LOCAL server-core (no network,
// no production) inside the Electron runtime, and asserts the AEAD
// backend selection matches an independent probe of that runtime.
import net from "node:net";
import { Readable, Writable } from "node:stream";
import { createCipheriv } from "node:crypto";
import { HollowClient } from "../vendor/shared/client-core.js";
import { HollowServer } from "../vendor/shared/server-core.js";
import { deriveVerifier, GATE } from "../vendor/shared/protocol.js";
import { randomBytes, getAeadBackend } from "../vendor/shared/crypto.js";

function fail(msg) { console.error("ELECTRON_AEAD_SMOKE_FAIL:", msg); process.exit(1); }

if (!process.versions.electron) fail("not running under Electron (process.versions.electron missing)");

// Independent probe of THIS runtime, then compare with the core's choice.
let nativeOk = true;
try {
  createCipheriv("chacha20-poly1305", Buffer.alloc(32), Buffer.alloc(12), { authTagLength: 16 });
} catch { nativeOk = false; }
const backend = getAeadBackend();
const expected = nativeOk ? "native" : "js";
if (backend !== expected) fail(`backend selection mismatch: probe=${expected}, core=${backend}`);
console.log(`electron ${process.versions.electron} node ${process.version}: native AEAD ${nativeOk ? "present" : "MISSING"} -> backend=${backend}`);

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
      readable: Readable.toWeb(sock),
      writable: Writable.toWeb(sock),
      opened: Promise.resolve(),
      close: () => sock.destroy(),
    }));
  });
}

const echo = net.createServer((s) => s.pipe(s));
await new Promise((r) => echo.listen(0, "127.0.0.1", r));
const port = echo.address().port;

try {
  const psk = randomBytes(32);
  const [ta, tb] = memoryTransportPair();
  const v = await deriveVerifier(psk);
  new HollowServer({
    transport: tb,
    verifiers: new Map([[1, v]]),
    ownHost: "hollow.example.workers.dev",
    zoneSuffix: "example.workers.dev",
    connectFn: nodeConnect,
    fetchFn: async () => { throw new Error("no fetch in local smoke"); },
  });
  const client = new HollowClient({ transport: ta, psk, keyId: 1 });
  await client.handshake();
  if (client.state !== "open") fail("handshake did not reach open state");
  const s = client.openStream({ host: "localhost", port, schemeHint: 0, gatePolicy: 0 });
  const gate = await s.opened;
  if (gate !== GATE.CONNECT) fail("stream gate != CONNECT");
  const msg = new TextEncoder().encode("hello hollow (electron aead smoke)");
  const got = [];
  const done = new Promise((res) => {
    s.onData = (d) => { got.push(d); if (Buffer.concat(got).length >= msg.length) res(); };
  });
  s.write(msg);
  await done;
  if (!Buffer.concat(got).equals(Buffer.from(msg))) fail("echo bytes differ");
  client.close();
  console.log("ELECTRON_AEAD_SMOKE_OK backend=" + backend);
} catch (e) {
  fail(String(e && e.message || e));
} finally {
  echo.close();
}
process.exit(0);
