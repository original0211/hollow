// Electron-runtime phoenix smoke (NP-1118-32, factory-surface
// discipline): the vendored phoenix wrapper must load and behave
// in the Electron runtime (BoringSSL build), not only in plain
// Node. Runs a kill-after-open scenario over memory transports
// against the vendored HollowServer: the carrier dies after the
// stream opens, the GET flight is replayed on a fresh carrier,
// and the echo must come back byte-exact.
// Run: ELECTRON_RUN_AS_NODE=1 ./node_modules/electron/dist/electron tools/electron-phoenix-smoke.mjs
import { HollowClient } from "../vendor/shared/client-core.js";
import { HollowServer } from "../vendor/shared/server-core.js";
import { deriveVerifier } from "../vendor/shared/protocol.js";
import { randomBytes } from "../vendor/shared/crypto.js";
import { wrapPhoenixStream, phoenixShared } from "../vendor/shared/phoenix.js";

function memoryTransportPair() {
  const a = { cb: null, closeCb: null };
  const b = { cb: null, closeCb: null };
  a.send = (bytes) => setImmediate(() => b.cb && b.cb(bytes));
  b.send = (bytes) => setImmediate(() => a.cb && a.cb(bytes));
  a.close = () => setImmediate(() => b.closeCb && b.closeCb());
  b.close = () => setImmediate(() => a.closeCb && a.closeCb());
  a.onMessage = (cb) => { a.cb = cb; };
  b.onMessage = (cb) => { b.cb = cb; };
  a.onClose = (cb) => { a.closeCb = cb; };
  b.onClose = (cb) => { b.closeCb = cb; };
  return [a, b];
}

const psk = randomBytes(32);
const verifier = await deriveVerifier(psk);
const clients = [];
const transports = [];
let heldTarget = null;

async function establish() {
  const [ct, st] = memoryTransportPair();
  transports.push([ct, st]);
  new HollowServer({
    transport: st, verifiers: new Map([[1, verifier]]),
    ownHost: "hollow.example.workers.dev", zoneSuffix: "example.workers.dev",
    connectFn: async () => {
      const t = { received: [], ctl: null };
      const readable = new ReadableStream({ start(c) { t.ctl = c; } });
      const writable = new WritableStream({
        write(chunk) {
          t.received.push(Buffer.from(chunk));
          t.ctl.enqueue(Buffer.from(chunk)); // echo immediately
        },
      });
      heldTarget = t;
      return { readable, writable, opened: Promise.resolve(), close: () => { try { t.ctl.close(); } catch {} } };
    },
    fetchFn: async () => { throw new Error("no fetch in smoke"); },
  });
  const client = new HollowClient({ transport: ct, psk, keyId: 1 });
  await client.handshake();
  clients.push(client);
  return client;
}

const first = await establish();
await establish(); // second carrier for the reopen to land on

const dial = async (client) => {
  const s = client.openStream({ host: "localhost", port: 443, schemeHint: 0, gatePolicy: 0 });
  await s.opened;
  return s;
};
const s0 = await dial(first);
const w = wrapPhoenixStream(s0, async () => dial(clients.find((c) => c.state === "open" && c !== first) || clients[1]));

const flight = Buffer.from("GET / HTTP/1.1\r\nHost: smoke.test\r\n\r\n");
const got = [];
const done = new Promise((resolve, reject) => {
  const to = setTimeout(() => reject(new Error("smoke timeout")), 10000);
  w.onData = (d) => {
    got.push(Buffer.from(d));
    if (Buffer.concat(got).length >= flight.length) { clearTimeout(to); resolve(); }
  };
  w.onFail = (r) => { clearTimeout(to); reject(new Error("stream failed: " + r)); };
});

// Kill the first carrier (both ends: a memory close notifies only the peer).
const [ct0, st0] = transports[0];
ct0.close(); st0.close();
w.write(flight);
await done;
const echoed = Buffer.concat(got);
if (!echoed.equals(flight)) throw new Error("echo mismatch");
if (phoenixShared.reopens !== 1 || phoenixShared.saved !== 1) {
  throw new Error(`counters wrong: reopens=${phoenixShared.reopens} saved=${phoenixShared.saved}`);
}
console.log(`PHOENIX_SMOKE_OK reopens=${phoenixShared.reopens} saved=${phoenixShared.saved} bytes=${echoed.length}`);
process.exit(0);
