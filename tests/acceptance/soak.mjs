// F-9 soak (spec §9.3): 1 hour of mixed load against the deployed Worker,
// with a per-action JSONL ledger so the request accounting can be closed
// against GraphQL afterwards (§9.2): every carrier = 1 worker request,
// every opened stream = 1 connect() subrequest, no fetch fallbacks expected.
// Env: HOLLOW_SOAK_MINUTES (default 60), HOLLOW_SOAK_OUT (ledger path).
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { HollowClient } from "../../shared/client-core.js";
import { connectWs } from "../../cli/src/ws-client.js";

const WORKER_URL = process.env.HOLLOW_WORKER_URL;
if (!WORKER_URL) throw new Error("HOLLOW_WORKER_URL is not set — the production endpoint is never recorded in this repo (NP-1114-47); supply it out-of-band");
const MINUTES = Number(process.env.HOLLOW_SOAK_MINUTES || 60);
const OUT = process.env.HOLLOW_SOAK_OUT || "soak-ledger.jsonl";
const PSK = new Uint8Array(fs.readFileSync(path.join(os.homedir(), ".hollow", "psk.bin")));

fs.writeFileSync(OUT, "");
const t0 = Date.now();
function log(entry) {
  const line = JSON.stringify({ t: new Date().toISOString(), elapsed_s: Math.round((Date.now() - t0) / 1000), ...entry });
  try { fs.appendFileSync(OUT, line + "\n"); } catch { /* ignore */ }
  console.log(line);
}
log({ action: "soak_start", minutes: MINUTES, target: "tcpbin.com:4242" });

let carriers = 0, streams = 0, bytesMoved = 0, failures = 0;
let client = null, carrierBorn = 0;

async function newCarrier() {
  const raw = await connectWs(WORKER_URL);
  const transport = {
    send: (b) => raw.send(b), close: () => raw.close(), closeCarrier: () => raw.close(),
    onMessage: (cb) => raw.onMessage(cb), onClose: (cb) => raw.onClose(cb),
  };
  const c = new HollowClient({ transport, psk: PSK, keyId: 1 });
  await c.handshake();
  carriers++;
  carrierBorn = Date.now();
  log({ action: "carrier_open", carriers });
  return c;
}

async function echoOnce(size) {
  const s = client.openStream({ host: "tcpbin.com", port: 4242, schemeHint: 0, gatePolicy: 0 });
  streams++;
  const gate = await s.opened;
  const data = crypto.randomBytes(size);
  let got = Buffer.alloc(0);
  const done = new Promise((res) => {
    s.onData = (d) => { got = Buffer.concat([got, d]); if (got.length >= size) res(true); };
    s.onEnd = () => res(false); s.onReset = () => res(false); s.onFail = () => res(false);
  });
  s.write(data);
  const ok = await Promise.race([done, new Promise((r) => setTimeout(() => r(false), 30000))]);
  // tcpbin drops a small tail when it closes (~15 s lifetime, proven by raw
  // controls): success = Hollow delivered everything the peer returned, in
  // order, as a prefix of what we sent.
  const prefixOk = got.length > 0 && Buffer.from(data.subarray(0, got.length)).equals(got);
  const full = got.length === size;
  bytesMoved += got.length;
  if (!prefixOk) failures++;
  log({ action: "echo", size, received: got.length, full, prefix_ok: prefixOk, gate });
  try { s.reset(); } catch { /* ignore */ }
  return prefixOk;
}

const deadline = t0 + MINUTES * 60 * 1000;
let iter = 0;
client = await newCarrier();
while (Date.now() < deadline) {
  iter++;
  try {
    if (Date.now() - carrierBorn > 15 * 60 * 1000) { // §5.6 carrier rotation
      try { client.close(); } catch { /* ignore */ }
      client = await newCarrier();
    }
    const big = iter % 15 === 0;
    await echoOnce(big ? 65536 + Math.floor(Math.random() * 65536) : 1024 + Math.floor(Math.random() * 7168));
  } catch (e) {
    failures++;
    log({ action: "iter_error", error: String(e && e.message || e) });
    try { client = await newCarrier(); } catch { /* next loop retries */ }
  }
  const waitMs = 15000 + Math.random() * 10000;
  if (Date.now() + waitMs < deadline) await new Promise((r) => setTimeout(r, waitMs));
}
try { client.close(); } catch { /* ignore */ }
log({ action: "soak_end", carriers, streams, bytesMoved, failures });
console.log(JSON.stringify({ carriers, streams, bytesMoved, failures }));
