// CPU gates G1/G2/G4 (spec §9.1) with per-invocation evidence from the
// Workers Tail API (each WS session is one invocation; tail reports its
// cpuTime). G1: handshake-only invocations. G2: invocations whose payload
// work is exactly one max-size (16 KiB bucket) record each way — if the
// whole invocation is < 10 ms, the record processing inside it is too.
// G4: well-formed but unauthenticated handshakes (bad PSK).
// Requires env HOLLOW_TAIL_URL (create via the CF API, delete afterwards).
import fs from "node:fs";
import net from "node:net";
import tls from "node:tls";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { HollowClient } from "../../shared/client-core.js";
import { connectWs } from "../../cli/src/ws-client.js";

const WORKER_URL = process.env.HOLLOW_WORKER_URL;
if (!WORKER_URL) throw new Error("HOLLOW_WORKER_URL is not set — the production endpoint is never recorded in this repo (NP-1114-47); supply it out-of-band");
const TAIL = process.env.HOLLOW_TAIL_URL;
const OUT = process.env.HOLLOW_CPU_OUT || "cpu-tail.jsonl";
if (!TAIL) { console.error("HOLLOW_TAIL_URL required"); process.exit(2); }
const PSK = new Uint8Array(fs.readFileSync(path.join(os.homedir(), ".hollow", "psk.bin")));
const BAD_PSK = new Uint8Array(32).fill(7);

// Tail consumer: the sandbox reaches tail.developers.workers.dev only via
// the egress proxy (CONNECT), and the tail endpoint requires the
// Sec-WebSocket-Protocol "trace-v1" subprotocol (else HTTP 406).
function connectTail(urlStr, onJson) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const proxy = new URL(process.env.https_proxy || process.env.HTTPS_PROXY);
    const raw = net.connect(Number(proxy.port), proxy.hostname, () => {
      raw.write(`CONNECT ${u.hostname}:443 HTTP/1.1\r\nHost: ${u.hostname}:443\r\n\r\n`);
    });
    let pre = Buffer.alloc(0);
    raw.on("data", function onData(d) {
      pre = Buffer.concat([pre, d]);
      const s = pre.toString("latin1");
      if (!s.includes("\r\n\r\n")) return;
      if (!/^HTTP\/1\.1 200/.test(s)) { reject(new Error("proxy CONNECT failed: " + s.split("\r\n")[0])); return; }
      raw.off("data", onData);
      const rest = pre.subarray(s.indexOf("\r\n\r\n") + 4);
      const sock = tls.connect({ socket: raw, servername: u.hostname }, () => {
        const key = crypto.randomBytes(16).toString("base64");
        sock.write(`GET ${u.pathname} HTTP/1.1\r\nHost: ${u.hostname}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: trace-v1\r\nUser-Agent: HollowCpuGate/0.1\r\n\r\n`);
      });
      let buf = Buffer.alloc(0);
      let upgraded = false;
      let frags = [];
      sock.on("data", (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        if (!upgraded) {
          const t = buf.toString("latin1");
          if (!t.includes("\r\n\r\n")) return;
          if (!/^HTTP\/1\.1 101/.test(t)) { reject(new Error("tail upgrade failed: " + t.split("\r\n")[0])); return; }
          upgraded = true;
          buf = buf.subarray(t.indexOf("\r\n\r\n") + 4);
          resolve({ close: () => { try { sock.destroy(); } catch {} } });
        }
        for (;;) {
          if (buf.length < 2) return;
          const fin = (buf[0] & 0x80) !== 0;
          const op = buf[0] & 0x0f;
          let len = buf[1] & 0x7f;
          let off = 2;
          if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
          else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
          if (buf.length < off + len) return;
          const payload = buf.subarray(off, off + len);
          buf = buf.subarray(off + len);
          if (op === 0x9) continue; // ping: tail tolerates no-pong briefly; ignore
          if (op === 0x8) return;
          if (op === 0x1 || op === 0x2 || op === 0x0) {
            frags.push(Buffer.from(payload));
            if (fin) {
              const all = Buffer.concat(frags); frags = [];
              try { onJson(JSON.parse(all.toString("utf8"))); } catch { /* ignore */ }
            }
          }
        }
      });
      sock.on("error", reject);
    });
    raw.on("error", reject);
  });
}

const events = [];
fs.writeFileSync(OUT, "");
fs.writeFileSync(OUT + ".marks.jsonl", "");
const tail = await connectTail(TAIL, (arr) => {
  for (const e of Array.isArray(arr) ? arr : [arr]) {
    events.push(e);
    // stream to disk immediately: this VM restarts without notice, and a
    // run that only writes at the end loses everything (happened once).
    try { fs.appendFileSync(OUT, JSON.stringify(e) + "\n"); } catch { /* ignore */ }
  }
});
console.log("tail connected");

async function session(fn) {
  const raw = await connectWs(WORKER_URL);
  const transport = {
    send: (b) => raw.send(b),
    close: () => raw.close(),
    closeCarrier: () => raw.close(),
    onMessage: (cb) => raw.onMessage(cb),
    onClose: (cb) => raw.onClose(cb),
  };
  const client = new HollowClient({ transport, psk: PSK, keyId: 1 });
  try { await fn(client); } finally { try { client.close(); } catch {} raw.close(); }
}

async function pool(n, conc, fn) {
  let i = 0;
  await Promise.all(Array.from({ length: conc }, async () => {
    while (i < n) { const k = i++; await fn(k); }
  }));
}

const marks = [];
function mark(name) {
  const m = { name, at: Date.now(), seen: events.length };
  marks.push(m);
  try { fs.appendFileSync(OUT + ".marks.jsonl", JSON.stringify(m) + "\n"); } catch { /* ignore */ }
  console.log("phase", name);
}

// ---- G1: >=50 handshake-only invocations
mark("g1-start");
await pool(60, 6, async () => { await session(async (c) => { await c.handshake(); }); });
mark("g1-end");

// ---- G2: >=200 invocations each moving one 16,373-byte DATA frame (16 KiB
// bucket) in each direction through a real echo stream
mark("g2-start");
const payload = new Uint8Array(16373);
for (let i = 0; i < payload.length; i++) payload[i] = i & 0xff;
await pool(210, 5, async () => {
  await session(async (c) => {
    await c.handshake();
    const s = c.openStream({ host: "tcpbin.com", port: 4242, schemeHint: 0, gatePolicy: 0 });
    await s.opened;
    let got = 0;
    const done = new Promise((res) => { s.onData = (d) => { got += d.length; if (got >= payload.length) res(); }; s.onEnd = res; s.onReset = res; });
    s.write(payload);
    await Promise.race([done, new Promise((r) => setTimeout(r, 15000))]);
    s.reset();
  });
});
mark("g2-end");

// ---- G4: 50 unauthenticated (bad-PSK) handshakes
mark("g4-start");
await pool(50, 5, async () => {
  const raw = await connectWs(WORKER_URL);
  const transport = {
    send: (b) => raw.send(b), close: () => raw.close(), closeCarrier: () => raw.close(),
    onMessage: (cb) => raw.onMessage(cb), onClose: (cb) => raw.onClose(cb),
  };
  const client = new HollowClient({ transport, psk: BAD_PSK, keyId: 1 });
  await client.handshake().catch(() => {});
  try { client.close(); } catch {}
  raw.close();
});
mark("g4-end");

console.log("waiting 20s for tail flush...");
await new Promise((r) => setTimeout(r, 20000));
tail.close();

console.log(`tail events captured: ${events.length} -> ${OUT} (streamed)`);
const sample = events[0];
console.log("sample event keys:", sample ? Object.keys(sample).join(",") : "none");
console.log("sample cpuTime/wallTime:", sample && sample.cpuTime, sample && sample.wallTime);
