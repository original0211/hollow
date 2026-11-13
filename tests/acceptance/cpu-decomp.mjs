// CPU decomposition harness (NP-1113-11): parametrized phase runner over a
// Tail stream. Phases are "label:kind:count" (kinds: g1 handshake-only,
// g2a one 16,373-byte DATA frame each way waiting for stream end like the
// original G2 run, g2b same payload but fast-close once the echo is
// effectively back). Env: HOLLOW_TARGET_URL, HOLLOW_TAIL_URL, HOLLOW_OUT,
// HOLLOW_CLIENT_CORE (path to client-core.js; defaults to repo shared/),
// HOLLOW_PHASES, HOLLOW_POOL (default 6).
import fs from "node:fs";
import net from "node:net";
import tls from "node:tls";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { connectWs } from "../../cli/src/ws-client.js";

const TARGET = process.env.HOLLOW_TARGET_URL;
const TAIL = process.env.HOLLOW_TAIL_URL;
const OUT = process.env.HOLLOW_OUT;
const PHASES = (process.env.HOLLOW_PHASES || "").split(",").filter(Boolean).map((s) => {
  const [label, kind, n] = s.split(":");
  return { label, kind, n: Number(n) };
});
const POOLN = Number(process.env.HOLLOW_POOL || 6);
if (!TARGET || !TAIL || !OUT || PHASES.length === 0) { console.error("missing env"); process.exit(2); }
const corePath = process.env.HOLLOW_CLIENT_CORE || new URL("../../shared/client-core.js", import.meta.url).pathname;
const { HollowClient } = await import(pathToFileURL(corePath).href);
const PSK = new Uint8Array(fs.readFileSync(path.join(os.homedir(), ".hollow", "psk.bin")));

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
      if (!/^HTTP\/1\.1 200/.test(s)) { reject(new Error("proxy CONNECT failed")); return; }
      raw.off("data", onData);
      const sock = tls.connect({ socket: raw, servername: u.hostname }, () => {
        const key = crypto.randomBytes(16).toString("base64");
        sock.write(`GET ${u.pathname} HTTP/1.1\r\nHost: ${u.hostname}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: trace-v1\r\nUser-Agent: HollowCpuDecomp/0.1\r\n\r\n`);
      });
      let buf = Buffer.alloc(0);
      let upgraded = false;
      let frags = [];
      sock.on("data", (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        if (!upgraded) {
          const t = buf.toString("latin1");
          if (!t.includes("\r\n\r\n")) return;
          if (!/^HTTP\/1\.1 101/.test(t)) { reject(new Error("tail upgrade failed")); return; }
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
          if (op === 0x9 || op === 0x8) continue;
          if (op === 0x1 || op === 0x2 || op === 0x0) {
            frags.push(Buffer.from(payload));
            if (fin) { const all = Buffer.concat(frags); frags = []; try { onJson(JSON.parse(all.toString("utf8"))); } catch { /* ignore */ } }
          }
        }
      });
      sock.on("error", reject);
    });
    raw.on("error", reject);
  });
}

fs.writeFileSync(OUT, "");
fs.writeFileSync(OUT + ".marks.jsonl", "");
let seen = 0;
const tail = await connectTail(TAIL, (arr) => {
  for (const e of Array.isArray(arr) ? arr : [arr]) {
    seen++;
    try { fs.appendFileSync(OUT, JSON.stringify(e) + "\n"); } catch { /* ignore */ }
  }
});
console.log("tail connected");
function mark(name) {
  const m = { name, at: Date.now(), seen };
  try { fs.appendFileSync(OUT + ".marks.jsonl", JSON.stringify(m) + "\n"); } catch { /* ignore */ }
  console.log("phase", name);
}

async function session(fn) {
  const raw = await connectWs(TARGET);
  const transport = {
    send: (b) => raw.send(b), close: () => raw.close(), closeCarrier: () => raw.close(),
    onMessage: (cb) => raw.onMessage(cb), onClose: (cb) => raw.onClose(cb),
  };
  const client = new HollowClient({ transport, psk: PSK, keyId: 1 });
  try { await fn(client); } finally { try { client.close(); } catch {} raw.close(); }
}
async function pool(n, fn) {
  let i = 0;
  await Promise.all(Array.from({ length: POOLN }, async () => { while (i < n) { const k = i++; await fn(k); } }));
}

const payload = new Uint8Array(16373);
for (let i = 0; i < payload.length; i++) payload[i] = i & 0xff;

for (const ph of PHASES) {
  mark(ph.label + "-start");
  if (ph.kind === "g1") {
    await pool(ph.n, async () => { await session(async (c) => { await c.handshake(); }); });
  } else if (ph.kind === "g2a" || ph.kind === "g2b") {
    await pool(ph.n, async () => {
      await session(async (c) => {
        await c.handshake();
        const s = c.openStream({ host: "tcpbin.com", port: 4242, schemeHint: 0, gatePolicy: 0 });
        await s.opened;
        let got = 0; let firstAt = 0;
        const done = new Promise((res) => {
          s.onData = (d) => { got += d.length; if (!firstAt) firstAt = Date.now(); if (got >= payload.length) res(); };
          s.onEnd = res; s.onReset = res; s.onFail = res;
        });
        s.write(payload);
        if (ph.kind === "g2a") {
          await Promise.race([done, new Promise((r) => setTimeout(r, 20000))]);
        } else {
          const t0 = Date.now();
          while (Date.now() - t0 < 6000) {
            if (got >= payload.length * 0.99) break;
            if (firstAt && Date.now() - firstAt > 1500) break;
            await new Promise((r) => setTimeout(r, 50));
          }
        }
        try { s.reset(); } catch { /* ignore */ }
      });
    });
  } else { console.error("unknown kind", ph.kind); process.exit(2); }
  mark(ph.label + "-end");
}
console.log("waiting 20s for tail flush...");
await new Promise((r) => setTimeout(r, 20000));
tail.close();
console.log("events captured:", seen);
