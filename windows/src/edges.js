// Edge-IP selection (plan §5, M2-4 / NP-1114-11): curated Cloudflare anycast
// candidates, refreshable from the Worker's own /edges.json; per-candidate
// landing identification through /meta and handshake-RTT measurement
// (3 probes, median). Presentation rule (plan §5): a candidate is labelled
// by its measured landing — "落地 colo 所在国" — never a promised country.
import https from "node:https";
import { HollowClient } from "../vendor/shared/client-core.js";
import { connectWs } from "../vendor/cli/src/ws-client.js";

// Keep in sync with worker/src/entry.js EDGES (the server copy is what
// /edges.json serves for refresh; this is the shipped fallback).
export const BUILTIN_EDGES = [
  { ip: "104.16.85.20", note: "Cloudflare anycast (104.16/16)" },
  { ip: "104.17.164.30", note: "Cloudflare anycast (104.17/16)" },
  { ip: "104.18.12.149", note: "Cloudflare anycast (104.18/16)" },
  { ip: "104.19.152.10", note: "Cloudflare anycast (104.19/16)" },
  { ip: "104.20.24.10", note: "Cloudflare anycast (104.20/16)" },
  { ip: "104.21.56.100", note: "Cloudflare anycast (104.21/16)" },
  { ip: "104.22.10.10", note: "Cloudflare anycast (104.22/16)" },
  { ip: "172.64.80.100", note: "Cloudflare anycast (172.64/16)" },
  { ip: "172.67.74.152", note: "Cloudflare anycast (172.67/16)" },
  { ip: "104.24.10.20", note: "Cloudflare anycast (104.24/16)" },
];

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
export function parseEdgesJson(text) {
  const obj = JSON.parse(text);
  if (!obj || !Array.isArray(obj.edges)) throw new Error("edges payload malformed");
  const out = [];
  for (const e of obj.edges.slice(0, 64)) {
    // v2 payload: bare IP strings (NP-1114-15 dropped the note field).
    const ip = typeof e === "string" ? e : e?.ip;
    if (ip && IPV4.test(ip)) out.push({ ip, note: typeof e === "object" && e ? String(e.note || "").slice(0, 80) : "" });
  }
  if (!out.length) throw new Error("edges payload empty");
  return out;
}
export function httpBaseOf(workerUrl) {
  const u = new URL(workerUrl);
  return `https://${u.host}`;
}
export const median = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
};

// GET the meta endpoint, optionally through a chosen edge IP (SNI/Host stay
// on the host). The path is deployment-specific (NP-1114-15) and arrives via
// the pairing/config channel — there is intentionally no default.
export function fetchMeta(workerUrl, { edgeIp = null, timeoutMs = 8000, path = null } = {}) {
  if (!path) return Promise.reject(new Error("meta path not configured (pairing/config channel)"));
  return new Promise((resolve, reject) => {
    const u = new URL(workerUrl);
    const req = https.request({
      hostname: edgeIp || u.hostname,
      servername: u.hostname,
      port: u.port || 443,
      path,
      headers: edgeIp ? { Host: u.host } : {},
      timeout: timeoutMs,
    }, (res) => {
      let body = "";
      res.on("data", (d) => { body += d; });
      res.on("end", () => {
        try { resolve(JSON.parse(body)); } catch { reject(new Error("/meta: bad JSON")); }
      });
    });
    req.on("timeout", () => req.destroy(new Error("/meta timeout")));
    req.on("error", reject);
    req.end();
  });
}
export function fetchRemoteEdges(workerUrl, { timeoutMs = 8000, path = null } = {}) {
  if (!path) return Promise.reject(new Error("edges path not configured (pairing/config channel)"));
  return new Promise((resolve, reject) => {
    const u = new URL(workerUrl);
    const req = https.request({ hostname: u.hostname, port: u.port || 443, path, timeout: timeoutMs }, (res) => {
      let body = "";
      res.on("data", (d) => { body += d; });
      res.on("end", () => { try { resolve(parseEdgesJson(body)); } catch (e) { reject(e); } });
    });
    req.on("timeout", () => req.destroy(new Error("/edges.json timeout")));
    req.on("error", reject);
    req.end();
  });
}

async function handshakeOnce(workerUrl, psk, keyId, edgeIp) {
  const t0 = Date.now();
  const transport = await connectWs(workerUrl, { userAgent: "HollowClient/0.1", edgeIp });
  const client = new HollowClient({ transport, psk, keyId });
  try {
    await client.handshake();
    return Date.now() - t0;
  } finally {
    try { client.close(); } catch { /* ignore */ }
  }
}

// Measure every candidate: 3 handshakes (median RTT) + one /meta landing.
// Failures are recorded per candidate (fail-open at selection time, never
// thrown as a whole). Deps injectable for tests.
export async function measureEdges({ workerUrl, psk, keyId = 1, edges, probe = handshakeOnce, meta = fetchMeta, metaPath = null, onProgress = null }) {
  const results = {};
  for (const { ip } of edges) {
    const samples = [];
    let error = null;
    for (let i = 0; i < 3; i++) {
      try { samples.push(await probe(workerUrl, psk, keyId, ip)); }
      catch (e) { error = e.message; break; }
    }
    let landing = null;
    if (samples.length === 3) {
      // fetchMeta itself rejects when no path is configured — landing then
      // stays unknown (fail-open), exactly like an unreachable endpoint.
      try { landing = await meta(workerUrl, { edgeIp: ip, path: metaPath }); } catch { /* landing unknown */ }
    }
    results[ip] = {
      ok: samples.length === 3,
      medianMs: samples.length === 3 ? median(samples) : null,
      colo: landing?.colo || null,
      country: landing?.country || null,
      error: samples.length === 3 ? null : (error || "probe failed"),
      at: new Date().toISOString(),
    };
    if (onProgress) onProgress(ip, results[ip]);
  }
  return results;
}
export function bestEdge(results) {
  let best = null;
  for (const [ip, r] of Object.entries(results || {})) {
    if (r.ok && (best === null || r.medianMs < results[best].medianMs)) best = ip;
  }
  return best;
}
