// Hollow Worker entry (bundled into worker/src/index.js by tools/build-worker.mjs
// together with shared/crypto.js, shared/protocol.js, shared/server-core.js).
// Cloudflare script name: newproto-hollow (newproto- prefix = infrastructure
// naming, unchanged by the Hollow product name, spec §10.4).
import { connect } from "cloudflare:sockets";

// §2-4: unauthenticated, non-Upgrade requests get exactly this fixed page:
// no protocol information, no outbound action. Changing these bytes changes
// the unauthenticated response surface and must be logged per spec §10.
const STATIC_PAGE = "<!doctype html><html><head><title>ok</title></head><body><p>ok</p></body></html>\n";

// NP-1114-11 (M2-4) deliberate exceptions to the static-page surface, kept
// minimal and read-only, flagged for the M2-5 red-team sweep of server
// changes: /meta echoes the request's own landing (colo/country) for the
// client's edge-IP identification; /edges.json serves the curated candidate
// list so shipped clients can refresh it without an app update.
const EDGES = [
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

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function cfTransport(serverWs) {
  let msgCb = null, closeCb = null;
  serverWs.accept();
  serverWs.addEventListener("message", (ev) => {
    if (!msgCb) return;
    const d = ev.data;
    msgCb(d instanceof ArrayBuffer ? new Uint8Array(d) : new Uint8Array(d));
  });
  serverWs.addEventListener("close", () => { if (closeCb) closeCb(); });
  serverWs.addEventListener("error", () => { if (closeCb) closeCb(); });
  return {
    send(b) { try { serverWs.send(b); } catch {} },
    close() { try { serverWs.close(1000); } catch {} },
    closeCarrier() { try { serverWs.close(1000); } catch {} }, // §8.1: code 1000, no reason
    onMessage(cb) { msgCb = cb; },
    onClose(cb) { closeCb = cb; },
  };
}

export default {
  async fetch(request, env) {
    const reqUrl = new URL(request.url);
    if (request.method === "GET" && reqUrl.pathname === "/meta") {
      const cf = request.cf || {};
      return Response.json({ colo: cf.colo || null, country: cf.country || null });
    }
    if (request.method === "GET" && reqUrl.pathname === "/edges.json") {
      return Response.json({ version: 1, edges: EDGES });
    }
    if ((request.headers.get("Upgrade") || "").toLowerCase() !== "websocket") {
      return new Response(STATIC_PAGE, {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }
    const verifiers = new Map();
    if (env.PSK_V_HEX) verifiers.set(1, hexToBytes(env.PSK_V_HEX));
    if (env.PSK_V_HEX_2) verifiers.set(2, hexToBytes(env.PSK_V_HEX_2));
    const host = new URL(request.url).host;
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    const transport = cfTransport(server);
    new HollowServer({
      transport,
      verifiers,
      ownHost: host,
      zoneSuffix: host.split(".").slice(1).join("."),
      connectFn: async ({ hostname, port }) => connect({ hostname, port }),
      fetchFn: (url, init) => fetch(url, init),
    });
    return new Response(null, { status: 101, webSocket: client });
  },
};
