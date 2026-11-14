// Hollow Worker entry (bundled into worker/src/index.js by tools/build-worker.mjs
// together with shared/crypto.js, shared/protocol.js, shared/server-core.js).
// Cloudflare script name: injected at deploy time from out-of-repo
// config and never recorded in this repo (NP-1114-47).
import { connect } from "cloudflare:sockets";

// §2-4: unauthenticated, non-Upgrade requests get exactly this fixed page:
// no protocol information, no outbound action. Changing these bytes changes
// the unauthenticated response surface and must be logged per spec §10.
const STATIC_PAGE = "<!doctype html><html><head><title>ok</title></head><body><p>ok</p></body></html>\n";

// NP-1114-11 added read-only meta + edges endpoints; the M2 red-team sweep
// (NP-1114-15) tightened that disposition into its final form: both
// endpoints live at unguessable paths carrying a deployment-random segment
// held in the META_SEG secret (never in this repo), the edges payload is
// IPs only, and every other non-Upgrade path still gets exactly the static
// page — the formal tightening of the frozen §2-4 surface. Clients learn
// the paths through the pairing/config channel.
const EDGES = [
  "104.16.85.20", "104.17.164.30", "104.18.12.149", "104.19.152.10",
  "104.20.24.10", "104.21.56.100", "104.22.10.10", "104.24.10.20",
  "172.64.80.100", "172.67.74.152",
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
    const seg = env.META_SEG || null; // NP-1114-15: unguessable-path segment
    if (seg && request.method === "GET" && reqUrl.pathname === `/${seg}/meta`) {
      const cf = request.cf || {};
      return Response.json({ colo: cf.colo || null, country: cf.country || null });
    }
    if (seg && request.method === "GET" && reqUrl.pathname === `/${seg}/edges.json`) {
      return Response.json({ version: 2, edges: EDGES });
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
