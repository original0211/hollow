// PAC sub-mode (plan §2 PAC segment, M2-4 / NP-1114-11): a loopback-only
// HTTP endpoint serves the PAC file; the system proxy points AutoConfigURL
// at it (sysproxy PAC form). Rules: loopback + private ranges + the user's
// direct list go DIRECT; everything else goes through the app's SOCKS port.
import http from "node:http";
import { assertPort, validPort } from "./config.js";

// Pure builder (unit-tested). directHosts entries match the host itself and
// any subdomain ("example.com" covers www.example.com).
export function buildPac({ socksPort, directHosts = [] }) {
  // NP-1117-19 (item 1): validate at the door — never emit a malformed
  // endpoint string ("SOCKS5 127.0.0.1:null" was the audit repro).
  const port = assertPort(socksPort, "socksPort");
  const hosts = [...new Set(directHosts.map((h) => String(h).trim().toLowerCase()).filter(Boolean))];
  const hostRules = hosts.map((h) =>
    `  if (host === ${JSON.stringify(h)} || dnsDomainIs(host, ${JSON.stringify("." + h)})) return "DIRECT";`
  ).join("\n");
  return `// Hollow PAC (generated; edit the direct list in the app, not here)
function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  if (isPlainHostName(host) || host === "localhost") return "DIRECT";
  // NP-1117-19 (item 3): the net-range checks run ONLY for IPv4
  // literals. Calling isInNet on a hostname makes the PAC engine
  // resolve it through DNS to decide DIRECT — a name whose answer
  // lands in a private range would silently bypass the tunnel (and
  // the resolution itself leaks). Hostnames are decided by the pure
  // string rules below, never by DNS.
  if (/^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$/.test(host)) {
    if (isInNet(host, "127.0.0.0", "255.0.0.0")) return "DIRECT";
    if (isInNet(host, "10.0.0.0", "255.0.0.0")) return "DIRECT";
    if (isInNet(host, "172.16.0.0", "255.240.0.0")) return "DIRECT";
    if (isInNet(host, "192.168.0.0", "255.255.0.0")) return "DIRECT";
    if (isInNet(host, "169.254.0.0", "255.255.0.0")) return "DIRECT";
  }
${hostRules}
  return "SOCKS5 127.0.0.1:${port}";
}
`;
}

// NP-1117-19 (item 2): the safe fallback when the bridge's SOCKS port
// is unknown and no good PAC has ever been built — everything DIRECT,
// never a guessed port.
export const DIRECT_ONLY_PAC = `// Hollow PAC (fallback: bridge port unknown — everything direct)
function FindProxyForURL(url, host) {
  return "DIRECT";
}
`;

// NP-1117-19 (item 2): PAC provider with a last-good cache. While the
// bridge port is known, every call rebuilds (port/list edits apply
// live) and refreshes the cache. When the port is unknown (bridge
// down / not yet bound / polluted), serve the cache; with no cache,
// serve DIRECT_ONLY_PAC. The port is NEVER guessed from config.
// State transitions are logged once, not per request.
export function makePacProvider({ getPort, getDirectHosts = () => [], log = () => {} }) {
  let lastGood = null;
  let mode = null; // "good" | "stale" | "direct"
  const setMode = (m, msg) => { if (mode !== m) { mode = m; if (msg) log(msg); } };
  return {
    getPac() {
      const p = validPort(getPort());
      if (p !== null) {
        lastGood = buildPac({ socksPort: p, directHosts: getDirectHosts() || [] });
        setMode("good");
        return lastGood;
      }
      if (lastGood) {
        setMode("stale", "pac: bridge socks port unknown — serving the last good PAC");
        return lastGood;
      }
      setMode("direct", "pac: bridge socks port unknown and no cached PAC — serving a DIRECT-only PAC");
      return DIRECT_ONLY_PAC;
    },
    get lastGood() { return lastGood; },
  };
}

// Loopback PAC server. getPac() is consulted per request so port/list edits
// take effect without a restart. Port increments like the SOCKS listener.
// pathSeg (H-15-01): when set, the PAC lives at /<seg>/proxy.pac and the
// bare /proxy.pac path 404s — the written AutoConfigURL becomes
// installation-specific instead of a generic fingerprint.
export async function startPacServer({ getPac, preferredPort = 18080, log = () => {}, pathSeg = null }) {
  const pacPath = pathSeg ? `/${pathSeg}/proxy.pac` : "/proxy.pac";
  let lastErr = null;
  for (let port = preferredPort; port < preferredPort + 20; port++) {
    const server = http.createServer((req, res) => {
      if (req.url === pacPath) {
        res.writeHead(200, { "content-type": "application/x-ns-proxy-autoconfig" });
        res.end(getPac());
      } else {
        res.writeHead(404); res.end();
      }
    });
    try {
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, "127.0.0.1", resolve);
      });
      log(`pac server on 127.0.0.1:${port}`);
      return {
        port,
        url: `http://127.0.0.1:${port}${pacPath}`,
        close: () => new Promise((res) => { try { server.close(() => res()); } catch { res(); } }),
      };
    } catch (e) {
      lastErr = e;
      if (e.code !== "EADDRINUSE") throw e;
    }
  }
  throw lastErr || new Error("no PAC port available");
}
