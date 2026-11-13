// PAC sub-mode (plan §2 PAC segment, M2-4 / NP-1114-11): a loopback-only
// HTTP endpoint serves the PAC file; the system proxy points AutoConfigURL
// at it (sysproxy PAC form). Rules: loopback + private ranges + the user's
// direct list go DIRECT; everything else goes through the app's SOCKS port.
import http from "node:http";

// Pure builder (unit-tested). directHosts entries match the host itself and
// any subdomain ("example.com" covers www.example.com).
export function buildPac({ socksPort, directHosts = [] }) {
  const hosts = [...new Set(directHosts.map((h) => String(h).trim().toLowerCase()).filter(Boolean))];
  const hostRules = hosts.map((h) =>
    `  if (host === ${JSON.stringify(h)} || dnsDomainIs(host, ${JSON.stringify("." + h)})) return "DIRECT";`
  ).join("\n");
  return `// Hollow PAC (generated; edit the direct list in the app, not here)
function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  if (isPlainHostName(host) || host === "localhost") return "DIRECT";
  if (isInNet(host, "127.0.0.0", "255.0.0.0")) return "DIRECT";
  if (isInNet(host, "10.0.0.0", "255.0.0.0")) return "DIRECT";
  if (isInNet(host, "172.16.0.0", "255.240.0.0")) return "DIRECT";
  if (isInNet(host, "192.168.0.0", "255.255.0.0")) return "DIRECT";
  if (isInNet(host, "169.254.0.0", "255.255.0.0")) return "DIRECT";
${hostRules}
  return "SOCKS5 127.0.0.1:${socksPort}";
}
`;
}

// Loopback PAC server. getPac() is consulted per request so port/list edits
// take effect without a restart. Port increments like the SOCKS listener.
export async function startPacServer({ getPac, preferredPort = 18080, log = () => {} }) {
  let lastErr = null;
  for (let port = preferredPort; port < preferredPort + 20; port++) {
    const server = http.createServer((req, res) => {
      if (req.url === "/proxy.pac") {
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
        url: `http://127.0.0.1:${port}/proxy.pac`,
        close: () => new Promise((res) => { try { server.close(() => res()); } catch { res(); } }),
      };
    } catch (e) {
      lastErr = e;
      if (e.code !== "EADDRINUSE") throw e;
    }
  }
  throw lastErr || new Error("no PAC port available");
}
