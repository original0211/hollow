// Edges + PAC tests (M2-4, NP-1114-11).
import { test as _test } from "node:test";
const test = (name, fn) => _test(name, { timeout: 15000 }, fn);
import assert from "node:assert/strict";
import { parseEdgesJson, httpBaseOf, median, measureEdges, bestEdge, BUILTIN_EDGES } from "../src/edges.js";
import { buildPac, startPacServer } from "../src/pac.js";

test("parseEdgesJson validates shape and caps entries", () => {
  const list = parseEdgesJson(JSON.stringify({ version: 1, edges: [{ ip: "104.16.0.1", note: "x" }, { ip: "not-an-ip" }, { ip: "1.2.3.4" }] }));
  assert.deepEqual(list.map((e) => e.ip), ["104.16.0.1", "1.2.3.4"]);
  assert.throws(() => parseEdgesJson("{}"), /malformed/);
  assert.throws(() => parseEdgesJson(JSON.stringify({ edges: [] })), /empty/);
  assert.ok(BUILTIN_EDGES.length >= 8);
});

test("httpBaseOf + median", () => {
  assert.equal(httpBaseOf("wss://example.workers.dev/some/path"), "https://example.workers.dev");
  assert.equal(median([9, 1, 5]), 5);
  assert.equal(median([10, 30, 20, 40]), 30); // upper median for even counts
});

test("measureEdges: median of 3, landing attached, failures recorded (fail-open)", async () => {
  const probes = { "1.1.1.1": [100, 300, 200], "2.2.2.2": [50, 60, 55] };
  const results = await measureEdges({
    workerUrl: "wss://x.example/", psk: new Uint8Array(32), edges: [{ ip: "1.1.1.1" }, { ip: "2.2.2.2" }, { ip: "3.3.3.3" }],
    probe: async (_u, _p, _k, ip) => {
      const seq = probes[ip];
      if (!seq) throw new Error("boom");
      return seq.shift();
    },
    meta: async () => ({ colo: "FRA", country: "DE" }),
  });
  assert.equal(results["1.1.1.1"].medianMs, 200);
  assert.equal(results["1.1.1.1"].colo, "FRA");
  assert.equal(results["2.2.2.2"].ok, true);
  assert.equal(results["3.3.3.3"].ok, false);
  assert.match(results["3.3.3.3"].error, /boom/);
  assert.equal(bestEdge(results), "2.2.2.2");
  assert.equal(bestEdge({}), null);
});

test("buildPac: private/localhost/user hosts DIRECT, rest via SOCKS5 port", () => {
  const pac = buildPac({ socksPort: 1081, directHosts: ["Example.COM", "internal.lan"] });
  assert.match(pac, /SOCKS5 127\.0\.0\.1:1081/);
  assert.match(pac, /isPlainHostName/);
  for (const net of ["10.0.0.0", "172.16.0.0", "192.168.0.0", "127.0.0.0"]) assert.ok(pac.includes(net), net);
  assert.ok(pac.includes('"example.com"') && pac.includes('".example.com"'), "user host normalized + subdomain rule");
  assert.ok(pac.includes('"internal.lan"'));
  // The generated PAC must actually evaluate: run it in a vm-like harness.
  const find = new Function("isPlainHostName", "isInNet", "dnsDomainIs", pac + "\nreturn FindProxyForURL;")(
    (h) => !h.includes("."),
    (h, net, mask) => {
      const p = (s) => s.split(".").map(Number);
      const [a, m, n] = [p(h), p(mask), p(net)];
      return a.every((o, i) => (o & m[i]) === (n[i] & m[i]));
    },
    (h, d) => h.endsWith(d),
  );
  assert.equal(find("http://192.168.1.5/", "192.168.1.5"), "DIRECT");
  assert.equal(find("http://foo.example.com/", "foo.example.com"), "DIRECT");
  assert.equal(find("http://example.com/", "example.com"), "DIRECT");
  assert.equal(find("http://printer/", "printer"), "DIRECT");
  assert.equal(find("https://news.site/", "news.site"), "SOCKS5 127.0.0.1:1081");
});

test("PAC server: serves on loopback with the PAC content type, 404 elsewhere", async () => {
  const srv = await startPacServer({ getPac: () => buildPac({ socksPort: 1080, directHosts: [] }), preferredPort: 18280, log: () => {} });
  try {
    const res = await fetch(srv.url);
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type"), /proxy-autoconfig/);
    assert.match(await res.text(), /FindProxyForURL/);
    const other = await fetch(`http://127.0.0.1:${srv.port}/nope`);
    assert.equal(other.status, 404);
  } finally { await srv.close(); }
});
