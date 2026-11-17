// Edges + PAC tests (M2-4, NP-1114-11).
import { test as _test } from "node:test";
const test = (name, fn) => _test(name, { timeout: 15000 }, fn);
import assert from "node:assert/strict";
import { parseEdgesJson, httpBaseOf, median, measureEdges, bestEdge, rankedEdges, BUILTIN_EDGES } from "../src/edges.js";
import { buildPac, startPacServer } from "../src/pac.js";

test("parseEdgesJson validates shape and caps entries", () => {
  const list = parseEdgesJson(JSON.stringify({ version: 1, edges: [{ ip: "104.16.0.1", note: "x" }, { ip: "not-an-ip" }, { ip: "1.2.3.4" }] }));
  assert.deepEqual(list.map((e) => e.ip), ["104.16.0.1", "1.2.3.4"]);
  assert.throws(() => parseEdgesJson("{}"), /malformed/);
  assert.throws(() => parseEdgesJson(JSON.stringify({ edges: [] })), /empty/);
  assert.ok(BUILTIN_EDGES.length >= 8);
});

test("parseEdgesJson accepts the v2 IP-only payload (NP-1114-15)", () => {
  const list = parseEdgesJson(JSON.stringify({ version: 2, edges: ["104.16.0.1", "bad-ip", "172.67.0.9"] }));
  assert.deepEqual(list.map((e) => e.ip), ["104.16.0.1", "172.67.0.9"]);
  assert.equal(list[0].note, "");
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

test("rankedEdges: ok-only, on-list only, RTT ascending (NP-1117-27)", () => {
  const list = [{ ip: "1.1.1.1" }, { ip: "2.2.2.2" }, { ip: "3.3.3.3" }];
  const results = {
    "1.1.1.1": { ok: true, medianMs: 30 },
    "2.2.2.2": { ok: true, medianMs: 10 },
    "3.3.3.3": { ok: false, medianMs: null },
    "9.9.9.9": { ok: true, medianMs: 1 }, // measured but no longer listed
  };
  assert.deepEqual(rankedEdges(results, list), [
    { ip: "2.2.2.2", rttMs: 10 },
    { ip: "1.1.1.1", rttMs: 30 },
  ]);
  assert.deepEqual(rankedEdges({}, list), []);
  assert.deepEqual(rankedEdges(null, list), []);
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

test("PAC server with pathSeg (H-15-01): seg path serves, bare path 404s", async () => {
  const srv = await startPacServer({ getPac: () => buildPac({ socksPort: 1080, directHosts: [] }), preferredPort: 18290, pathSeg: "ab12cd34ef56", log: () => {} });
  try {
    assert.ok(srv.url.endsWith("/ab12cd34ef56/proxy.pac"));
    const res = await fetch(srv.url);
    assert.equal(res.status, 200);
    const bare = await fetch(`http://127.0.0.1:${srv.port}/proxy.pac`);
    assert.equal(bare.status, 404);
  } finally { await srv.close(); }
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

// ---- NP-1117-19: PAC hardening (port validation, isInNet guard, provider) ----
import { makePacProvider, DIRECT_ONLY_PAC } from "../src/pac.js";

test("port validation (NP-1117-19 a): buildPac throws on polluted ports, coerces numeric strings", () => {
  for (const bad of [null, undefined, "abc", "", 0, -1, 65536, 1.5, NaN]) {
    assert.throws(() => buildPac({ socksPort: bad }), /invalid socksPort/, `port ${String(bad)}`);
  }
  const pac = buildPac({ socksPort: "1081" });
  assert.match(pac, /SOCKS5 127\.0\.0\.1:1081/);
  assert.ok(!/null|undefined/.test(pac.split("\n").filter((l) => l.includes("SOCKS5")).join("")), "no polluted endpoint string");
});

test("isInNet literal guard (NP-1117-19 c): hostnames never enter the DNS-resolving net check", () => {
  const pac = buildPac({ socksPort: 1081, directHosts: ["example.com"] });
  let inNetCalls = 0;
  const find = new Function("isPlainHostName", "isInNet", "dnsDomainIs", pac + "\nreturn FindProxyForURL;")(
    (h) => !h.includes("."),
    (h, net, mask) => {
      inNetCalls++;
      const p = (s) => s.split(".").map(Number);
      const [a, m, n] = [p(h), p(mask), p(net)];
      return a.every((o, i) => (o & m[i]) === (n[i] & m[i]));
    },
    (h, d) => h.endsWith(d),
  );
  // Private IP literals still go DIRECT through the guarded block.
  assert.equal(find("http://192.168.1.5/", "192.168.1.5"), "DIRECT");
  assert.ok(inNetCalls > 0);
  assert.equal(find("http://10.1.2.3/", "10.1.2.3"), "DIRECT");
  // A public hostname: the net check is never consulted (no DNS-driven DIRECT).
  inNetCalls = 0;
  assert.equal(find("https://x.com/", "x.com"), "SOCKS5 127.0.0.1:1081");
  assert.equal(inNetCalls, 0);
  // A public IP literal IS checked and correctly not matched.
  assert.equal(find("https://8.8.8.8/", "8.8.8.8"), "SOCKS5 127.0.0.1:1081");
  assert.ok(inNetCalls > 0);
  // The direct-list string rules are untouched (and also skip isInNet).
  inNetCalls = 0;
  assert.equal(find("http://foo.example.com/", "foo.example.com"), "DIRECT");
  assert.equal(inNetCalls, 0);
});

test("pac provider (NP-1117-19 b): last-good cache, DIRECT-only without cache, never a guessed port", () => {
  let port = 1081;
  const logs = [];
  const prov = makePacProvider({ getPort: () => port, getDirectHosts: () => [], log: (m) => logs.push(m) });
  const good = prov.getPac();
  assert.match(good, /SOCKS5 127\.0\.0\.1:1081/);
  port = null; // bridge port unknown
  assert.equal(prov.getPac(), good); // last good, byte-identical
  port = "abc"; // polluted — treated as unknown, not baked into a string
  assert.equal(prov.getPac(), good);
  const fresh = makePacProvider({ getPort: () => null, log: (m) => logs.push(m) });
  const direct = fresh.getPac();
  assert.equal(direct, DIRECT_ONLY_PAC);
  assert.ok(!direct.includes("SOCKS5"));
  const find = new Function(direct + "\nreturn FindProxyForURL;")();
  assert.equal(find("https://anything.example/", "anything.example"), "DIRECT");
  assert.ok(logs.some((l) => l.includes("DIRECT-only")), "fallback is logged");
});
