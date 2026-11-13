import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { classifyNetcfgBackup, restorableRoutes } from "../src/netcfg-backup.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixtureText = fs.readFileSync(path.join(here, "fixtures", "netcfg-backup.json"), "utf8");

// RF-21-02: the SAME fixture the Go side asserts field-by-field
// (tun-helper/internal/netcfg/fixture_test.go). If either side's format
// understanding drifts, one of the two suites goes red.
test("cross-language fixture: classifies ok, every field as pinned", () => {
  const { kind, snapshot, problems } = classifyNetcfgBackup(fixtureText);
  assert.equal(kind, "ok", JSON.stringify(problems));
  assert.equal(snapshot.version, 1);
  assert.equal(snapshot.takenAt, "2026-11-14T00:00:00Z");
  assert.equal(snapshot.original.defaultGateway, "192.168.1.1");
  assert.equal(snapshot.written.defaultGateway, "192.168.1.1");
  assert.deepEqual(snapshot.original.physicalDns, { "Wi-Fi": ["192.168.1.1"] });
  assert.deepEqual(snapshot.written.adapter, {
    name: "Hollow", ipv4: "10.99.0.1/24", ipv6: "fd00::1/64", dns: ["10.99.0.1"],
  });
  assert.deepEqual(snapshot.original.addedRoutes, []);
  assert.deepEqual(
    snapshot.written.addedRoutes.map((r) => `${r.dest}|${r.gateway}|${r.interface ?? ""}`),
    [
      "203.0.113.7/32|192.168.1.1|",
      "0.0.0.0/1|10.99.0.1|Hollow",
      "128.0.0.0/1|10.99.0.1|Hollow",
      "::/1|fd00::1|Hollow",
      "8000::/1|fd00::1|Hollow",
    ],
  );
  assert.equal(restorableRoutes(snapshot).length, 5);
});

test("netcfg backup: absent is none; each structural defect is corrupt", () => {
  assert.equal(classifyNetcfgBackup(null).kind, "none");
  assert.equal(classifyNetcfgBackup("{nope").kind, "corrupt");
  const good = JSON.parse(fixtureText);
  const variants = {
    "wrong version": (s) => { s.version = 99; },
    "missing takenAt": (s) => { s.takenAt = ""; },
    "original adapter name": (s) => { s.original.adapter.name = ""; },
    "written gateway": (s) => { s.written.defaultGateway = ""; },
    "written routes null": (s) => { s.written.addedRoutes = null; },
    "route missing gateway": (s) => { delete s.written.addedRoutes[0].gateway; },
  };
  for (const [name, mutate] of Object.entries(variants)) {
    const s = structuredClone(good);
    mutate(s);
    assert.equal(classifyNetcfgBackup(JSON.stringify(s)).kind, "corrupt", name);
  }
});
