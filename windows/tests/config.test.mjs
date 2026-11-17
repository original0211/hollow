// Config resilience tests (M2-5 hardening): corrupt/absent config handling
// and atomic persistence. Isolation via HOLLOW_HOME (read per call).
import { test as _test } from "node:test";
const test = (name, fn) => _test(name, { timeout: 15000 }, fn);
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadConfig, saveConfig, writePsk, loadPsk } from "../src/config.js";

function freshHome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hollow-cfg-"));
  process.env.HOLLOW_HOME = dir;
  return dir;
}

test("missing config -> defaults; partial config merges over defaults", () => {
  const dir = freshHome();
  const d = loadConfig();
  assert.equal(d.proxyMode, "off");
  assert.equal(d.keyId, 1);
  fs.writeFileSync(path.join(dir, "config.json"), JSON.stringify({ proxyMode: "pac", directHosts: ["a.example"] }));
  const m = loadConfig();
  assert.equal(m.proxyMode, "pac");
  assert.deepEqual(m.directHosts, ["a.example"]);
  assert.equal(m.socksPort, 1080); // default preserved
});

test("corrupt config.json -> defaults, no throw (app keeps running)", () => {
  const dir = freshHome();
  fs.writeFileSync(path.join(dir, "config.json"), "{not json!!");
  const c = loadConfig();
  assert.equal(c.workerUrl, "wss://hollow.example.workers.dev/");
});

test("saveConfig is atomic: roundtrip exact, no tmp residue", () => {
  const dir = freshHome();
  const cfg = { ...loadConfig(), proxyMode: "global", edgeResults: { "1.2.3.4": { ok: true, medianMs: 42 } } };
  saveConfig(cfg);
  assert.deepEqual(loadConfig(), cfg);
  const leftovers = fs.readdirSync(dir).filter((f) => f.includes(".tmp-"));
  assert.deepEqual(leftovers, []);
});

test("writePsk is atomic: roundtrip exact, no tmp residue", () => {
  const dir = freshHome();
  const psk = new Uint8Array(32).fill(7);
  writePsk(psk);
  assert.deepEqual([...loadPsk()], [...psk]);
  assert.deepEqual(fs.readdirSync(dir).filter((f) => f.includes(".tmp-")), []);
});

test("loadConfig port coercion (NP-1117-19 a): polluted ports fall back, numeric strings coerce", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hollow-cfg-polluted-"));
  const prev = process.env.HOLLOW_HOME;
  process.env.HOLLOW_HOME = dir;
  try {
    fs.writeFileSync(path.join(dir, "config.json"), JSON.stringify({ socksPort: null, pacPort: "junk" }));
    let c = loadConfig();
    assert.equal(c.socksPort, 1080);
    assert.equal(c.pacPort, 18080);
    fs.writeFileSync(path.join(dir, "config.json"), JSON.stringify({ socksPort: "2443", pacPort: 65536 }));
    c = loadConfig();
    assert.equal(c.socksPort, 2443);
    assert.equal(c.pacPort, 18080);
  } finally {
    if (prev === undefined) delete process.env.HOLLOW_HOME; else process.env.HOLLOW_HOME = prev;
  }
});
