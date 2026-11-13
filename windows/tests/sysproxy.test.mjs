// sysproxy policy tests (M2-2, NP-1114-05): every red-team correction gets a
// test over an in-memory fake registry + a real temp backup dir.
//  R1 iron rule   — an existing backup is never overwritten.
//  R2 robustness  — atomic write; corrupt backup -> degraded no-proxy
//                   restore; post-restore read-back assertion, backup kept on
//                   verification failure.
//  R3 self-heal   — exact-match against the recorded written/original
//                   states; partial state degrades; a foreign local proxy
//                   (user's own tool) is never mistaken for ours.
import { test as _test } from "node:test";
const test = (name, fn) => _test(name, { timeout: 15000 }, fn);
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createSysProxy, parseRegQuery, writtenFor, NO_PROXY, BYPASS } from "../src/sysproxy.js";

function fakeRegistry(initial = {}) {
  const store = new Map(Object.entries({ ProxyEnable: 0, ...initial }));
  return {
    store,
    async get(name) { return store.has(name) ? store.get(name) : null; },
    async set(name, value) { if (value === null) store.delete(name); else store.set(name, value); },
    async refresh() {},
    snapshot() {
      return {
        ProxyEnable: store.get("ProxyEnable") ?? 0,
        ProxyServer: store.get("ProxyServer") ?? null,
        ProxyOverride: store.get("ProxyOverride") ?? null,
        AutoConfigURL: store.get("AutoConfigURL") ?? null,
      };
    },
  };
}
function setup(initial) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hollow-sysproxy-"));
  const reg = fakeRegistry(initial);
  const logs = [];
  const sp = createSysProxy({ adapter: reg, dir, log: (m) => logs.push(m) });
  return { dir, reg, sp, logs, backupFile: path.join(dir, "proxy-backup.json") };
}
const USER_STATE = { ProxyEnable: 1, ProxyServer: "proxy.user.example:8080", ProxyOverride: "user-bypass", AutoConfigURL: "http://user.example/pac" };

test("roundtrip: enable writes the four keys; restore returns the user's state verbatim", async () => {
  const { reg, sp, backupFile } = setup({ ...USER_STATE });
  await sp.enableGlobal(1080);
  assert.deepEqual(reg.snapshot(), writtenFor(1080));
  const backup = JSON.parse(fs.readFileSync(backupFile, "utf8"));
  assert.deepEqual(backup.original, USER_STATE);
  assert.deepEqual(backup.written, writtenFor(1080));
  const r = await sp.restore();
  assert.equal(r.restored, true);
  assert.equal(r.mode, "snapshot");
  assert.deepEqual(reg.snapshot(), USER_STATE); // verbatim, incl. PAC + bypass
  assert.equal(fs.existsSync(backupFile), false);
});

test("R1 iron rule: a second enable never overwrites the held snapshot", async () => {
  const { reg, sp, backupFile } = setup({ ...USER_STATE });
  await sp.enableGlobal(1080);
  // User hand-edits the proxy mid-session, then hits connect again.
  await reg.set("ProxyServer", "changed.by.user:9999");
  await reg.set("ProxyEnable", 0);
  await sp.enableGlobal(1081);
  const backup = JSON.parse(fs.readFileSync(backupFile, "utf8"));
  assert.deepEqual(backup.original, USER_STATE); // still the true original
  // RF-06-02 same-shape assertion: written followed the actually bound port.
  assert.deepEqual(backup.written, writtenFor(1081));
  assert.deepEqual(reg.snapshot(), writtenFor(1081));
  const r = await sp.restore();
  assert.equal(r.restored, true);
  assert.deepEqual(reg.snapshot(), USER_STATE);
});

test("RF-06-02: held backup — only the written port moves, original never does", async () => {
  const { reg, sp, backupFile } = setup({ ...USER_STATE });
  await sp.enableGlobal(1080); // first session binds 1080
  // App restarts; SOCKS now binds 1090 (1080 was taken). Enable reuses backup.
  await sp.enableGlobal(1090);
  const backup = JSON.parse(fs.readFileSync(backupFile, "utf8"));
  assert.deepEqual(backup.original, USER_STATE);
  assert.deepEqual(backup.written, writtenFor(1090));
  assert.deepEqual(reg.snapshot(), writtenFor(1090)); // post-enable read-back == writtenFor(actual port)
  const r = await sp.restore();
  assert.equal(r.restored, true);
  assert.deepEqual(reg.snapshot(), USER_STATE);
});

test("RF-06-01: backup held + complete FOREIGN config -> registry untouched, backup kept", async () => {
  const { reg, sp, backupFile, logs } = setup({ ...USER_STATE });
  await sp.enableGlobal(1080);
  // The user has since adopted their own complete proxy setup (no Hollow
  // fingerprint in ProxyServer or ProxyOverride).
  const foreign = { ProxyEnable: 1, ProxyServer: "their.proxy:3128", ProxyOverride: "their-bypass-list", AutoConfigURL: "http://their.example/pac" };
  for (const [k, v] of Object.entries(foreign)) await reg.set(k, v);
  const fresh = createSysProxy({ adapter: reg, dir: path.dirname(backupFile), log: (m) => logs.push(m) });
  const r = await fresh.selfHealOnStartup();
  assert.equal(r.healed, false);
  assert.equal(r.mode, "foreign-state");
  assert.deepEqual(reg.snapshot(), foreign); // byte-for-byte untouched
  assert.equal(fs.existsSync(backupFile), true); // backup retained for manual handling
  assert.ok(logs.some((l) => /FOREIGN/.test(l)));
});

test("R2: corrupt backup degrades to a verified no-proxy restore (never silent)", async () => {
  const { reg, sp, backupFile, logs } = setup({ ...USER_STATE });
  await sp.enableGlobal(1080);
  fs.writeFileSync(backupFile, "{ not json !!");
  const r = await sp.restore();
  assert.equal(r.restored, true);
  assert.equal(r.mode, "degraded-corrupt-backup");
  assert.deepEqual(reg.snapshot(), { ...NO_PROXY, ProxyEnable: 0 });
  assert.ok(logs.some((l) => /corrupt/i.test(l)), "degradation must be logged");
});

test("R2: post-restore assertion catches a dropped write and keeps the backup", async () => {
  const { reg, sp, backupFile } = setup({ ...USER_STATE });
  await sp.enableGlobal(1080);
  const origSet = reg.set;
  reg.set = async (name, value) => { if (name === "ProxyServer") return; return origSet(name, value); }; // fault injection
  const r = await sp.restore();
  assert.equal(r.restored, false);
  assert.equal(r.verified, false);
  assert.deepEqual(r.mismatches, ["ProxyServer"]);
  assert.equal(fs.existsSync(backupFile), true); // kept for retry
});

test("R3 self-heal: exact written state at startup -> restored to original (kill -9 path)", async () => {
  const { dir, reg, sp } = setup({ ...USER_STATE });
  await sp.enableGlobal(1080);
  // Process dies here (no restore). A fresh instance over the same dir heals.
  const fresh = createSysProxy({ adapter: reg, dir, log: () => {} });
  const r = await fresh.selfHealOnStartup();
  assert.equal(r.healed, true);
  assert.equal(r.mode, "self-heal");
  assert.deepEqual(reg.snapshot(), USER_STATE);
});

test("R3 self-heal: values already original -> no-op, stale backup dropped", async () => {
  const { reg, sp, backupFile } = setup({ ...USER_STATE });
  await sp.enableGlobal(1080);
  // Someone already restored by hand: registry is back at the original state.
  for (const [k, v] of Object.entries(USER_STATE)) await reg.set(k, v);
  const r = await sp.selfHealOnStartup();
  assert.equal(r.healed, false);
  assert.equal(r.mode, "already-original");
  assert.equal(fs.existsSync(backupFile), false);
  assert.deepEqual(reg.snapshot(), USER_STATE);
});

test("R3 self-heal: partial/damaged state -> degraded no-proxy restore", async () => {
  const { reg, sp, logs } = setup({ ...USER_STATE });
  await sp.enableGlobal(1080);
  await reg.set("ProxyServer", "half-written.example:1234"); // one key diverged
  const res = await sp.selfHealOnStartup();
  assert.equal(res.healed, true);
  assert.equal(res.mode, "degraded-partial-state");
  assert.deepEqual(reg.snapshot(), { ...NO_PROXY, ProxyEnable: 0 });
  assert.ok(logs.some((l) => /PARTIAL/.test(l)));
});

test("R3: a foreign local proxy is never mistaken for ours", async () => {
  // User runs their own local proxy tool; no backup exists -> nothing happens.
  const foreign = { ProxyEnable: 1, ProxyServer: "127.0.0.1:7890", ProxyOverride: "their-bypass", AutoConfigURL: null };
  const { reg, sp } = setup({ ...foreign });
  const r = await sp.selfHealOnStartup();
  assert.equal(r.healed, false);
  assert.equal(r.mode, "none");
  assert.deepEqual(reg.snapshot(), foreign);
});

test("atomicity: backup file is complete valid JSON with no tmp residue", async () => {
  const { dir, sp } = setup({ ...USER_STATE });
  await sp.enableGlobal(1080);
  const files = fs.readdirSync(dir);
  assert.deepEqual(files, ["proxy-backup.json"]);
  const data = JSON.parse(fs.readFileSync(path.join(dir, "proxy-backup.json"), "utf8"));
  assert.equal(data.version, 2);
  assert.equal(data.written.ProxyOverride, BYPASS);
});

test("parseRegQuery: DWORD hex canonicalizes; SZ passes through; absent is null", () => {
  const sample = "\r\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\r\n    ProxyEnable    REG_DWORD    0x1\r\n";
  assert.equal(parseRegQuery(sample, "ProxyEnable"), 1);
  assert.equal(parseRegQuery(sample.replace("0x1", "0x0"), "ProxyEnable"), 0);
  const sz = "    ProxyServer    REG_SZ    127.0.0.1:1080";
  assert.equal(parseRegQuery(sz, "ProxyServer"), "127.0.0.1:1080");
  assert.equal(parseRegQuery("ERROR: The system was unable to find the specified registry key or value.", "ProxyServer"), null);
});
