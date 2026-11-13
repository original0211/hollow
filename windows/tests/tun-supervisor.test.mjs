import { test } from "node:test";
import assert from "node:assert/strict";
import { TunGraceSupervisor, createStaleRestoreHandler } from "../src/tun-supervisor.js";

function fakeMono(start = 0) {
  const c = { t: start };
  return { now: () => c.t, advance: (ms) => { c.t += ms; } };
}

// ---- 60s grace (item 4) ----

test("grace: reconnecting holds the takeover for 60s, then auto-restores once", () => {
  const m = fakeMono();
  const fired = [];
  const g = new TunGraceSupervisor({ monoNow: m.now, onAutoRestore: (r) => fired.push(r) });
  g.noteTunActive(true);
  g.noteBridgeStatus("connected");
  g.noteBridgeStatus("reconnecting");
  m.advance(59_000);
  assert.equal(g.check(), "grace-pending");
  assert.equal(fired.length, 0);
  m.advance(1_500);
  assert.equal(g.check(), "restored");
  assert.deepEqual(fired, ["grace-expired"]);
  assert.equal(g.check(), "idle"); // never twice
});

test("grace: recovery inside the window cancels; sleep does not burn the grace", () => {
  const m = fakeMono();
  const fired = [];
  const g = new TunGraceSupervisor({ monoNow: m.now, onAutoRestore: (r) => fired.push(r) });
  g.noteTunActive(true);
  g.noteBridgeStatus("reconnecting");
  m.advance(30_000); // 30s of AWAKE time; wall clock may have jumped hours in sleep — irrelevant, mono rules
  g.noteBridgeStatus("connected");
  m.advance(60_000);
  assert.equal(g.check(), "idle");
  assert.equal(fired.length, 0);
});

test("grace: bridge error restores immediately, no 60s wait", () => {
  const m = fakeMono();
  const fired = [];
  const g = new TunGraceSupervisor({ monoNow: m.now, onAutoRestore: (r) => fired.push(r) });
  g.noteTunActive(true);
  g.noteBridgeStatus("reconnecting");
  m.advance(3_000);
  g.noteBridgeStatus("error");
  assert.equal(g.check(), "restored");
  assert.deepEqual(fired, ["bridge-error"]);
});

// ---- stale action path (items 3③ + 5) ----

function handlerDeps(overrides = {}) {
  const calls = [];
  const deps = {
    isStale: () => true,
    pingIpc: async () => { calls.push("ping"); return false; },
    ipcRestore: async () => { calls.push("ipcRestore"); return true; },
    spawnRestoreCli: async () => { calls.push("cli"); return true; },
    wait: async () => { calls.push("wait"); },
    heartbeatMs: 2000,
    log: () => {},
    onOutcome: () => {},
    ...overrides,
  };
  return { deps, calls };
}

test("stale action: a live IPC recheck overturns the judgement — nothing happens", async () => {
  const { deps, calls } = handlerDeps({ pingIpc: async () => { calls.push("ping"); return true; } });
  const h = createStaleRestoreHandler(deps);
  const r = await h();
  assert.equal(r.acted, false);
  assert.equal(r.reason, "ipc-recheck-alive");
  assert.deepEqual(calls, ["ping"]); // no wait, no restore
});

test("stale action: recovery inside the grace cycle also stands the action down", async () => {
  let stale = true;
  const { deps, calls } = handlerDeps({ isStale: () => stale });
  deps.wait = async () => { calls.push("wait"); stale = false; };
  const h = createStaleRestoreHandler(deps);
  const r = await h();
  assert.equal(r.acted, false);
  assert.equal(r.reason, "recovered-in-grace");
  assert.deepEqual(calls, ["ping", "wait"]);
});

test("stale action: confirmed stale restores over IPC first", async () => {
  const { deps, calls } = handlerDeps();
  const h = createStaleRestoreHandler(deps);
  const r = await h();
  assert.deepEqual(r, { acted: true, via: "ipc", reason: "restored" });
  assert.deepEqual(calls, ["ping", "wait", "ipcRestore"]);
});

test("stale action: IPC restore unanswered falls back to --restore-tun; double failure surfaces", async () => {
  const a = handlerDeps({ ipcRestore: async () => { a.calls.push("ipcRestore"); return false; } });
  const r1 = await createStaleRestoreHandler(a.deps)();
  assert.equal(r1.via, "cli");

  const b = handlerDeps({
    ipcRestore: async () => false,
    spawnRestoreCli: async () => false,
  });
  const r2 = await createStaleRestoreHandler(b.deps)();
  assert.deepEqual(r2, { acted: false, via: null, reason: "restore-paths-failed" });
});

// ---- status view + mode family (item 6) ----

test("status view: fixed notices, counters mapped, inactive mode hides notices", async () => {
  const { tunStatusView, modeFamily } = await import("../src/tun-supervisor.js");
  const v = tunStatusView({
    proxyMode: "tun", helperAlive: true,
    helperStatus: { mode: "tun", pump: { droppedV6: 3, droppedUdp: 5, dnsQueries: 9, dnsResolved: 8, dnsServfail: 1, dnsConns: 1 } },
    graceRemainingMs: 12000,
  });
  assert.equal(v.active, true);
  assert.equal(v.droppedV6, 3);
  assert.equal(v.dns.servfail, 1);
  assert.deepEqual(v.notices, ["IPv6 已阻断", "UDP 流量不经过 Hollow 加密通道"]);
  const off = tunStatusView({ proxyMode: "global", helperAlive: false, helperStatus: null });
  assert.deepEqual(off.notices, []);
  assert.equal(modeFamily("tun"), "tun");
  assert.equal(modeFamily("pac"), "sysproxy");
  assert.equal(modeFamily("off"), "off");
});
