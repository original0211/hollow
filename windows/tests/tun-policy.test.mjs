// TUN policy + bearer lock + helper watch tests (NP-1114-20, mapping M-18).
// Hermetic: no network — the bridge is driven with a recording transport
// factory, the watch with injected clocks.
import { test as _test } from "node:test";
const test = (name, fn) => _test(name, { timeout: 15000 }, fn);
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const winDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
execFileSync("node", [path.join(winDir, "tools", "prepare-vendor.mjs")], { stdio: "ignore" });

const { CoreBridge } = await import("../src/core-bridge.js");
const { planTunEnable, planCandidateRefresh, edgeModeDisabledInTun, isDialAllowed } = await import("../src/tun-policy.js");
const { HelperWatch } = await import("../src/helper-watch.js");

const PSK = new Uint8Array(32).fill(7);

// ---- planTunEnable ----

test("plan: manual pick inside candidates pins the set as-is", () => {
  const p = planTunEnable({ edgeMode: "manual", preferredEdgeIp: "1.1.1.1", candidates: ["1.1.1.1", "8.8.8.8"] });
  assert.equal(p.ok, true);
  assert.equal(p.bearerIp, "1.1.1.1");
  assert.deepEqual(p.pins, ["1.1.1.1", "8.8.8.8"]);
});

test("plan: manual pick outside the list joins the set (one ledger)", () => {
  const p = planTunEnable({ edgeMode: "manual", preferredEdgeIp: "9.9.9.9", candidates: ["1.1.1.1"] });
  assert.equal(p.ok, true);
  assert.deepEqual(p.pins, ["1.1.1.1", "9.9.9.9"]);
});

test("plan: default mode pins a resolved answer; without one it refuses", () => {
  const ok = planTunEnable({ edgeMode: "default", candidates: ["1.1.1.1"], resolvedIps: ["203.0.113.7"] });
  assert.equal(ok.ok, true);
  assert.equal(ok.bearerIp, "203.0.113.7");
  assert.ok(ok.pins.includes("203.0.113.7") && ok.pins.includes("1.1.1.1"));
  const no = planTunEnable({ edgeMode: "default", candidates: ["1.1.1.1"], resolvedIps: [] });
  assert.equal(no.ok, false);
  assert.match(no.reason, /resolve/i);
});

test("plan: default-resolution UI choice is disabled under TUN", () => {
  assert.equal(edgeModeDisabledInTun("default", true), true);
  assert.equal(edgeModeDisabledInTun("default", false), false);
  assert.equal(edgeModeDisabledInTun("auto", true), false);
});

// ---- planCandidateRefresh ----

test("refresh: two-phase — union first (old bearer survives), retire only after confirm", () => {
  const r = planCandidateRefresh(["1.1.1.1", "8.8.8.8"], ["8.8.8.8", "9.9.9.9"], "1.1.1.1");
  assert.deepEqual(r.added, ["9.9.9.9"]);
  assert.deepEqual(r.retired, ["1.1.1.1"]);
  assert.deepEqual([...r.pinsToSend].sort(), ["1.1.1.1", "8.8.8.8", "9.9.9.9"]); // phase 1 keeps the live bearer's /32
  assert.deepEqual([...r.finalPins].sort(), ["8.8.8.8", "9.9.9.9"]); // phase 2 retires it, post-confirm only
  assert.deepEqual(r.retiredAfterConfirm, ["1.1.1.1"]);
  assert.equal(r.bearerStillValid, false);
  assert.equal(r.nextBearerIp, "8.8.8.8");
  const r2 = planCandidateRefresh(["1.1.1.1"], ["1.1.1.1", "9.9.9.9"], "1.1.1.1");
  assert.equal(r2.bearerStillValid, true);
  assert.equal(r2.nextBearerIp, "1.1.1.1");
});

// ---- CoreBridge bearer lock ----

test("bridge lock: effective dial IP is coerced into the pinned set", () => {
  const b = new CoreBridge({ workerUrl: "wss://example.workers.dev", psk: PSK, edgeIp: "9.9.9.9" });
  assert.equal(b.effectiveEdgeIp(), "9.9.9.9"); // unlocked: as configured
  b.setBearerLock(["1.1.1.1", "8.8.8.8"]);
  assert.equal(b.effectiveEdgeIp(), "1.1.1.1"); // 9.9.9.9 not pinned -> first pinned
  b.setEdgeIp("8.8.8.8");
  assert.equal(b.effectiveEdgeIp(), "8.8.8.8"); // pinned member honored
  b.setEdgeIp(null); // user asks for default resolution under TUN...
  assert.equal(b.effectiveEdgeIp(), "1.1.1.1"); // ...still pinned, never hostname dialing
  b.setBearerLock(null);
  assert.equal(b.effectiveEdgeIp(), null); // unlocked again: default resolution
  assert.equal(isDialAllowed("1.1.1.1", ["1.1.1.1"]), true);
  assert.equal(isDialAllowed(null, ["1.1.1.1"]), false);
});

test("bridge lock: empty lock forbids dialing entirely (no transport is ever built)", async () => {
  let built = 0;
  const b = new CoreBridge({
    workerUrl: "wss://example.workers.dev", psk: PSK,
    makeTransport: async () => { built++; throw new Error("must not be called"); },
    backoffBaseMs: 5, backoffCapMs: 10,
  });
  b.setBearerLock([]);
  await b.connect();
  await new Promise((r) => setTimeout(r, 60));
  await b.disconnect();
  assert.equal(built, 0);
});

// ---- HelperWatch ----

function fakeClocks() {
  const c = { wall: 1_000_000, mono: 500_000 };
  return { c, wallNow: () => c.wall, monoNow: () => c.mono };
}

test("watch: flowing heartbeats stay alive; silence past threshold goes stale once", () => {
  const { c, wallNow, monoNow } = fakeClocks();
  let fired = 0;
  const w = new HelperWatch({ wallNow, monoNow, onStale: () => fired++ });
  assert.equal(w.check(), "unknown");
  w.noteHeartbeat(1000);
  c.wall += 3000; c.mono += 3000;
  assert.equal(w.check(), "alive");
  c.wall += 11_000; c.mono += 11_000;
  assert.equal(w.check(), "stale");
  assert.equal(w.check(), "stale");
  assert.equal(fired, 1); // once per episode
  w.noteHeartbeat(15000);
  assert.equal(w.check(), "alive"); // episode reset
});

test("watch: a long sleep (wall jumps, mono barely moves) is NOT staleness", () => {
  const { c, wallNow, monoNow } = fakeClocks();
  let fired = 0;
  const w = new HelperWatch({ wallNow, monoNow, onStale: () => fired++ });
  w.noteHeartbeat(1000);
  c.wall += 8 * 3600 * 1000; // 8h of wall time...
  c.mono += 4000;            // ...but only 4s of awake time (mono excludes sleep)
  assert.equal(w.check(), "alive");
  assert.equal(fired, 0);
});

test("watch: helper dead before a sleep (both clocks jump) IS stale after wake", () => {
  const { c, wallNow, monoNow } = fakeClocks();
  const w = new HelperWatch({ wallNow, monoNow });
  w.noteHeartbeat(1000);
  c.wall += 8 * 3600 * 1000;
  c.mono += 8 * 3600 * 1000; // sleep-inclusive mono platform
  assert.equal(w.check(), "stale");
});

test("RF-21-05: v6 candidates are stripped with reasons; the v4 plan proceeds intact", () => {
  const plan = planTunEnable({
    edgeMode: "manual",
    preferredEdgeIp: "203.0.113.7",
    candidates: ["203.0.113.7", "2606:4700:4700::1111", "198.51.100.9"],
    resolvedIps: [],
  });
  assert.equal(plan.ok, true);
  assert.equal(plan.bearerIp, "203.0.113.7");
  assert.deepEqual([...plan.pins].sort(), ["198.51.100.9", "203.0.113.7"]);
  assert.equal(plan.stripped.length, 1);
  assert.equal(plan.stripped[0].ip, "2606:4700:4700::1111");
  assert.match(plan.stripped[0].reason, /RF-21-05/);

  const refresh = planCandidateRefresh(plan.pins, ["203.0.113.7", "2001:db8::1"], "203.0.113.7");
  assert.deepEqual(refresh.finalPins, ["203.0.113.7"]);
  assert.ok(refresh.pinsToSend.includes("198.51.100.9")); // phase-1 union keeps it until confirm
  assert.equal(refresh.stripped.length, 1);
  assert.equal(refresh.bearerStillValid, true);

  const v6Bearer = planTunEnable({ edgeMode: "manual", preferredEdgeIp: "2001:db8::9", candidates: ["203.0.113.7"] });
  assert.equal(v6Bearer.ok, false);
  assert.equal(v6Bearer.stripped.length, 1);
});
