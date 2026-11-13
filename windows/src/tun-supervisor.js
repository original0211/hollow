// TUN application-side orchestration (NP-1114-25 items 4/5, RF-21-03③).
// Pure decision logic with injected clocks and effects — main.js wires
// the real IPC/process calls into these seams.
//
// Two responsibilities:
//  1. TunGraceSupervisor — the 60-second reconnect grace (notes v2 §6):
//     TUN up + bridge reconnecting keeps the takeover (DNS fails closed
//     via SERVFAIL, T-3); if the bridge has not recovered when the grace
//     expires on the SLEEP-EXCLUDED monotonic clock, auto-restore. A
//     bridge error terminal state restores immediately, no grace
//     (RF-06-03 philosophy: never sit on a dead bearer).
//  2. createStaleRestoreHandler — HelperWatch onStale action path: a
//     stale JUDGEMENT is never acted on directly. First an IPC recheck
//     (a live reply overturns it), then one heartbeat cycle of grace and
//     a second judgement; only then restore — IPC restore verb first,
//     the helper's --restore-tun CLI as fallback. Every outcome is
//     reported through onOutcome + log; failures surface, never vanish.

export class TunGraceSupervisor {
  constructor({ monoNow, graceMs = 60_000, onAutoRestore } = {}) {
    this.monoNow = monoNow ?? (() => performance.now());
    this.graceMs = graceMs;
    this.onAutoRestore = onAutoRestore ?? (() => {});
    this.tunActive = false;
    this.bridgeStatus = "off";
    this.graceStartMono = null;
    this.fired = false;
  }

  noteTunActive(active) {
    this.tunActive = active;
    if (!active) {
      this.graceStartMono = null;
      this.fired = false;
    }
  }

  noteBridgeStatus(status) {
    this.bridgeStatus = status;
    if (!this.tunActive) return;
    if (status === "reconnecting" && this.graceStartMono === null && !this.fired) {
      this.graceStartMono = this.monoNow();
    }
    if (status === "connected") {
      this.graceStartMono = null; // recovered inside the grace
    }
  }

  // Poll-driven (main ticks ~1s). Returns the current disposition.
  check() {
    if (!this.tunActive || this.fired) return "idle";
    if (this.bridgeStatus === "error") {
      this.fired = true;
      this.onAutoRestore("bridge-error");
      return "restored";
    }
    if (this.graceStartMono !== null) {
      if (this.monoNow() - this.graceStartMono >= this.graceMs) {
        this.fired = true;
        this.onAutoRestore("grace-expired");
        return "restored";
      }
      return "grace-pending";
    }
    return "idle";
  }

  graceRemainingMs() {
    if (this.graceStartMono === null) return null;
    return Math.max(0, this.graceMs - (this.monoNow() - this.graceStartMono));
  }
}

// The TUN status segment for the app's state surface (item 6). Fixed
// copy is deliberate: the notices say exactly what the mode does — IPv6
// is blocked, UDP does not traverse the encrypted channel — and never
// claim a "global proxy" the build does not provide.
export const TUN_NOTICES = [
  "IPv6 已阻断",
  "UDP 流量不经过 Hollow 加密通道",
];

export function tunStatusView({ proxyMode, helperAlive, helperStatus, graceRemainingMs }) {
  const active = proxyMode === "tun";
  const pump = helperStatus?.pump ?? null;
  return {
    active,
    helperAlive: !!helperAlive,
    mode: helperStatus?.mode ?? "off",
    droppedV6: pump?.droppedV6 ?? 0,
    droppedUdp: pump?.droppedUdp ?? 0,
    dns: {
      queries: pump?.dnsQueries ?? 0,
      resolved: pump?.dnsResolved ?? 0,
      servfail: pump?.dnsServfail ?? 0,
      conns: pump?.dnsConns ?? 0,
    },
    graceRemainingMs: graceRemainingMs ?? null,
    notices: active ? [...TUN_NOTICES] : [],
  };
}

// The mode families are mutually exclusive (item 6): exactly one of
// off / sysproxy (global|pac) / tun owns the system at a time.
export function modeFamily(proxyMode) {
  if (proxyMode === "tun") return "tun";
  if (proxyMode === "global" || proxyMode === "pac") return "sysproxy";
  return "off";
}
//   isStale()      -> bool, the HelperWatch's current judgement
//   pingIpc()      -> Promise<bool>: one fresh IPC round-trip answered
//   ipcRestore()   -> Promise<bool>: the restore verb over the pipe
//   spawnRestoreCli() -> Promise<bool>: helper --restore-tun exit success
//   wait(ms)       -> Promise<void> (injectable; defaults to setTimeout)
//   heartbeatMs    -> one heartbeat cycle (default 2000)
//   log(msg), onOutcome(result)
export function createStaleRestoreHandler(deps) {
  const wait = deps.wait ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  const heartbeatMs = deps.heartbeatMs ?? 2000;
  const log = deps.log ?? (() => {});
  const onOutcome = deps.onOutcome ?? (() => {});

  return async function handleStale() {
    // Step 1 (RF-21-03③): IPC recheck before ANY action.
    if (await deps.pingIpc()) {
      log("helper-watch: stale judgement overturned by IPC recheck — no action");
      const r = { acted: false, via: null, reason: "ipc-recheck-alive" };
      onOutcome(r);
      return r;
    }
    // Step 2: one heartbeat cycle of grace, then judge again.
    await wait(heartbeatMs);
    if (!deps.isStale()) {
      log("helper-watch: helper recovered inside the grace cycle — no action");
      const r = { acted: false, via: null, reason: "recovered-in-grace" };
      onOutcome(r);
      return r;
    }
    // Step 3: restore — IPC verb first.
    if (await deps.ipcRestore()) {
      log("helper-watch: stale confirmed; restored via IPC restore");
      const r = { acted: true, via: "ipc", reason: "restored" };
      onOutcome(r);
      return r;
    }
    // Step 4: CLI fallback.
    if (await deps.spawnRestoreCli()) {
      log("helper-watch: IPC restore unanswered; restored via --restore-tun");
      const r = { acted: true, via: "cli", reason: "restored" };
      onOutcome(r);
      return r;
    }
    log("helper-watch: STALE HELPER AND BOTH RESTORE PATHS FAILED — takeover state unknown, surfacing");
    const r = { acted: false, via: null, reason: "restore-paths-failed" };
    onOutcome(r);
    return r;
  };
}
