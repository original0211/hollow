// App-side dead-man's watch over the helper's heartbeats (self-heal spec
// §7; notes v2 §6 mandatory change D). Liveness is heartbeat FRESHNESS,
// never process existence, and the freshness gap must be measured on a
// sleep-deducted clock: a machine that slept 8 hours must not wake up and
// instantly declare its (also sleeping) helper dead — nor may a helper
// that died before the sleep escape detection after the wake.
//
// Method: staleness requires BOTH clocks to agree the peer is overdue —
// the wall gap AND the monotonic gap must each exceed the threshold.
//   - mono excludes sleep (unbiased): after a sleep the mono gap stays
//     small while the wall gap explodes -> not stale (correct).
//   - mono includes sleep (raw QPC): a helper that died pre-sleep shows
//     huge gaps on both after the wake -> stale (correct).
//   - no sleep involved: both gaps track real time -> stale at threshold.
// The helper's own unbiased uptime (carried in each heartbeat) is kept
// for diagnostics and rate sanity, not as the yardstick.
//
// onStale fires once per stale episode; a fresh heartbeat resets it. The
// caller's onStale runs the restore chain: ask the helper to restore via
// IPC, and if it does not answer, launch `hollow-tun-helper --restore-tun`
// elevated (self-heal spec §6/§7). That wiring lives in the main process
// (T-4 integration); this module is the judge.
export class HelperWatch {
  constructor({
    thresholdMs = 10_000,
    wallNow = () => Date.now(),
    monoNow = () => performance.now(),
    onStale = () => {},
  } = {}) {
    this.thresholdMs = thresholdMs;
    this.wallNow = wallNow;
    this.monoNow = monoNow;
    this.onStale = onStale;
    this.lastWall = null;
    this.lastMono = null;
    this.lastUptime = null;
    this.stale = false;
  }

  noteHeartbeat(uptimeMs = null) {
    this.lastWall = this.wallNow();
    this.lastMono = this.monoNow();
    if (typeof uptimeMs === "number") this.lastUptime = uptimeMs;
    this.stale = false;
  }

  gaps() {
    if (this.lastWall === null) return null;
    return {
      wallGap: this.wallNow() - this.lastWall,
      monoGap: this.monoNow() - this.lastMono,
    };
  }

  // Returns "unknown" (no heartbeat yet), "alive", or "stale".
  check() {
    const g = this.gaps();
    if (!g) return "unknown";
    const overdue = g.wallGap > this.thresholdMs && g.monoGap > this.thresholdMs;
    if (overdue && !this.stale) {
      this.stale = true;
      this.onStale({ ...g, lastUptime: this.lastUptime });
    }
    return overdue ? "stale" : "alive";
  }
}
