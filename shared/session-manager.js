// Session manager (NP-1117-16, plan A): ONE rotation machine shared by
// the CLI serve loop and the Windows CoreBridge. It owns the lineage
// of HollowClient sessions for a host:
//
//   - The host establishes the first session (with all of its own
//     policy: backoff, auth-fatal, edge fallback) and hands it to
//     adopt(); adopt's promise resolves when the lineage genuinely
//     ends (the then-current session dies with no successor), which is
//     where the host's reconnect loop takes over again.
//   - Rotations — the 15-minute carrier timer AND the NP-1117-16 open
//     budget (SESSION_ROTATE_THRESHOLD sent OPENs, against the
//     measured ~50-establishment platform cap) — go through the same
//     rotateNow(): build the replacement FIRST, swap atomically (the
//     current pointer never goes null mid-rotation, so the SOCKS
//     layer and the bridge state never flicker), then retire the old
//     session to DRAIN: its in-flight streams finish in place, and it
//     is closed only when its stream table empties or the bounded
//     drain grace expires. In-flight streams are never killed by a
//     rotation itself.
//   - Reactive fallback: noteOutboundFailure(client) is the SOCKS
//     layer's 0x06 hook — only a session at/over its budget (or
//     already retired) earns a rotate + one retry; a target-level 0x06
//     under budget changes nothing.
import { SESSION_ROTATE_THRESHOLD } from "./client-core.js";

export const ROTATION_MS = 15 * 60 * 1000; // spec §5.6 carrier rotation
export const DRAIN_GRACE_MS = 10 * 60 * 1000; // bounded drain for retired sessions
const DRAIN_POLL_MS = 200;
const ROTATE_FAILURE_COOLDOWN_MS = 5000;

export class SessionManager {
  constructor({
    establish, // async () => HollowClient (handshaken, host-instrumented)
    log = () => {},
    rotateThreshold = SESSION_ROTATE_THRESHOLD,
    rotationMs = ROTATION_MS,
    drainGraceMs = DRAIN_GRACE_MS,
    onSwap = () => {}, // (newClient, oldClient) after an atomic swap
    onLineageEnd = () => {}, // the lineage's current session is gone
  }) {
    this.establish = establish;
    this.log = log;
    this.rotateThreshold = rotateThreshold;
    this.rotationMs = rotationMs;
    this.drainGraceMs = drainGraceMs;
    this.onSwap = onSwap;
    this.onLineageEnd = onLineageEnd;
    this._current = null;
    this._draining = new Set();
    this._waiters = []; // adopt() resolvers for the live lineage
    this._rotating = null; // in-flight rotateNow() promise (dedup)
    this._rotateTimer = null;
    this._cooldownUntil = 0;
    this._stopped = false;
    this.rotations = 0; // completed swaps (telemetry/tests)
  }

  current() { return this._current; }

  // Register a host-established session as the lineage's current.
  // Returns a promise that resolves when the lineage ends.
  adopt(client) {
    this._register(client);
    this._current = client;
    this._armRotationTimer();
    return new Promise((res) => { this._waiters.push(res); });
  }

  _register(client) {
    client.onCarrierDead = () => this._onClientDeath(client);
    client.onOpenThreshold = () => {
      this.log(`session open budget reached (${this.rotateThreshold} opens); rotating`);
      this.rotateNow("open budget");
    };
  }

  _onClientDeath(client) {
    if (this._draining.has(client)) {
      // A retired session died on its own: just finish its bookkeeping.
      this._finishDrain(client);
      return;
    }
    if (client !== this._current) return; // stale; already superseded
    this._current = null;
    if (this._rotating) {
      // The current died mid-rotation: the rotation's outcome decides
      // the lineage — success installs a successor (lineage goes on),
      // failure ends it (the host reconnects from scratch).
      this._rotating.then((ok) => { if (!ok) this._endLineage(); });
      return;
    }
    this._endLineage();
  }

  _endLineage() {
    this._clearRotationTimer();
    try { this.onLineageEnd(); } catch { /* host callback */ }
    const waiters = this._waiters.splice(0);
    for (const res of waiters) res();
  }

  _armRotationTimer() {
    this._clearRotationTimer();
    if (this.rotationMs > 0 && !this._stopped) {
      this._rotateTimer = setTimeout(() => {
        this.log("carrier rotation (15 min)");
        this.rotateNow("15 min rotation");
      }, this.rotationMs);
      this._rotateTimer.unref?.();
    }
  }
  _clearRotationTimer() {
    if (this._rotateTimer) { clearTimeout(this._rotateTimer); this._rotateTimer = null; }
  }

  // Build a replacement, swap atomically, retire the old session to
  // drain. Concurrent calls share one rotation. Returns true iff a
  // swap happened. A failed establishment keeps the old current and
  // arms a cooldown so threshold triggers cannot hammer the dialer.
  rotateNow(reason = "rotation") {
    if (this._stopped) return Promise.resolve(false);
    if (this._rotating) return this._rotating;
    if (Date.now() < this._cooldownUntil) return Promise.resolve(false);
    const run = (async () => {
      let next;
      try {
        next = await this.establish();
      } catch (e) {
        this.log(`rotation (${reason}) failed: ${e && e.message || e}; keeping current session`);
        this._cooldownUntil = Date.now() + ROTATE_FAILURE_COOLDOWN_MS;
        return false;
      }
      if (this._stopped) { try { next.close(); } catch { /* ignore */ } return false; }
      const old = this._current;
      this._register(next);
      this._current = next;
      this.rotations++;
      this.log(`session rotated (${reason})`);
      try { this.onSwap(next, old); } catch { /* host callback */ }
      this._armRotationTimer();
      if (old && old !== next) this._retireToDrain(old);
      return true;
    })();
    this._rotating = run;
    run.then(() => { if (this._rotating === run) this._rotating = null; });
    return run;
  }

  _retireToDrain(client) {
    client.budgetExhausted = true; // late 0x06s on it still earn migration
    if (client.state === "dead") return;
    this._draining.add(client);
    const grace = setTimeout(() => this._finishDrain(client, true), this.drainGraceMs);
    grace.unref?.();
    const poll = setInterval(() => {
      if (client.state === "dead" || client.streams.size === 0) this._finishDrain(client);
    }, DRAIN_POLL_MS);
    poll.unref?.();
    client._drainTimers = { grace, poll };
    if (client.streams.size === 0) this._finishDrain(client);
  }

  _finishDrain(client, forced = false) {
    if (!this._draining.delete(client)) {
      // Not draining (or already finished): still drop stray timers.
      if (client._drainTimers) {
        clearTimeout(client._drainTimers.grace);
        clearInterval(client._drainTimers.poll);
        client._drainTimers = null;
      }
      return;
    }
    if (client._drainTimers) {
      clearTimeout(client._drainTimers.grace);
      clearInterval(client._drainTimers.poll);
      client._drainTimers = null;
    }
    if (client.state !== "dead") {
      this.log(forced
        ? "drain grace expired; closing retired session"
        : "retired session drained; closing it");
      try { client.close(); } catch { /* ignore */ }
    }
  }

  // SOCKS-layer 0x06 hook (NP-1117-16 item 2): rotate + let the caller
  // retry once on the new session — ONLY when the failing session is
  // at/over its open budget or already retired. A target-level 0x06
  // under budget returns false: no rotation, no retry.
  async noteOutboundFailure(client) {
    if (this._stopped || !client) return false;
    if (client.opensSent >= this.rotateThreshold || client.budgetExhausted) {
      // If that session is no longer current (already swapped), the
      // retry can go straight onto the live one — no new rotation.
      if (client !== this._current && this._current) return true;
      return this.rotateNow("outbound failed at budget");
    }
    return false;
  }

  stop() {
    this._stopped = true;
    this._clearRotationTimer();
    const all = [...this._draining];
    if (this._current) all.push(this._current);
    this._current = null;
    for (const c of all) {
      if (c._drainTimers) {
        clearTimeout(c._drainTimers.grace);
        clearInterval(c._drainTimers.poll);
        c._drainTimers = null;
      }
      try { c.close(); } catch { /* ignore */ }
    }
    this._draining.clear();
    const waiters = this._waiters.splice(0);
    for (const res of waiters) res();
  }
}
