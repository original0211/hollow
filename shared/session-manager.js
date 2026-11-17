// Session lineage (NP-1117-16, plan A): ONE rotation machine for ONE
// carrier, shared by the CLI serve loop and the Windows CoreBridge.
// It owns the lineage of HollowClient sessions for a host:
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

class SessionLineage {
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

  // Pool support (NP-1117-23): does this lineage own the session
  // (as its current or as a draining retiree)?
  has(client) { return client === this._current || this._draining.has(client); }

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

// ---------------------------------------------------------------------------
// Session pool (NP-1117-23): N independent lineages behind one facade.
// The striping A/B (NP-1117-22) showed aggregate throughput scaling
// near-linearly with independent carriers — each carrier is its own
// TCP/WebSocket leg with its own head-of-line blocking domain, and the
// server simply sees N ordinary independent sessions; the protocol is
// untouched. Placement: a new stream goes to the healthy carrier with
// the fewest active streams (ties broken round-robin); a stream
// belongs to its carrier for life and is never split across carriers.
// Every lineage keeps the full NP-1117-16 semantics (open-budget
// rotation, reactive 0x06 rotation, 15-minute timer, drain). One
// lineage ending never blocks placement on the others; the host runs
// one supervisor loop per slot and replenishes a slot by adopt()ing a
// fresh session when that lineage's promise resolves.
export const DEFAULT_POOL_SIZE = 4;
export const MAX_POOL_SIZE = 8;

export class SessionManager {
  constructor({
    establish, // async () => HollowClient (handshaken, host-instrumented)
    log = () => {},
    rotateThreshold = SESSION_ROTATE_THRESHOLD,
    rotationMs = ROTATION_MS,
    drainGraceMs = DRAIN_GRACE_MS,
    onSwap = () => {}, // (newClient, oldClient) after an atomic swap in any lineage
    onLineageEnd = () => {}, // one lineage's current session is gone
    size = DEFAULT_POOL_SIZE,
  }) {
    this.establish = establish;
    this.log = log;
    this.size = Math.max(1, Math.min(MAX_POOL_SIZE, Math.floor(size) || 1));
    this._lineageOpts = { establish, log, rotateThreshold, rotationMs, drainGraceMs };
    this._onSwap = onSwap;
    this._onLineageEnd = onLineageEnd;
    this._slots = []; // { lineage, busy }
    this._rr = 0; // round-robin cursor for placement ties
    this._stopped = false;
  }

  _newSlot() {
    const slot = { lineage: null, busy: false };
    slot.lineage = new SessionLineage({
      ...this._lineageOpts,
      onSwap: (next, old) => { this._onSwap(next, old); },
      onLineageEnd: () => {
        slot.busy = false;
        this._onLineageEnd();
      },
    });
    this._slots.push(slot);
    return slot;
  }

  // Register a host-established session into a free slot; the
  // returned promise resolves when THAT lineage ends. The host runs
  // exactly one supervisor loop per slot, so a free slot always
  // exists — overflow is a host bug, not a runtime condition.
  adopt(client) {
    let slot = this._slots.find((s) => !s.busy);
    if (!slot) {
      if (this._slots.length >= this.size) {
        throw new Error(`session pool exhausted (size ${this.size})`);
      }
      slot = this._newSlot();
    }
    slot.busy = true;
    return slot.lineage.adopt(client);
  }

  // Placement for a NEW stream: the healthy carrier with the fewest
  // active streams; ties round-robin. `exclude` (the carrier a stream
  // just failed on) is avoided while any alternative exists.
  pick(exclude = null) {
    const healthy = [];
    for (const slot of this._slots) {
      const c = slot.lineage.current();
      if (c && c.state === "open") healthy.push(c);
    }
    if (!healthy.length) return null;
    let pool = healthy.filter((c) => c !== exclude);
    if (!pool.length) pool = healthy;
    let min = Infinity;
    for (const c of pool) min = Math.min(min, c.streams.size);
    const tied = pool.filter((c) => c.streams.size === min);
    const chosen = tied[this._rr % tied.length];
    this._rr++;
    return chosen;
  }

  // A representative live session (the least loaded), or null.
  current() { return this.pick(); }

  healthyCount() {
    let n = 0;
    for (const slot of this._slots) {
      const c = slot.lineage.current();
      if (c && c.state === "open") n++;
    }
    return n;
  }

  get rotations() {
    return this._slots.reduce((sum, s) => sum + s.lineage.rotations, 0);
  }

  // SOCKS-layer 0x06 hook: route to the lineage that owns the
  // failing session (as its current or as a draining retiree).
  async noteOutboundFailure(client) {
    if (this._stopped || !client) return false;
    for (const slot of this._slots) {
      if (slot.lineage.has(client)) return slot.lineage.noteOutboundFailure(client);
    }
    return false;
  }

  stop() {
    this._stopped = true;
    for (const slot of this._slots) slot.lineage.stop();
  }
}
