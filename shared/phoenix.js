// Phoenix streams (NP-1118-32): the JS mirror of the Go core's
// NP-1118-30 layer 1 (design NP-1118-28). A stream that dies
// BEFORE its first inbound byte is transparently reopened and
// its buffered first flight replayed, so the local proxy
// connection never breaks. No protocol change. All knobs are
// local parameters, values identical to the Go side.
export const PHOENIX_BUFFER_CAP = 64 * 1024;
export const PHOENIX_MAX_REOPENS = 2;
export const PHOENIX_REDIAL_RETRY_MS = 400;
export const PHOENIX_BREAKER_THRESHOLD = 5;
export const PHOENIX_BREAKER_WINDOW_MS = 30_000;
export const PHOENIX_BREAKER_COOLDOWN_MS = 60_000;
// NP-1118-48 (Go parity): the establishment window and the
// fast-death bar scale with the measured path cost; the
// floors are the pre-NP-1118-48 constants, so cost 0
// reproduces the old behavior exactly.
export const PHOENIX_WINDOW_FLOOR_MS = 15_000;
export const PHOENIX_WINDOW_CAP_MS = 45_000;
export const PHOENIX_FAST_DEATH_FLOOR_MS = 2_000;
export const PHOENIX_FAST_DEATH_CAP_MS = 10_000;

// clamp(3*cost + 5s, 15s, 45s); cost 0 -> exactly 15s.
export function phoenixWindowFor(costMs) {
  return Math.min(PHOENIX_WINDOW_CAP_MS, Math.max(PHOENIX_WINDOW_FLOOR_MS, 3 * costMs + 5_000));
}

// clamp(1.5*cost, 2s, 10s); cost 0 -> exactly 2s.
export function phoenixFastDeathFor(costMs) {
  return Math.min(PHOENIX_FAST_DEATH_CAP_MS, Math.max(PHOENIX_FAST_DEATH_FLOOR_MS, 1.5 * costMs));
}

const IDEMPOTENT_METHODS = ["GET", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE"];

// Whether the buffered first flight may be replayed onto a
// fresh stream (Go replayableFlight, identical table): nothing
// sent is always safe; a TLS record is always safe; plaintext
// HTTP only for idempotent methods; anything opaque is not
// replayed. An incomplete prefix is replayable only while it
// can still become a TLS record or an idempotent method.
export function replayableFlight(buf) {
  if (buf.length === 0) return true;
  if (buf[0] === 0x16) return buf.length === 1 || buf[1] === 0x03;
  const sp = buf.indexOf(0x20);
  if (sp < 0) {
    const s = buf.toString("latin1");
    return IDEMPOTENT_METHODS.some((m) => s.length < m.length && m.startsWith(s));
  }
  return IDEMPOTENT_METHODS.includes(buf.subarray(0, sp).toString("latin1"));
}

// Session-wide futility guard (Go phoenixBreaker).
export class PhoenixBreaker {
  constructor() {
    this.fastDeaths = 0;
    this.lastFastDeath = 0;
    this.openUntil = 0;
    this.trips = 0;
    // NP-1118-48 path cost (Go parity): max of an EWMA of
    // resolved attempt durations and an EWMA of dial
    // durations (the seed the bridge feeds from carrier
    // establishments).
    this.attemptCostMs = 0;
    this.dialCostMs = 0;
  }
  allow() { return Date.now() > this.openUntil; }
  noteAttemptCost(ms) {
    this.attemptCostMs = this.attemptCostMs > 0 ? (7 * this.attemptCostMs + 3 * ms) / 10 : ms;
  }
  noteDialCost(ms) {
    this.dialCostMs = this.dialCostMs > 0 ? (7 * this.dialCostMs + 3 * ms) / 10 : ms;
  }
  costMs() { return Math.max(this.attemptCostMs, this.dialCostMs); }
  noteFastDeath() {
    const now = Date.now();
    if (now - this.lastFastDeath > PHOENIX_BREAKER_WINDOW_MS) this.fastDeaths = 0;
    this.fastDeaths++;
    this.lastFastDeath = now;
    if (this.fastDeaths >= PHOENIX_BREAKER_THRESHOLD) {
      this.openUntil = now + PHOENIX_BREAKER_COOLDOWN_MS;
      this.trips++;
      this.fastDeaths = 0;
    }
  }
  noteSuccess() { this.fastDeaths = 0; }
}

// Process-wide shared state: one breaker and the two counters
// the bridge snapshot surfaces as phoenixReopens/phoenixSaved
// (same names and meaning as the Go State snapshot).
export const phoenixShared = {
  breaker: new PhoenixBreaker(),
  reopens: 0,
  saved: 0,
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Wrap an opened stream. redial() must return a Promise for a
// fresh opened stream to the same target (in socks.js it is
// openWithRetry with the same arguments). The wrapper presents
// the ClientStream surface the pump uses.
export function wrapPhoenixStream(first, redial, shared = phoenixShared) {
  const w = {
    _cur: first,
    _curBorn: Date.now(),
    _attemptStart: Date.now(),
    _gen: 0,
    _buf: [],
    _bufBytes: 0,
    _protected: true,
    _firstByte: false,
    _attempts: 0,
    _t0: Date.now(),
    _closed: false,
    _failed: false,
    _redialing: false,
    _closeWritePending: false,
    _paused: false,
    _onData: null, _onEnd: null, _onReset: null, _onFail: null, _onDrain: null,
    opened: first.opened,

    get id() { return this._cur ? this._cur.id : first.id; },
    get gate() { return this._cur ? this._cur.gate : first.gate; },
    get state() {
      if (this._closed) return "closed";
      if (this._failed) return "failed";
      return "open";
    },
    get pending() { return this._cur ? this._cur.pending : this._buf; },
    get paused() { return this._paused; },
    set paused(v) {
      this._paused = v;
      if (this._cur) this._cur.paused = v;
    },
    get onData() { return this._onData; },
    set onData(cb) { this._onData = cb; },
    get onEnd() { return this._onEnd; },
    set onEnd(cb) { this._onEnd = cb; },
    get onReset() { return this._onReset; },
    set onReset(cb) { this._onReset = cb; },
    get onFail() { return this._onFail; },
    set onFail(cb) { this._onFail = cb; },
    get onDrain() { return this._onDrain; },
    set onDrain(cb) { this._onDrain = cb; if (this._cur) this._cur.onDrain = cb; },
    get onQueued() { return this._cur ? this._cur.onQueued : null; },
    set onQueued(cb) { if (this._cur) this._cur.onQueued = cb; },

    write(data) {
      if (this._closed || this._failed) return false;
      const chunk = Buffer.isBuffer(data) ? data : Buffer.from(data);
      if (this._protected) {
        this._buf.push(chunk);
        this._bufBytes += chunk.length;
        if (this._bufBytes > PHOENIX_BUFFER_CAP) {
          this._protected = false;
          this._buf = [];
          this._bufBytes = 0;
        }
      }
      if (this._cur) return this._cur.write(chunk);
      // NP-1118-66 (S5): mid-redial. While protection lasts, the
      // chunk was buffered above and replays on install — true is
      // honest. Once protection has ended (first byte seen, or
      // the replay cap dropped the buffer) the chunk would be
      // DISCARDED here: write must refuse (false) so the pump
      // takes its ordinary failure path, instead of the byte
      // stream silently losing a chunk that only the peer's
      // TLS/protocol layer would ever notice.
      return this._protected;
    },

    closeWrite() {
      if (this._closed || this._failed) return;
      this._closeWritePending = true;
      if (this._cur) this._cur.closeWrite();
    },

    reset(code = 0x00) {
      if (this._closed) return;
      this._closed = true;
      if (this._cur) { try { this._cur.reset(code); } catch {} }
    },

    consume(n) {
      if (this._cur) this._cur.consume(n);
    },

    _wire(s) {
      const gen = ++this._gen;
      s.onData = (data) => {
        if (gen !== this._gen || this._closed || this._failed) return;
        if (!this._firstByte) {
          this._firstByte = true;
          this._protected = false;
          this._buf = [];
          this._bufBytes = 0;
          shared.breaker.noteAttemptCost(Date.now() - this._attemptStart);
          if (this._attempts > 0) {
            shared.saved++;
            shared.breaker.noteSuccess();
          }
        }
        if (this._onData) this._onData(data);
      };
      s.onEnd = () => { if (gen === this._gen) this._onDeath("end"); };
      s.onReset = (code) => { if (gen === this._gen) this._onDeath("reset", code); };
      s.onFail = (reason) => { if (gen === this._gen) this._onDeath("fail", reason); };
      s.onDrain = () => { if (gen === this._gen && this._onDrain) this._onDrain(); };
      s.paused = this._paused;
    },

    _onDeath(kind, arg) {
      if (this._closed || this._failed) return;
      if (this._firstByte) {
        // Post-first-byte: today's semantics, forwarded as-is.
        if (kind === "end" && this._onEnd) this._onEnd();
        else if (kind === "reset" && this._onReset) this._onReset(arg);
        else if (kind === "fail" && this._onFail) this._onFail(arg);
        return;
      }
      if (this._redialing) return;
      const now = Date.now();
      // The death is cost evidence first (Go parity): it
      // extends this flow's own window before eligibility is
      // judged.
      shared.breaker.noteAttemptCost(now - this._attemptStart);
      const costMs = shared.breaker.costMs();
      const flight = Buffer.concat(this._buf);
      const eligible = this._protected &&
        this._attempts < PHOENIX_MAX_REOPENS &&
        now - this._t0 < phoenixWindowFor(costMs) &&
        replayableFlight(flight) && shared.breaker.allow();
      const fastDeath = this._attempts > 0 && now - this._curBorn < phoenixFastDeathFor(costMs);
      this._cur = null;
      if (fastDeath) shared.breaker.noteFastDeath();
      if (!eligible) {
        this._failed = true;
        if (this._onFail) this._onFail("phoenix: stream died before first byte");
        return;
      }
      this._redialing = true;
      this._redialLoop(flight);
    },

    async _redialLoop(flight) {
      const dialStart = Date.now();
      for (;;) {
        let s = null;
        try { s = await redial(); } catch { s = null; }
        if (this._closed) { if (s) { try { s.reset(0); } catch {} } return; }
        if (s) {
          this._attempts++;
          shared.reopens++;
          shared.breaker.noteDialCost(Date.now() - dialStart);
          this._cur = s;
          this._curBorn = Date.now();
          this._attemptStart = dialStart;
          this._redialing = false;
          this._wire(s);
          for (const chunk of this._buf) s.write(chunk);
          if (this._closeWritePending) s.closeWrite();
          return;
        }
        // A failed dial does not consume a reopen (Go parity):
        // retry inside the establishment window.
        if (Date.now() - this._t0 > phoenixWindowFor(shared.breaker.costMs())) {
          this._redialing = false;
          this._failed = true;
          if (this._onFail) this._onFail("phoenix: no carrier within the establishment window");
          return;
        }
        await sleep(PHOENIX_REDIAL_RETRY_MS);
        if (this._closed) return;
      }
    },
  };
  w._wire(first);
  return w;
}
