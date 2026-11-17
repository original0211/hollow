// Core bridge (M2-1, NP-1114-03): owns the M1-verified HollowClient inside
// the app — connection state machine, §8.4 reconnect backoff and 15-minute
// carrier rotation mirroring `cli serve` semantics, the SOCKS5 entry
// lifecycle, stream/carrier counters and the OPEN_QUEUED event surface.
// The one deliberate addition over the CLI: auth-class handshake failures
// (wrong PSK and friends) are fatal — they stop in the Error state instead
// of retrying forever (plan §4). Electron-free: tests drive this module
// directly with an injected transport factory.
import { HollowClient } from "../vendor/shared/client-core.js";
import { SessionManager } from "../vendor/shared/session-manager.js";
import { connectWs } from "../vendor/cli/src/ws-client.js";
import { startSocks } from "../vendor/cli/src/socks.js";

const AUTH_FATAL = /undecryptable|server hello rejected|finished|verifier/i;
export const ROTATION_MS = 15 * 60 * 1000; // spec §5.6
// NP-1117-07 (d3): consecutive carrier failures against a pinned edge IP
// before the session falls back to default (domain) resolution.
export const EDGE_FALLBACK_THRESHOLD = 3;

export function backoffDelay(failures, baseMs = 1000, capMs = 60000, rnd = Math.random) {
  // spec §8.4 as implemented by the CLI: 1s doubling to a 60s cap, ±25% jitter.
  const base = Math.min(capMs, baseMs * 2 ** Math.min(Math.max(failures - 1, 0), 6));
  return Math.round(base * (1 + (rnd() * 0.5 - 0.25)));
}

export class CoreBridge {
  constructor({ workerUrl, psk, keyId = 1, log = () => {}, makeTransport = null, rotationMs = ROTATION_MS, backoffBaseMs = 1000, backoffCapMs = 60000, edgeIp = null, poolSize = 4, edgeCandidates = null }) {
    this.workerUrl = workerUrl;
    this.psk = psk;
    this.keyId = keyId;
    this.log = log;
    this.rotationMs = rotationMs;
    this.backoffBaseMs = backoffBaseMs;
    this.backoffCapMs = backoffCapMs;
    // Edge-IP selection (M2-4): read at every carrier attempt, so changing it
    // takes effect on the NEXT carrier (rotation/reconnect) and never tears
    // down the live one.
    this.edgeIp = edgeIp;
    // NP-1117-27: entry dispersion. `edgeCandidates` is the measured,
    // RTT-ranked candidate list ([{ ip, rttMs }], best first) or null.
    // When a list is active, pool slot i pins candidate i (slots past
    // the end of the list dial by domain), a candidate that fails
    // EDGE_FALLBACK_THRESHOLD consecutive establishments is demoted
    // and its slot re-pins to the best unused healthy candidate, and
    // setEdgeCandidates() with a fresh measurement clears demotions
    // (a re-measured candidate may rise again). When no list is
    // active, every slot uses the single-pin behavior (edgeIp above)
    // exactly as before. The TUN bearer lock overrides all of this:
    // under a lock the dial set is a routing-safety matter.
    this.edgeCandidates = null;
    this._edgeFailCounts = new Map(); // ip -> consecutive establishment failures
    this._edgeDisfavored = new Set(); // demoted ips (until the next refresh)
    this._slotEdge = new Map(); // slotIndex -> ip currently pinned by that slot
    if (edgeCandidates) this.setEdgeCandidates(edgeCandidates);
    // Bearer lock (TUN mode, notes v2 §3 / mandatory change C): while TUN
    // is up, the bearer may ONLY dial IPs from the pinned candidate set
    // (candidate set = exclusion set — every member has a /32 host route
    // around the tunnel). null = unlocked; [] = locked with an empty set,
    // which forbids dialing entirely (fail-closed: default-resolution
    // dialing under TUN would loop the bearer into its own tunnel).
    this.bearerLock = null;
    // The transport factory receives the dial target for THIS attempt
    // (NP-1117-27): an explicit IP string, null for domain resolution,
    // or undefined for "the bridge default" (the single-pin /
    // bearer-lock path). Injected factories may ignore the argument.
    this.makeTransport = makeTransport || (async (dialIp) => {
      const pingMs = 75000 + Math.floor(Math.random() * 75000); // §2-5 randomized keepalive
      const raw = await connectWs(this.workerUrl, { pingIntervalMs: pingMs, edgeIp: dialIp !== undefined ? dialIp : this.effectiveEdgeIp(), userAgent: "HollowClient/0.1" });
      return {
        send: (b) => raw.send(b), close: () => raw.close(), closeCarrier: () => raw.close(),
        onMessage: (cb) => raw.onMessage(cb), onClose: (cb) => raw.onClose(cb),
      };
    });
    this.state = "disconnected"; // disconnected|connecting|connected|reconnecting|error
    this.stateDetail = "";
    this.connectedSince = null;
    this.client = null;
    this.socksServer = null;
    this.socksPort = null;
    this.queuedNow = 0;
    this.failures = 0;
    this._want = false;
    this._loopPromise = null;
    this._wakes = new Set();
    this._listeners = new Set();
    this.stats = { carriers: 0, streams: 0, day: new Date().toISOString().slice(0, 10) };
    // NP-1117-16: the shared session manager owns rotations (15-min
    // timer + the 40-open budget) with drain semantics. This bridge
    // keeps its own connect/backoff/auth policy for the FIRST session
    // of a lineage (the loops below) and hands each established client
    // to the manager; rotations are established through the same
    // _establishClient() and land here via onSwap without the state
    // machine ever leaving "connected".
    // NP-1117-23: the manager is a POOL of independent lineages
    // (striping) — the supervisor runs one lineage loop per slot and
    // the SOCKS layer places each new stream on the least-loaded
    // healthy carrier. this.client is only a representative session.
    this.sessions = new SessionManager({
      establish: (slot) => this._establishClient(slot),
      log: (m) => this.log(m),
      rotationMs: this.rotationMs,
      size: poolSize,
      onSwap: (next) => {
        this.client = next;
        this._rollDay(); this.stats.carriers++;
        this.connectedSince = Date.now();
        this._emit("stats", { stats: { ...this.stats } });
      },
      onLineageEnd: () => {
        // Repoint the representative at any surviving carrier.
        this.client = this.sessions.pick();
      },
    });
    this.poolSize = this.sessions.size;
  }

  // NP-1117-27: replace the ranked candidate list (fresh measurement).
  // A refresh is new health evidence: demotions and failure counts
  // reset, so a candidate that measures well again may rise again.
  // Live carriers are never torn down; new pins apply at each slot's
  // next establishment.
  setEdgeCandidates(list) {
    if (!list || !list.length) {
      this.edgeCandidates = null;
    } else {
      const seen = new Set();
      const out = [];
      for (const c of list) {
        if (c && typeof c.ip === "string" && !seen.has(c.ip)) {
          seen.add(c.ip);
          out.push({ ip: c.ip, rttMs: typeof c.rttMs === "number" ? c.rttMs : null });
        }
      }
      out.sort((a, b) => (a.rttMs ?? Infinity) - (b.rttMs ?? Infinity));
      this.edgeCandidates = out.length ? out : null;
    }
    this._edgeFailCounts.clear();
    this._edgeDisfavored.clear();
    this.log(this.edgeCandidates
      ? `edge candidates ranked: ${this.edgeCandidates.map((c) => `${c.ip}(${c.rttMs ?? "?"}ms)`).join(", ")}`
      : "edge candidates cleared (single-entry behavior)");
  }

  // The candidate pinned for a slot right now, or null when the slot
  // should dial by domain. The primary pin is candidates[slot]; a
  // demoted or already-taken primary falls through to the best-ranked
  // candidate that is healthy and not pinned by another slot; when
  // none qualifies the slot dials by domain (dispatch NP-1117-27 (a)).
  _pickSlotEdge(slotIndex) {
    const list = this.edgeCandidates;
    if (!list || this.bearerLock !== null) return null;
    // A slot past the end of the list has no primary: it dials by
    // domain, never by substitute (dispatch (a): the gap goes domain).
    if (slotIndex >= list.length) return null;
    const usedByOthers = new Set();
    for (const [slot, ip] of this._slotEdge) if (slot !== slotIndex) usedByOthers.add(ip);
    const primary = list[slotIndex];
    if (primary && !this._edgeDisfavored.has(primary.ip) && !usedByOthers.has(primary.ip)) return primary;
    for (const c of list) {
      if (!this._edgeDisfavored.has(c.ip) && !usedByOthers.has(c.ip)) return c;
    }
    return null;
  }

  // NP-1117-27 (b): per-IP health memory on the d3 threshold - an IP
  // whose establishments fail EDGE_FALLBACK_THRESHOLD times in a row
  // (a success resets its count) is demoted until the next refresh.
  _noteEdgeFailure(ip) {
    const n = (this._edgeFailCounts.get(ip) || 0) + 1;
    this._edgeFailCounts.set(ip, n);
    if (n >= EDGE_FALLBACK_THRESHOLD && !this._edgeDisfavored.has(ip)) {
      this._edgeDisfavored.add(ip);
      this.log(`edge ${ip} demoted after ${n} consecutive establishment failures; its slot re-pins at the next attempt`);
    }
  }

  // One establishment path for the loop's first session and for the
  // session manager's rotations (NP-1117-16): TUN bearer lock check,
  // transport, instrumentation, handshake. NP-1117-27: with a ranked
  // candidate list active (and no bearer lock), the dial target is
  // the slot's pinned candidate - or explicit domain when the list
  // has no candidate left for the slot; otherwise the target is left
  // to the bridge default (single pin / bearer lock), as before.
  async _establishClient(slotIndex = -1) {
    if (this.bearerLock !== null && this.bearerLock.length === 0) {
      throw new Error("bearer <redacted> is empty: TUN mode forbids default-resolution dialing (would loop into the tunnel)");
    }
    const dispersed = !!(this.edgeCandidates && this.bearerLock === null);
    const pick = dispersed && slotIndex >= 0 ? this._pickSlotEdge(slotIndex) : null;
    const dialIp = dispersed ? (pick ? pick.ip : null) : undefined;
    // Reserve the pin at pick time, not at success time: concurrent
    // establishments of other slots must already see this slot's IP
    // as taken, or two slots could land on the same entry.
    if (dispersed && slotIndex >= 0) {
      if (pick) this._slotEdge.set(slotIndex, pick.ip);
      else this._slotEdge.delete(slotIndex);
    }
    let client;
    try {
      const transport = await this.makeTransport(dialIp);
      if (!this._want) { try { transport.close(); } catch { /* ignore */ } throw new Error("connect aborted"); }
      client = this._instrument(new HollowClient({ transport, psk: this.psk, keyId: this.keyId }));
      await client.handshake();
    } catch (e) {
      const msg = String(e && e.message || e);
      if (pick && msg !== "connect aborted" && !AUTH_FATAL.test(msg)) this._noteEdgeFailure(pick.ip);
      throw e;
    }
    if (!this._want) { try { client.close(); } catch { /* ignore */ } throw new Error("connect aborted"); }
    if (pick) {
      this._edgeFailCounts.delete(pick.ip);
      this.log(`carrier established: slot ${slotIndex}, entry ${pick.ip}, rtt ${pick.rttMs ?? "?"}ms`);
    } else if (dispersed) {
      this.log(`carrier established: slot ${slotIndex}, entry domain (no candidate for this slot)`);
    }
    return client;
  }

  onEvent(cb) { this._listeners.add(cb); return () => this._listeners.delete(cb); }
  _emit(type, data = {}) {
    const ev = { type, state: this.state, ...data };
    for (const cb of this._listeners) { try { cb(ev); } catch { /* ignore */ } }
  }
  _setState(s, detail = "") {
    this.state = s; this.stateDetail = detail;
    this.log(`state=${s}${detail ? " " + detail : ""}`);
    this._emit("state", { detail });
  }
  _rollDay() {
    const today = new Date().toISOString().slice(0, 10);
    if (this.stats.day !== today) this.stats = { carriers: 0, streams: 0, day: today };
  }

  // Wrap a fresh client: count streams, surface OPEN_QUEUED transitions.
  // NP-1117-12: the queued count is EVENT-driven off client-core's own
  // queue surface (the stream's onQueued callback + the settlement of
  // its `opened` promise), never a poll of s.state. The old 50 ms state
  // poll latched the banner: HollowClient._die() settles a queued
  // stream's promises but never moves s.state out of "queued", so on
  // carrier death/rotation the count was never returned and the banner
  // stayed up for the rest of the session. `opened` settles on EVERY
  // exit — OPEN_OK resolve, OPEN_REJECT reject, carrier death reject —
  // and a local reset() is wrapped to settle the count too.
  _instrument(client) {
    const origOpen = client.openStream.bind(client);
    client.openStream = (opts) => {
      const s = origOpen(opts);
      this._rollDay(); this.stats.streams++;
      this._emit("stats", { stats: { ...this.stats } });
      let counted = false;
      const settle = () => {
        if (!counted) return;
        counted = false;
        this.queuedNow = Math.max(0, this.queuedNow - 1);
        this._emit("queued", { queuedNow: this.queuedNow, active: this.queuedNow > 0 });
      };
      const prevOnQueued = s.onQueued;
      s.onQueued = (info) => {
        if (prevOnQueued) prevOnQueued(info);
        if (!counted) {
          counted = true; this.queuedNow++;
          this.log(`stream ${s.id} queued (server busy)`);
          this._emit("queued", { queuedNow: this.queuedNow, active: true });
        }
      };
      // `opened` may already be settled by the time we attach (it
      // cannot — openStream returns before any frame can arrive — but
      // .then on a settled promise still fires, so this is safe either
      // way). Both branches settle: resolve = established, reject =
      // refused or carrier died mid-queue.
      s.opened.then(settle, settle);
      const origReset = s.reset.bind(s);
      s.reset = (code) => { settle(); origReset(code); };
      return s;
    };
    return client;
  }

  async connect() {
    if (this._want) return;
    this._want = true;
    this.failures = 0;
    this._setState("connecting");
    this._loopPromise = this._runLoop();
  }

  // NP-1117-23: the supervisor runs one lineage loop per pool slot,
  // concurrently. Each loop keeps the pre-pool policy for its own
  // lineage (host establishment, adopt, §8.4 backoff between
  // attempts, edge-IP fallback); the bridge state is "connected"
  // while at least one lineage is healthy and only falls to
  // "reconnecting" when the whole pool is down.
  async _runLoop() {
    const loops = [];
    for (let i = 0; i < this.sessions.size; i++) loops.push(this._lineageLoop(i));
    await Promise.all(loops);
    if (this.state !== "error") this._setState("disconnected");
  }

  async _lineageLoop(slotIndex) {
    while (this._want) {
      let client = null;
      try {
        client = await this._establishClient(slotIndex);
        if (!this.client || this.client.state !== "open") this.client = client;
        this.failures = 0;
        this._rollDay(); this.stats.carriers++;
        if (this.state !== "connected") {
          this.connectedSince = Date.now();
          this._setState("connected");
        }
        this._emit("stats", { stats: { ...this.stats } });
        // NP-1117-16: the session manager now owns this lineage —
        // rotations (15-min + open budget) swap this.client under us
        // via onSwap; adopt() resolves only when the lineage truly
        // ends (the then-current session died with no successor).
        await this.sessions.adopt(client, slotIndex);
        if (this.client === client && client.state === "dead") this.client = this.sessions.pick();
        if (!this._want) break;
        if (this.sessions.healthyCount() === 0) this.log("carrier down; will reconnect");
      } catch (e) {
        if (this.client === client) this.client = null;
        const msg = String(e && e.message || e);
        if (this._want && AUTH_FATAL.test(msg)) {
          // Fatal for every lineage alike (the PSK is shared): stop
          // the whole pool, not just this loop.
          this._want = false;
          this._setState("error", `fatal: ${msg}`);
          this._wakeAll();
          return;
        }
        if (!this._want) break;
        this.log(`carrier attempt failed: ${msg}`);
      }
      if (!this._want) break;
      this.failures++;
      // NP-1117-07 (d3): a pinned edge IP that keeps failing is worse
      // than the default route (some networks refuse direct dials to
      // candidate IPs entirely — the carrier then never comes up and
      // every SOCKS request is refused). After the threshold, fall
      // back to domain resolution for the rest of the session and say
      // so; the dead IP is not retried. TUN bearer locks are exempt:
      // under a lock the dial set is a routing-safety matter, not a
      // preference.
      if (this.failures >= EDGE_FALLBACK_THRESHOLD && this.bearerLock === null
          && this.edgeIp && this._edgeDeadIp !== this.edgeIp) {
        this._edgeDeadIp = this.edgeIp;
        this.edgeIp = null;
        this.log(`edge ip unreachable, fell back to domain (was ${this._edgeDeadIp})`);
      }
      const delay = backoffDelay(this.failures, this.backoffBaseMs, this.backoffCapMs);
      if (this.sessions.healthyCount() === 0) {
        this.connectedSince = null;
        if (this.state !== "reconnecting") {
          this._setState("reconnecting", `attempt ${this.failures}, next in ${delay}ms`);
        }
      }
      await this._sleep(delay);
    }
  }

  _sleep(ms) {
    return new Promise((res) => {
      const wake = () => { clearTimeout(timer); this._wakes.delete(wake); res(); };
      const timer = setTimeout(wake, ms);
      timer.unref?.();
      this._wakes.add(wake);
    });
  }
  _wakeAll() { for (const w of [...this._wakes]) w(); }

  // SOCKS entry lifecycle (plan §2): default port, increment while occupied.
  async startSocks(preferredPort = 1080, host = "127.0.0.1") {
    if (this.socksServer) return this.socksPort;
    let lastErr = null;
    for (let port = preferredPort; port < preferredPort + 20; port++) {
      try {
        const server = await startSocks({
          getClient: (exclude) => (this.state === "connected" ? this.sessions.pick(exclude) : null),
          host, port, log: (m) => this.log(`socks: ${m}`),
          openHooks: { onOutboundExhausted: (c) => this.sessions.noteOutboundFailure(c) },
        });
        this.socksServer = server;
        this.socksPort = port;
        this.log(`socks5 listening on ${host}:${port}`);
        this._emit("socks", { socksPort: port });
        return port;
      } catch (e) {
        if (e && e.code === "EADDRINUSE") { lastErr = e; continue; }
        throw e;
      }
    }
    throw lastErr || new Error("no free port for socks");
  }
  async stopSocks() {
    if (this.socksServer) {
      const s = this.socksServer; this.socksServer = null; this.socksPort = null;
      // server.close() waits for live SOCKS sessions to drain; cap the wait —
      // on app exit the process takes the port down regardless.
      await Promise.race([
        new Promise((res) => { try { s.close(() => res()); } catch { res(); } }),
        new Promise((res) => setTimeout(res, 1500)),
      ]);
      this.log("socks5 stopped");
      this._emit("socks", { socksPort: null });
    }
  }

  async disconnect() {
    this._want = false;
    this._wakeAll();
    this.sessions.stop();
    await this.stopSocks();
    if (this.client) { try { this.client.close(); } catch { /* ignore */ } this.client = null; }
    if (this._loopPromise) { try { await this._loopPromise; } catch { /* ignore */ } this._loopPromise = null; }
    this.connectedSince = null;
    if (this.state !== "disconnected") this._setState("disconnected");
  }

  setEdgeIp(ip) {
    this.edgeIp = ip || null;
    this.log(ip ? `edge ip selected: ${ip} (applies to the next carrier)` : "edge ip: default resolution");
  }
  // Engage/release the TUN bearer lock. ips is the pinned candidate set
  // (already /32-excluded by the helper before this is called — spec R5
  // sequencing lives with the caller).
  setBearerLock(ips) {
    this.bearerLock = ips === null ? null : [...new Set(ips)];
    this.log(this.bearerLock === null
      ? "bearer lock released"
      : `bearer lock engaged: [${this.bearerLock.join(", ")}] (dial ip now ${this.effectiveEdgeIp() ?? "NONE — dialing forbidden"})`);
  }
  // The IP the next carrier will actually dial.
  effectiveEdgeIp() {
    if (this.bearerLock === null) return this.edgeIp;
    if (this.bearerLock.length === 0) return null;
    return this.bearerLock.includes(this.edgeIp) ? this.edgeIp : this.bearerLock[0];
  }
  snapshot() {
    return {
      state: this.state, detail: this.stateDetail,
      connectedSince: this.connectedSince,
      socksPort: this.socksPort, queuedNow: this.queuedNow,
      liveCarriers: this.sessions.healthyCount(), poolSize: this.poolSize,
      edgeIp: this.edgeIp,
      slotEdges: Object.fromEntries(this._slotEdge),
      edgeCandidates: this.edgeCandidates ? this.edgeCandidates.map((c) => c.ip) : null,
      effectiveEdgeIp: this.effectiveEdgeIp(),
      bearerLock: this.bearerLock === null ? null : [...this.bearerLock],
      stats: { ...this.stats },
    };
  }
}
