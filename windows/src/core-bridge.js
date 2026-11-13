// Core bridge (M2-1, NP-1114-03): owns the M1-verified HollowClient inside
// the app — connection state machine, §8.4 reconnect backoff and 15-minute
// carrier rotation mirroring `cli serve` semantics, the SOCKS5 entry
// lifecycle, stream/carrier counters and the OPEN_QUEUED event surface.
// The one deliberate addition over the CLI: auth-class handshake failures
// (wrong PSK and friends) are fatal — they stop in the Error state instead
// of retrying forever (plan §4). Electron-free: tests drive this module
// directly with an injected transport factory.
import { HollowClient } from "../vendor/shared/client-core.js";
import { connectWs } from "../vendor/cli/src/ws-client.js";
import { startSocks } from "../vendor/cli/src/socks.js";

const AUTH_FATAL = /undecryptable|server hello rejected|finished|verifier/i;
export const ROTATION_MS = 15 * 60 * 1000; // spec §5.6

export function backoffDelay(failures, baseMs = 1000, capMs = 60000, rnd = Math.random) {
  // spec §8.4 as implemented by the CLI: 1s doubling to a 60s cap, ±25% jitter.
  const base = Math.min(capMs, baseMs * 2 ** Math.min(Math.max(failures - 1, 0), 6));
  return Math.round(base * (1 + (rnd() * 0.5 - 0.25)));
}

export class CoreBridge {
  constructor({ workerUrl, psk, keyId = 1, log = () => {}, makeTransport = null, rotationMs = ROTATION_MS, backoffBaseMs = 1000, backoffCapMs = 60000, edgeIp = null }) {
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
    // Bearer lock (TUN mode, notes v2 §3 / mandatory change C): while TUN
    // is up, the bearer may ONLY dial IPs from the pinned candidate set
    // (candidate set = exclusion set — every member has a /32 host route
    // around the tunnel). null = unlocked; [] = locked with an empty set,
    // which forbids dialing entirely (fail-closed: default-resolution
    // dialing under TUN would loop the bearer into its own tunnel).
    this.bearerLock = null;
    this.makeTransport = makeTransport || (async () => {
      const pingMs = 75000 + Math.floor(Math.random() * 75000); // §2-5 randomized keepalive
      const raw = await connectWs(this.workerUrl, { pingIntervalMs: pingMs, edgeIp: this.effectiveEdgeIp(), userAgent: "HollowClient/0.1" });
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
    this._wake = null;
    this._listeners = new Set();
    this.stats = { carriers: 0, streams: 0, day: new Date().toISOString().slice(0, 10) };
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
  _instrument(client) {
    const origOpen = client.openStream.bind(client);
    client.openStream = (opts) => {
      const s = origOpen(opts);
      this._rollDay(); this.stats.streams++;
      this._emit("stats", { stats: { ...this.stats } });
      let counted = false;
      const iv = setInterval(() => {
        if (s.state === "queued" && !counted) {
          counted = true; this.queuedNow++;
          this.log(`stream ${s.id} queued (server busy)`);
          this._emit("queued", { queuedNow: this.queuedNow, active: true });
        } else if (s.state !== "queued" && counted) {
          counted = false; this.queuedNow = Math.max(0, this.queuedNow - 1);
          this._emit("queued", { queuedNow: this.queuedNow, active: this.queuedNow > 0 });
          clearInterval(iv);
        } else if (["rejected", "closed", "reset", "failed"].includes(s.state)) {
          clearInterval(iv);
        }
      }, 50);
      iv.unref?.();
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

  async _runLoop() {
    while (this._want) {
      let client = null;
      try {
        if (this.bearerLock !== null && this.bearerLock.length === 0) {
          throw new Error("bearer lock is empty: TUN mode forbids default-resolution dialing (would loop into the tunnel)");
        }
        const transport = await this.makeTransport();
        if (!this._want) { try { transport.close(); } catch { /* ignore */ } break; }
        client = this._instrument(new HollowClient({ transport, psk: this.psk, keyId: this.keyId }));
        this.client = client;
        await client.handshake();
        if (!this._want) { try { client.close(); } catch { /* ignore */ } break; }
        this.failures = 0;
        this._rollDay(); this.stats.carriers++;
        this.connectedSince = Date.now();
        this._setState("connected");
        this._emit("stats", { stats: { ...this.stats } });
        const rotate = setTimeout(() => { this.log("carrier rotation (15 min)"); try { client.close(); } catch { /* ignore */ } }, this.rotationMs);
        rotate.unref?.();
        await new Promise((res) => { client.onCarrierDead = () => res(); });
        clearTimeout(rotate);
        this.connectedSince = null;
        if (this.client === client) this.client = null;
        if (!this._want) break;
        this.log("carrier down; will reconnect");
      } catch (e) {
        if (this.client === client) this.client = null;
        this.connectedSince = null;
        const msg = String(e && e.message || e);
        if (this._want && AUTH_FATAL.test(msg)) {
          this._want = false;
          this._setState("error", `fatal: ${msg}`);
          return;
        }
        if (!this._want) break;
        this.log(`carrier attempt failed: ${msg}`);
      }
      if (!this._want) break;
      this.failures++;
      const delay = backoffDelay(this.failures, this.backoffBaseMs, this.backoffCapMs);
      this._setState("reconnecting", `attempt ${this.failures}, next in ${delay}ms`);
      await new Promise((res) => { this._wake = res; setTimeout(res, delay).unref?.(); });
      this._wake = null;
    }
    if (this.state !== "error") this._setState("disconnected");
  }

  // SOCKS entry lifecycle (plan §2): default port, increment while occupied.
  async startSocks(preferredPort = 1080, host = "127.0.0.1") {
    if (this.socksServer) return this.socksPort;
    let lastErr = null;
    for (let port = preferredPort; port < preferredPort + 20; port++) {
      try {
        const server = await startSocks({
          getClient: () => (this.state === "connected" ? this.client : null),
          host, port, log: (m) => this.log(`socks: ${m}`),
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
    if (this._wake) { const w = this._wake; this._wake = null; w(); }
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
      edgeIp: this.edgeIp,
      effectiveEdgeIp: this.effectiveEdgeIp(),
      bearerLock: this.bearerLock === null ? null : [...this.bearerLock],
      stats: { ...this.stats },
    };
  }
}
