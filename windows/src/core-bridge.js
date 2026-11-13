// Core bridge (NP-1114-01 skeleton): owns the M1-verified HollowClient, the
// SOCKS5 entry (vendored cli modules) and the connection state machine the
// UI renders (plan §4). Electron-free: the headless smoke uses this module
// directly under plain Node.
import { HollowClient } from "../vendor/shared/client-core.js";
import { connectWs } from "../vendor/cli/src/ws-client.js";
import { startSocks } from "../vendor/cli/src/socks.js";

export class CoreBridge {
  constructor({ workerUrl, psk, keyId = 1, log = () => {} }) {
    this.workerUrl = workerUrl;
    this.psk = psk;
    this.keyId = keyId;
    this.log = log;
    this.state = "disconnected"; // disconnected|connecting|connected|reconnecting|error
    this.client = null;
    this.socks = null;
    this.socksPort = null;
    this.listeners = new Set();
    this.stats = { carriers: 0, streams: 0, day: new Date().toISOString().slice(0, 10) };
  }
  onState(cb) { this.listeners.add(cb); return () => this.listeners.delete(cb); }
  _setState(s, detail = "") {
    this.state = s;
    for (const cb of this.listeners) { try { cb(s, detail); } catch { /* ignore */ } }
    this.log(`state=${s}${detail ? " " + detail : ""}`);
  }
  _rollDay() {
    const today = new Date().toISOString().slice(0, 10);
    if (this.stats.day !== today) this.stats = { carriers: 0, streams: 0, day: today };
  }
  async _openCarrier() {
    const raw = await connectWs(this.workerUrl);
    const transport = {
      send: (b) => raw.send(b), close: () => raw.close(), closeCarrier: () => raw.close(),
      onMessage: (cb) => raw.onMessage(cb), onClose: (cb) => raw.onClose(cb),
    };
    const client = new HollowClient({ transport, psk: this.psk, keyId: this.keyId });
    client.onCarrierDead = (reason) => this.log(`carrier dead: ${reason}`);
    await client.handshake();
    this._rollDay();
    this.stats.carriers++;
    return client;
  }
  async connect() {
    if (this.state === "connected" || this.state === "connecting") return;
    this._setState("connecting");
    try {
      this.client = await this._openCarrier();
      this._setState("connected");
    } catch (e) {
      this._setState("error", String(e && e.message || e));
      throw e;
    }
  }
  // Start the local SOCKS5 entry bound to the live client (plan §2).
  async startSocks(port) {
    if (!this.client) throw new Error("not connected");
    if (this.socks) return this.socksPort;
    const client = this.client;
    this.socks = startSocks({
      getClient: () => (this.client === client && this.state === "connected" ? client : null),
      port,
      log: (m) => this.log(`socks: ${m}`),
    });
    this.socksPort = port;
    return port;
  }
  async disconnect() {
    if (this.socks) { try { this.socks.close(); } catch { /* ignore */ } this.socks = null; this.socksPort = null; }
    if (this.client) { try { this.client.close(); } catch { /* ignore */ } this.client = null; }
    this._setState("disconnected");
  }
  snapshot() {
    return { state: this.state, socksPort: this.socksPort, stats: { ...this.stats } };
  }
}
