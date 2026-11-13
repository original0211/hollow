// App-side client for the TUN helper's named-pipe protocol (T-4 wiring).
// NDJSON frames, the exact wire shape of the helper's ipc.Frame:
//   request:  {id, verb, params}
//   reply:    {id, ok, error?, result?}
//   event:    {event:"heartbeat", seq, uptimeMs}
// The transport is injectable (production: net.createConnection to the
// pipe; tests: an in-memory pair). Heartbeats are surfaced via
// onHeartbeat(seq) — main feeds them to HelperWatch; request timeouts
// and pipe closes reject, they never hang silently.

import net from "node:net";

export const HELPER_PIPE_PATH = "\\\\.\\pipe\\hollow-tun-helper";

export class HelperClient {
  constructor({ connect, onHeartbeat, onClose, log } = {}) {
    this._connect = connect ?? (() => net.createConnection(HELPER_PIPE_PATH));
    this.onHeartbeat = onHeartbeat ?? (() => {});
    this.onClose = onClose ?? (() => {});
    this.log = log ?? (() => {});
    this.sock = null;
    this.buf = "";
    this.nextId = 0;
    this.pending = new Map();
  }

  get connected() { return this.sock !== null; }

  async connect() {
    if (this.sock) return;
    const sock = this._connect();
    this.sock = sock;
    sock.setEncoding("utf8");
    sock.on("data", (chunk) => this._onData(chunk));
    sock.on("error", (e) => { this.log(`helper pipe error: ${e.message}`); this._teardown(); });
    sock.on("close", () => this._teardown());
    if (sock.connecting) {
      await new Promise((resolve, reject) => {
        sock.once("connect", resolve);
        sock.once("error", reject);
      });
    }
  }

  _teardown() {
    const was = this.sock;
    this.sock = null;
    for (const [, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(new Error("helper pipe closed"));
    }
    this.pending.clear();
    if (was) this.onClose();
  }

  _onData(chunk) {
    this.buf += chunk;
    let idx;
    while ((idx = this.buf.indexOf("\n")) >= 0) {
      const line = this.buf.slice(0, idx).trim();
      this.buf = this.buf.slice(idx + 1);
      if (!line) continue;
      let frame;
      try { frame = JSON.parse(line); } catch { continue; }
      if (frame.event === "heartbeat") { this.onHeartbeat(frame.seq ?? 0); continue; }
      if (frame.id && this.pending.has(frame.id)) {
        const p = this.pending.get(frame.id);
        this.pending.delete(frame.id);
        clearTimeout(p.timer);
        if (frame.ok) p.resolve(frame);
        else p.reject(new Error(frame.error || `helper verb failed`));
      }
    }
  }

  request(verb, params = null, timeoutMs = 5000) {
    if (!this.sock) return Promise.reject(new Error("helper not connected"));
    const id = ++this.nextId;
    const frame = { id, verb, ...(params ? { params } : {}) };
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`helper ${verb} timed out (${timeoutMs}ms)`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.sock.write(JSON.stringify(frame) + "\n", (err) => {
        if (err) {
          this.pending.delete(id);
          clearTimeout(timer);
          reject(err);
        }
      });
    });
  }

  async ping(timeoutMs = 2000) {
    try { await this.request("ping", null, timeoutMs); return true; }
    catch { return false; }
  }

  close() {
    if (this.sock) { try { this.sock.destroy(); } catch { /* ignore */ } this._teardown(); }
  }
}
