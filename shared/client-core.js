// Hollow client session core (spec v0.1 §4, §5, §6, §7.5 client side).
// Transport-agnostic: transport = { send(bytes), close(), onMessage, onClose }
// carrying raw WebSocket messages (hello plaintext, then AEAD records).
import { randomBytes, x25519Generate, x25519Derive, AeadUnavailableError, X25519UnavailableError } from "./crypto.js";
import {
  PROTO_VERSION, FT, ERR, GATE, BUCKETS,
  CONN_WINDOW_INIT, STREAM_WINDOW_INIT, CONN_WINDOW_GRANT, STREAM_WINDOW_GRANT,
  MERGE_WINDOW_MS, MAX_PAYLOAD,
  buildClientHello, parseServerHello, deriveVerifier, deriveSession,
  finishedMac, buildFrame, parseFrames, sealRecords, RecordReceiver,
  buildOpenPayload, eq, RecordSender,
} from "./protocol.js";


export class ClientStream {
  constructor(client, id) {
    this.client = client; this.id = id;
    this.state = "opening"; // opening | queued | open | rejected | closed | reset | failed
    this.gate = null;
    this.pending = []; // Uint8Array chunks awaiting send window
    this.sendWindow = STREAM_WINDOW_INIT;
    // §6.5 v0.2.1: credit we grant the server is our GRANT target (the
    // server learns it via our top-up WINDOW_UPDATE at stream creation;
    // its send side still starts from STREAM_WINDOW_INIT).
    this.recvWindow = client.streamWindowGrant;
    this.recvUnacked = 0; // bytes delivered to app, not yet window-updated
    this.localClosed = false; // we sent CLOSE
    this.remoteClosed = false; // peer sent CLOSE
    this.paused = false;
    this.pendingBytes = 0; // NP-1118-66 (S4): bytes held in pending
    this.onOpenOk = null; this.onQueued = null; this.onReject = null;
    this.onData = null; this.onEnd = null; this.onReset = null; this.onFail = null;
    this._openResolve = null; this._openReject = null;
    this._openTimer = null; // NP-1118-54: local OPEN-answer bound
  }
  write(data) {
    if (this.state !== "open" && this.state !== "opening" && this.state !== "queued") return false;
    const buf = new Uint8Array(data);
    // NP-1118-66 (S4): the pending queue is capped. Overflow is a
    // stream-level failure (onFail + RESET), and write reports
    // the refusal — it must never accept data it then holds
    // without bound.
    const cap = this.client.streamPendingMaxBytes;
    if (cap && this.pendingBytes + buf.length > cap) {
      this.client._failPendingOverflow(this);
      return false;
    }
    this.pending.push(buf);
    this.pendingBytes += buf.length;
    this.client._pumpStream(this);
    return true;
  }
  closeWrite() {
    if (this.localClosed || this.closePending) return;
    // CLOSE is stream-ordered: it must not overtake DATA still queued in the
    // app-level pending buffer. Defer until the pump has framed everything.
    this.closePending = true;
    if (this.pending.length === 0) this.client._sendCloseFrame(this);
  }
  reset(code = 0x00) {
    this.client._sendFrame(buildFrame(FT.RESET, this.id,
      new Uint8Array([code, 0, 0])), true);
    this.state = "reset";
    this.client._forgetStream(this);
  }
  // App signals it has consumed n bytes (default: auto on delivery when not paused)
  consume(n) {
    this.client._onConsume(this, n);
  }
}

// NP-1117-16 (plan A, Brody-approved): the platform caps a session at
// roughly 50 outbound establishments — past it, every OPEN is refused
// 0x06 while the session otherwise looks alive (measured on a real
// browser, 2026-11-17: stream 51+ all 0x06, a fresh session is fine).
// The client therefore counts the OPENs it has SENT on this session
// and the session layer rotates proactively at 40 — a safety margin
// under the measured cap — so the cap is never user-visible.
export const SESSION_OPEN_HARD_CAP = 50; // measured platform ceiling (approx.)
export const SESSION_ROTATE_THRESHOLD = 40; // rotate here; margin = 10
// NP-1118-54: local bound on the OPEN answer (§10.2 local parameter,
// no wire change). Neither the client nor the server's establishing
// phase had any timer: an OPEN whose egress connect never settles
// hung the stream until the whole carrier died (NP-1118-52
// assessment). 20 s sits far above every measured legitimate OPEN
// answer (queue guarantee 5 s + egress connect + several
// worst-grade RTTs) and matches the NP-1118-49 establishment
// budget family. 0/null disables (rollback switch).
export const OPEN_TIMEOUT_MS = 20000;
// NP-1118-66 (S4): per-stream cap on app data queued behind a
// peer that has stopped granting window. The stream's granted
// send window tops out at the 1 MiB v0.2.1 grant target; a queue
// four times that means the application is 4 MiB ahead of a peer
// that has granted everything it will — the stream is dead in
// practice, and the queue must fail the stream instead of
// growing memory without bound while write() keeps reporting
// success.
export const STREAM_PENDING_MAX_BYTES = 4 * 1024 * 1024;

export class HollowClient {
  constructor({ transport, psk, keyId = 1, streamWindowGrant = STREAM_WINDOW_GRANT, connWindowGrant = CONN_WINDOW_GRANT, openTimeoutMs = OPEN_TIMEOUT_MS, streamPendingMaxBytes = STREAM_PENDING_MAX_BYTES }) {
    this.transport = transport;
    this.psk = psk; this.keyId = keyId;
    // §6.5 v0.2.1 (NP-1117-25): receiver grant targets. Passing the
    // INIT values reproduces pre-v0.2.1 behavior exactly (top-up is 0),
    // which is also the per-endpoint rollback switch.
    this.streamWindowGrant = streamWindowGrant;
    this.connWindowGrant = connWindowGrant;
    this.openTimeoutMs = openTimeoutMs; // NP-1118-54 (0/null = disabled)
    this.streamPendingMaxBytes = streamPendingMaxBytes; // NP-1118-66 S4 (0/null = disabled)
    this.halfStream = streamWindowGrant / 2;
    this.halfConn = connWindowGrant / 2;
    this.state = "idle"; // idle | hello | wait-finished | open | dead
    // NP-1117-16: outbound budget bookkeeping (see constants above).
    this.opensSent = 0; // OPEN frames sent on THIS session
    this.budgetExhausted = false; // set when the session is retired to drain
    this.onOpenThreshold = null; // fired once when opensSent hits the threshold
    this.failReason = null;
    this.streams = new Map();
    this.nextStreamId = 1;
    this.sender = null; this.receiver = null;
    this.connSendWindow = CONN_WINDOW_INIT;
    this.connRecvWindow = connWindowGrant;
    this.connRecvUnacked = 0;
    this.streamErrors = 0;
    this.wireSizes = []; // observed WS message sizes (records + hello), for F-8
    this._hsResolve = null; this._hsReject = null;
    this._th = null; this._keys = null;
    this.onCarrierDead = null;
    this.onGoAway = null; // NP-1118-66 (S3): fired once when the server sends GOAWAY
    // Serialize message handling (async crypto in handshake steps; wire order
    // must be observed even for back-to-back messages).
    this._chain = Promise.resolve();
    transport.onMessage((bytes) => {
      this._chain = this._chain.then(() => this._onMessage(bytes));
    });
    transport.onClose(() => this._die("carrier closed"));
  }

  async handshake() {
    if (this.state !== "idle") throw new Error("bad state");
    this.state = "hello";
    const done = new Promise((res, rej) => { this._hsResolve = res; this._hsReject = rej; });
    let kp;
    try {
      kp = await x25519Generate();
    } catch (e) {
      // NP-1117-06: capability missing is not a key failure.
      if (e instanceof X25519UnavailableError) this._die("X25519 unavailable in this runtime (WebCrypto)");
      throw e;
    }
    this._eph = kp;
    this._clientRandom = randomBytes(32);
    const padding = randomBytes(Math.floor(Math.random() * 129));
    this._clientHello = buildClientHello({
      versions: [PROTO_VERSION], keyId: this.keyId,
      publicRaw: kp.publicRaw, random: this._clientRandom, padding,
    });
    this.transport.send(this._clientHello);
    return done;
  }

  _die(reason) {
    if (this.state === "dead") return;
    this.state = "dead"; this.failReason = reason;
    if (this._hsReject) { this._hsReject(new Error(reason)); this._hsReject = null; }
    for (const s of this.streams.values()) {
      if (s._openTimer) { clearTimeout(s._openTimer); s._openTimer = null; }
      if (s.onFail) s.onFail(reason);
      if (s._openReject) s._openReject(new Error(reason));
    }
    this.streams.clear();
    if (this.onCarrierDead) this.onCarrierDead(reason);
  }

  async _onMessage(bytes) {
    this.wireSizes.push(bytes.length);
    try {
      if (this.state === "hello") return await this._onServerHello(bytes);
      if (this.state === "wait-finished") return await this._onServerFinished(bytes);
      if (this.state === "open") return this._onRecord(bytes);
      if (this.state === "idle") return; // stray
    } catch (e) {
      this._die("local error: " + (e && e.message || e));
      try { this.transport.close(); } catch {}
    }
  }

  async _onServerHello(bytes) {
    const sh = parseServerHello(bytes);
    if (!sh || sh.selectedVersion !== PROTO_VERSION) {
      this._die("server hello rejected");
      try { this.transport.close(); } catch {}
      return;
    }
    this._serverHello = bytes;
    let dh;
    try {
      dh = await x25519Derive(this._eph.privateKey, sh.publicRaw);
    } catch (e) {
      // NP-1117-06: capability missing is not a key failure.
      if (e instanceof X25519UnavailableError) { this._die("X25519 unavailable in this runtime (WebCrypto)"); try { this.transport.close(); } catch {} return; }
      throw e;
    }
    if (!dh) { this._die("x25519 failed"); try { this.transport.close(); } catch {} return; }
    const verifier = await deriveVerifier(this.psk);
    const keys = await deriveSession({
      dh, verifier,
      clientRandom: this._clientRandom, serverRandom: sh.random,
      clientHello: this._clientHello, serverHello: bytes,
    });
    this._keys = keys; this._th = keys.th;
    this.sender = new RecordSender(keys.kC2s, keys.ivC2s, (b) => {
      this.lastSentRecord = b; // kept for replay-negative testing (F-4)
      this.transport.send(b);
    });
    this.receiver = new RecordReceiver(keys.kS2c, keys.ivS2c);
    this.state = "wait-finished";
  }

  async _onServerFinished(bytes) {
    let opened;
    try {
      opened = this.receiver.open(bytes);
    } catch (e) {
      // NP-1117-04: capability missing is not an authentication failure.
      if (e instanceof AeadUnavailableError) { this._die("chacha20-poly1305 AEAD unavailable in this runtime"); try { this.transport.close(); } catch {} return; }
      throw e;
    }
    if (!opened) { this._die("server finished record undecryptable"); try { this.transport.close(); } catch {} return; }
    const parsed = parseFrames(opened.framesBlob);
    const f = parsed.frames[0];
    const expect = await finishedMac(this._keys.fS, this._th, "server");
    if (parsed.recordError || parsed.frames.length !== 1 || !f ||
        f.type !== FT.FINISH || f.streamId !== 0 || !eq(f.payload, expect)) {
      this._die("server finished mismatch");
      try { this.transport.close(); } catch {}
      return;
    }
    // verify complete: send client Finished (c2s seq=0 via sender)
    const mac = await finishedMac(this._keys.fC, this._th, "client");
    this.sender.push(buildFrame(FT.FINISH, 0, mac), true);
    this.state = "open";
    // §6.5 v0.2.1: top up the server's connection window from the
    // legacy INIT to our grant target (a pre-v0.2.1 server just sees
    // extra credit arrive; its own accounting is unaffected).
    this._topUp(0, this.connWindowGrant - CONN_WINDOW_INIT);
    if (this._hsResolve) { this._hsResolve(); this._hsResolve = null; }
  }

  _sendFrame(frameBytes, immediate) {
    if (this.sender) this.sender.push(frameBytes, immediate);
  }

  _sendWindowUpdate(streamId, inc) {
    const p = new Uint8Array(4);
    new DataView(p.buffer).setUint32(0, inc);
    this._sendFrame(buildFrame(FT.WINDOW_UPDATE, streamId, p), true);
  }

  // §6.5 v0.2.1: express the difference between the legacy INIT
  // window (all a pre-v0.2.1 sender assumes) and our grant target as
  // an explicit WINDOW_UPDATE. Zero/negative differences send nothing,
  // which is exactly the legacy behavior.
  _topUp(streamId, inc) {
    if (inc > 0) this._sendWindowUpdate(streamId, inc);
  }

  openStream({ host, port, schemeHint = 0, gatePolicy = 0 }) {
    if (this.state !== "open") throw new Error("session not open");
    if (this.goAway) {
      // NP-1118-66 (S3): the server has told this session to wind
      // down — refuse the stream locally (nothing is sent, no id
      // is consumed) and let the host's rotation (onGoAway) move
      // later streams onto a fresh carrier. Existing streams are
      // untouched and drain on this carrier.
      const s = new ClientStream(this, 0);
      s.state = "failed";
      s.opened = new Promise((res, rej) => { s._openResolve = res; s._openReject = rej; });
      const err = new Error("session going away (GOAWAY received)");
      queueMicrotask(() => {
        if (s._openReject) { s._openReject(err); s._openReject = null; }
        if (s.onFail) s.onFail("session going away");
      });
      return s;
    }
    const id = this.nextStreamId; this.nextStreamId += 2;
    const s = new ClientStream(this, id);
    this.streams.set(id, s);
    const payload = buildOpenPayload({ host, port, schemeHint, gatePolicy });
    this._sendFrame(buildFrame(FT.OPEN, id, payload), true);
    // §6.5 v0.2.1: top up the server's per-stream window for the
    // return direction (rides right behind OPEN on the same carrier;
    // the record sender's FIFO order is preserved).
    this._topUp(id, this.streamWindowGrant - STREAM_WINDOW_INIT);
    // NP-1117-16: the OPEN is on the wire — count it (retries included:
    // every re-OPEN consumes budget exactly like a first attempt).
    this.opensSent++;
    if (this.opensSent === SESSION_ROTATE_THRESHOLD && this.onOpenThreshold) {
      try { this.onOpenThreshold(); } catch { /* the session layer's problem, not the stream's */ }
    }
    s.opened = new Promise((res, rej) => { s._openResolve = res; s._openReject = rej; });
    // NP-1118-54: arm the OPEN-answer bound. OPEN_QUEUED does NOT
    // clear it (the queue has its own 5 s server guarantee; if that
    // frame is lost this bound is the backstop). OPEN_OK /
    // OPEN_REJECT / RESET / carrier death clear it via
    // _forgetStream / _die.
    if (this.openTimeoutMs) {
      s._openTimer = setTimeout(() => this._onOpenTimeout(s), this.openTimeoutMs);
      if (s._openTimer.unref) s._openTimer.unref();
    }
    return s;
  }

  // NP-1118-54: the bound expired with no OPEN_OK / OPEN_REJECT.
  // Stream-local failure only: reject `opened`, fire onFail, and
  // RESET the stream (which also cancels a queued OPEN and frees
  // the server-side bookkeeping). The error's code is
  // ERR.STREAM_TIMEOUT — deliberately neither 0x01 nor 0x06, so
  // openWithRetry surfaces it as an ordinary non-retryable failure.
  _onOpenTimeout(s) {
    s._openTimer = null;
    if (this.streams.get(s.id) !== s) return;
    if (s.state !== "opening" && s.state !== "queued") return;
    s.state = "failed";
    if (s._openReject) {
      const e = new Error("open timed out after " + this.openTimeoutMs + "ms");
      e.code = ERR.STREAM_TIMEOUT;
      s._openReject(e); s._openReject = null;
    }
    if (s.onFail) s.onFail("open timed out");
    this._sendFrame(buildFrame(FT.RESET, s.id,
      new Uint8Array([ERR.STREAM_TIMEOUT, 0, 0])), true);
    this._forgetStream(s);
  }

  // NP-1118-66 (S4): the pending cap tripped. Same closure shape as
  // the OPEN bound: stream-local failure, onFail, a RESET to free
  // the server-side bookkeeping, and the stream is forgotten.
  _failPendingOverflow(s) {
    if (!this.streams.has(s.id)) return;
    s.state = "failed";
    if (s._openReject) {
      const e = new Error("send queue overflow (pending cap)");
      s._openReject(e); s._openReject = null;
    }
    if (s.onFail) s.onFail("send queue overflow");
    this._sendFrame(buildFrame(FT.RESET, s.id,
      new Uint8Array([0x00, 0, 0])), true);
    this._forgetStream(s);
  }

  _pumpStream(s) {
    while (s.pending.length > 0 && (s.state === "open")) {
      const avail = Math.min(s.sendWindow, this.connSendWindow);
      if (avail <= 0) return;
      const head = s.pending[0];
      const take = Math.min(head.length, avail, MAX_PAYLOAD);
      const chunk = head.subarray(0, take);
      if (take === head.length) s.pending.shift();
      else s.pending[0] = head.subarray(take);
      s.pendingBytes -= take;
      s.sendWindow -= take; this.connSendWindow -= take;
      this._sendFrame(buildFrame(FT.DATA, s.id, chunk), false);
    }
    if (s.pending.length === 0) {
      if (s.closePending && !s.localClosed) this._sendCloseFrame(s);
      if (s.onDrain) s.onDrain();
    }
  }

  _sendCloseFrame(s) {
    s.localClosed = true;
    s.closePending = false;
    this._sendFrame(buildFrame(FT.CLOSE, s.id, new Uint8Array([0x00])), true);
    this._maybeFreeStream(s);
  }

  _onConsume(s, n) {
    // §6.5: WINDOW_UPDATE when accumulated consumption >= half the window,
    // per-stream and connection level independently.
    s.recvUnacked += n;
    if (s.recvUnacked >= this.halfStream) {
      const inc = s.recvUnacked; s.recvUnacked = 0; s.recvWindow += inc;
      const p = new Uint8Array(4);
      new DataView(p.buffer).setUint32(0, inc);
      this._sendFrame(buildFrame(FT.WINDOW_UPDATE, s.id, p), true);
    }
    this.connRecvUnacked += n;
    if (this.connRecvUnacked >= this.halfConn) {
      const inc = this.connRecvUnacked; this.connRecvUnacked = 0; this.connRecvWindow += inc;
      const p = new Uint8Array(4);
      new DataView(p.buffer).setUint32(0, inc);
      this._sendFrame(buildFrame(FT.WINDOW_UPDATE, 0, p), true);
    }
  }

  _onRecord(bytes) {
    let opened;
    try {
      opened = this.receiver.open(bytes);
    } catch (e) {
      // NP-1117-04: capability missing is not a record failure.
      if (e instanceof AeadUnavailableError) { this._die("chacha20-poly1305 AEAD unavailable in this runtime"); try { this.transport.close(); } catch {} return; }
      throw e;
    }
    if (!opened) {
      if (this.receiver.consecFails >= 3) { this._die("record failure limit"); try { this.transport.close(); } catch {} }
      return;
    }
    const parsed = parseFrames(opened.framesBlob);
    if (parsed.recordError) {
      // frames not exactly exhausting frames_len = record-level failure (§6.1)
      this.receiver.noteFailure();
      if (this.receiver.consecFails >= 3) { this._die("record failure limit"); try { this.transport.close(); } catch {} }
      return;
    }
    this.receiver.noteSuccess();
    for (const os of parsed.oversize) {
      const s = this.streams.get(os.streamId);
      if (s) { s.state = "reset"; if (s.onReset) s.onReset(ERR.PROTOCOL_ERROR); this._forgetStream(s); }
    }
    for (const f of parsed.frames) this._dispatch(f);
  }

  _dispatch(f) {
    const s = this.streams.get(f.streamId);
    switch (f.type) {
      case FT.OPEN_OK: {
        if (!s) return;
        s.gate = f.payload[0];
        s.state = "open";
        if (s.onOpenOk) s.onOpenOk(s.gate);
        if (s._openResolve) { s._openResolve(s.gate); s._openResolve = null; }
        this._pumpStream(s);
        break;
      }
      case FT.OPEN_QUEUED: {
        if (!s) return;
        s.state = "queued";
        const info = {
          position: (f.payload[0] << 8) | f.payload[1],
          estWaitMs: (f.payload[2] << 8) | f.payload[3],
          maxWaitMs: (f.payload[4] << 8) | f.payload[5],
        };
        s.queuedInfo = info;
        if (s.onQueued) s.onQueued(info);
        break;
      }
      case FT.OPEN_REJECT: {
        if (!s) return;
        s.state = "rejected";
        const code = f.payload[0];
        const retryAfterMs = (f.payload[1] << 8) | f.payload[2];
        if (s.onReject) s.onReject(code, retryAfterMs);
        if (s._openReject) { const e = new Error("open rejected " + code); e.code = code; e.retryAfterMs = retryAfterMs; s._openReject(e); s._openReject = null; }
        this._forgetStream(s);
        break;
      }
      case FT.DATA: {
        if (!s) return;
        // §6.5: DATA beyond the credit we granted -> RESET the stream
        if (f.payload.length > s.recvWindow || f.payload.length > this.connRecvWindow) {
          this._sendFrame(buildFrame(FT.RESET, s.id,
            new Uint8Array([ERR.FLOW_CONTROL_VIOLATION, 0, 0])), true);
          s.state = "reset";
          if (s.onReset) s.onReset(ERR.FLOW_CONTROL_VIOLATION);
          this._forgetStream(s);
          return;
        }
        s.recvWindow -= f.payload.length;
        this.connRecvWindow -= f.payload.length;
        if (s.onData) s.onData(f.payload);
        if (!s.paused) s.consume(f.payload.length);
        break;
      }
      case FT.CLOSE: {
        if (!s) return;
        s.remoteClosed = true;
        if (s.onEnd) s.onEnd();
        this._maybeFreeStream(s);
        break;
      }
      case FT.RESET: {
        if (!s) return;
        s.state = "reset";
        if (s.onReset) s.onReset(f.payload[0]);
        if (s._openReject) { const e = new Error("stream reset " + f.payload[0]); e.code = f.payload[0]; s._openReject(e); s._openReject = null; }
        this._forgetStream(s);
        break;
      }
      case FT.WINDOW_UPDATE: {
        const inc = f.payload.length >= 4 ? new DataView(f.payload.buffer, f.payload.byteOffset).getUint32(0) : 0;
        if (f.streamId === 0) { this.connSendWindow += inc; for (const st of this.streams.values()) this._pumpStream(st); }
        else if (s) { s.sendWindow += inc; this._pumpStream(s); }
        break;
      }
      case FT.PING: {
        this._sendFrame(buildFrame(FT.PONG, f.streamId, f.payload), true);
        break;
      }
      case FT.GOAWAY: {
        // NP-1118-66 (S3): consumed, not just recorded — the
        // openStream gate above refuses new streams and the host
        // is notified once so the session layer rotates (existing
        // streams drain here; §8.2 semantics).
        const firstGoAway = !this.goAway;
        this.goAway = { code: f.payload[0] };
        if (firstGoAway && this.onGoAway) {
          try { this.onGoAway(this.goAway.code); } catch { /* the session layer's problem, not the stream's */ }
        }
        break;
      }
      default: {
        // unknown frame type: stream-level protocol error (§8.2/§10.2)
        if (s) { s.state = "reset"; if (s.onReset) s.onReset(ERR.PROTOCOL_ERROR); this._forgetStream(s); }
      }
    }
  }

  _maybeFreeStream(s) {
    if (s.localClosed && s.remoteClosed) { s.state = "closed"; this._forgetStream(s); }
  }
  _forgetStream(s) {
    if (s._openTimer) { clearTimeout(s._openTimer); s._openTimer = null; }
    if (this.sender) this.sender.flush();
    this.streams.delete(s.id);
  }
  close() {
    try { this.transport.close(); } catch {}
    this._die("closed by app");
  }
}
export { GATE };
