// Hollow server session core (spec v0.1 §4, §5, §6, §7, §8).
// Transport-agnostic. Injected platform functions:
//   connectFn({hostname, port}) -> Promise<socket>  (CF connect() / node net)
//   socket: { readable, writable, opened: Promise, close() }
//   fetchFn(url, init) -> Promise<Response-like>    (CF fetch() / node fetch)
// env: { verifiers: Map<keyId, Uint8Array>, ownHost, zoneSuffix }
import { randomBytes, x25519Generate, x25519Derive } from "./crypto.js";
import {
  PROTO_VERSION, FT, ERR, GATE, SCHEME,
  CONN_WINDOW_INIT, STREAM_WINDOW_INIT, MAX_PAYLOAD,
  MAX_OCCUPANCY, QUEUE_DEPTH, QUEUE_MAX_WAIT_MS, QUEUE_RETRY_AFTER_MS,
  FETCH_CONCURRENCY, FETCH_BODY_MAX, RECORD_FAIL_LIMIT, STREAM_ERROR_LIMIT,
  parseClientHello, buildServerHello, deriveSession, finishedMac,
  buildFrame, parseFrames, sealRecords, RecordReceiver,
  parseOpenPayload, isPrivateIPv4Bytes, isPrivateIPv6Bytes,
  rejectPayload, resetPayload, eq, concat, RecordSender,
} from "./protocol.js";

const HALF_STREAM = STREAM_WINDOW_INIT / 2;
const HALF_CONN = CONN_WINDOW_INIT / 2;
const CONNECT_SPECIAL_ERROR = "proxy request failed, cannot connect to the specified address";

export class HollowServer {
  constructor({ transport, verifiers, ownHost, zoneSuffix, connectFn, fetchFn }) {
    this.transport = transport;
    this.verifiers = verifiers;
    this.ownHost = ownHost;
    this.zoneSuffix = zoneSuffix; // e.g. "newproto.workers.dev"
    this.connectFn = connectFn; this.fetchFn = fetchFn;
    this.state = "hello"; // hello | wait-finished | open | dead
    this.streams = new Map();
    this.queue = []; // FIFO of {streamId, open} (§7.5)
    this.occupancy = 0;
    this.fetchActive = 0;
    this.streamErrors = 0;
    this.connSendWindow = CONN_WINDOW_INIT;
    this.connRecvWindow = CONN_WINDOW_INIT;
    this.connRecvUnacked = 0;
    this.sender = null; this.receiver = null;
    this.dead = false;
    // Serialize message handling: handshake steps are async (WebCrypto), and
    // back-to-back records must observe state transitions in wire order.
    this._chain = Promise.resolve();
    transport.onMessage((bytes) => {
      this._chain = this._chain
        .then(() => this._onMessage(bytes))
        .catch(() => this._carrierFail());
    });
    transport.onClose(() => { this._teardown(); });
  }

  _teardown() {
    this.dead = true;
    for (const s of this.streams.values()) this._closeSocket(s);
    this.streams.clear();
    this.queue.length = 0;
  }
  _carrierFail() {
    if (this.dead) return;
    this._teardown();
    try { this.transport.closeCarrier(); } catch { try { this.transport.close(); } catch {} }
  }
  _sendFrame(bytes, immediate) { if (this.sender) this.sender.push(bytes, immediate); }
  _noteStreamError() {
    this.streamErrors++;
    if (this.streamErrors >= STREAM_ERROR_LIMIT) this._carrierFail();
  }

  async _onMessage(bytes) {
    if (this.dead) return;
    if (this.state === "hello") return this._onClientHello(bytes);
    if (this.state === "wait-finished") return this._onClientFinished(bytes);
    if (this.state === "open") return this._onRecord(bytes);
  }

  async _onClientHello(bytes) {
    const ch = parseClientHello(bytes);
    if (!ch) return this._carrierFail();
    const common = ch.versions.filter((v) => v === PROTO_VERSION);
    const verifier = this.verifiers.get(ch.keyId);
    if (common.length === 0) {
      // §5.2: selected_version 0x00 then §8.1 close
      const kp = await x25519Generate();
      const sh = buildServerHello({
        selectedVersion: 0x00, publicRaw: kp.publicRaw,
        random: randomBytes(32), padding: randomBytes(8),
      });
      this.transport.send(sh);
      return this._carrierFail();
    }
    if (!verifier) return this._carrierFail();
    const kp = await x25519Generate();
    const serverRandom = randomBytes(32);
    const sh = buildServerHello({
      selectedVersion: PROTO_VERSION, publicRaw: kp.publicRaw,
      random: serverRandom, padding: randomBytes(Math.floor(Math.random() * 129)),
    });
    this.transport.send(sh);
    const dh = await x25519Derive(kp.privateKey, ch.publicRaw);
    if (!dh) return this._carrierFail();
    const keys = await deriveSession({
      dh, verifier,
      clientRandom: ch.random, serverRandom,
      clientHello: bytes, serverHello: sh,
    });
    this._keys = keys;
    this.sender = new RecordSender(keys.kS2c, keys.ivS2c, (b) => this.transport.send(b));
    this.receiver = new RecordReceiver(keys.kC2s, keys.ivC2s);
    // server Finished first (§4): s2c record seq=0
    const mac = await finishedMac(keys.fS, keys.th, "server");
    this._sendFrame(buildFrame(FT.FINISH, 0, mac), true);
    this.state = "wait-finished";
  }

  async _onClientFinished(bytes) {
    const opened = this.receiver.open(bytes);
    if (!opened) return this._carrierFail();
    const parsed = parseFrames(opened.framesBlob);
    const f = parsed.frames[0];
    const expect = await finishedMac(this._keys.fC, this._keys.th, "client");
    if (parsed.recordError || parsed.frames.length !== 1 || !f ||
        f.type !== FT.FINISH || f.streamId !== 0 || !eq(f.payload, expect)) {
      return this._carrierFail();
    }
    this.state = "open";
  }

  _onRecord(bytes) {
    const opened = this.receiver.open(bytes);
    if (!opened) {
      if (this.receiver.consecFails >= RECORD_FAIL_LIMIT) this._carrierFail();
      return;
    }
    const parsed = parseFrames(opened.framesBlob);
    if (parsed.recordError) {
      this.receiver.noteFailure();
      if (this.receiver.consecFails >= RECORD_FAIL_LIMIT) this._carrierFail();
      return;
    }
    this.receiver.noteSuccess();
    for (const os of parsed.oversize) {
      // payload_len over the 16,373 hard cap -> stream-level RESET (§8.2)
      this._resetStream(os.streamId, ERR.PROTOCOL_ERROR);
      this._noteStreamError();
    }
    for (const f of parsed.frames) {
      this._dispatch(f).catch(() => {});
      if (this.dead) return;
    }
  }

  async _dispatch(f) {
    switch (f.type) {
      case FT.OPEN: return this._onOpen(f);
      case FT.DATA: return this._onData(f);
      case FT.CLOSE: return this._onCloseFrame(f);
      case FT.RESET: return this._onResetFrame(f);
      case FT.WINDOW_UPDATE: return this._onWindowUpdate(f);
      case FT.PING:
        this._sendFrame(buildFrame(FT.PONG, f.streamId, f.payload), true);
        return;
      case FT.PONG: return;
      default: {
        // unknown/reserved type: stream-level protocol error (§8.2, §10.2)
        if (f.streamId !== 0) this._resetStream(f.streamId, ERR.PROTOCOL_ERROR);
        this._noteStreamError();
      }
    }
  }

  // ---------- §7.2 / §7.3 / §7.5 ----------
  _validateTarget(open) {
    if (open.port === 25) return ERR.PROHIBITED_PORT;
    if (open.port === 0) return ERR.OUTBOUND_FAILED;
    if (open.addrType === 0x01 && isPrivateIPv4Bytes(open.addrBytes)) return ERR.PRIVATE_TARGET;
    if (open.addrType === 0x02 && isPrivateIPv6Bytes(open.addrBytes)) return ERR.PRIVATE_TARGET;
    if (open.host === this.ownHost) return ERR.LOOP_TARGET;
    if (this.zoneSuffix && open.host.endsWith("." + this.zoneSuffix)) return ERR.UNSUPPORTED_TARGET;
    return 0;
  }

  _onOpen(f) {
    const open = parseOpenPayload(f.payload);
    if (!open) {
      this._sendFrame(buildFrame(FT.RESET, f.streamId, resetPayload(ERR.PROTOCOL_ERROR)), true);
      this._noteStreamError();
      return;
    }
    if (this.streams.has(f.streamId) || this.queue.some((q) => q.streamId === f.streamId)) {
      this._sendFrame(buildFrame(FT.RESET, f.streamId, resetPayload(ERR.PROTOCOL_ERROR)), true);
      this._noteStreamError();
      return;
    }
    const bad = this._validateTarget(open);
    if (bad) {
      this._sendFrame(buildFrame(FT.OPEN_REJECT, f.streamId, rejectPayload(bad, 0)), true);
      return;
    }
    if (this.occupancy >= MAX_OCCUPANCY) {
      if (this.queue.length >= QUEUE_DEPTH) {
        this._sendFrame(buildFrame(FT.OPEN_REJECT, f.streamId,
          rejectPayload(ERR.CONCURRENCY_LIMIT, QUEUE_RETRY_AFTER_MS)), true);
        return;
      }
      const entry = { streamId: f.streamId, open, timer: null };
      entry.timer = setTimeout(() => {
        const i = this.queue.indexOf(entry);
        if (i >= 0) {
          this.queue.splice(i, 1);
          this._sendFrame(buildFrame(FT.OPEN_REJECT, entry.streamId,
            rejectPayload(ERR.CONCURRENCY_LIMIT, QUEUE_RETRY_AFTER_MS)), true);
        }
      }, QUEUE_MAX_WAIT_MS);
      this.queue.push(entry);
      // §7.5: queueing must be explicit — OPEN_QUEUED immediately.
      const qp = new Uint8Array(6);
      const dv = new DataView(qp.buffer);
      dv.setUint16(0, this.queue.length); // position, 1-based
      dv.setUint16(2, 0); // est wait: unknown -> 0
      dv.setUint16(4, QUEUE_MAX_WAIT_MS);
      this._sendFrame(buildFrame(FT.OPEN_QUEUED, f.streamId, qp), true);
      return;
    }
    this._startOpen(f.streamId, open);
  }

  async _startOpen(streamId, open) {
    this.occupancy++;
    const s = {
      id: streamId, open, gate: null, socket: null, writer: null,
      sendWindow: STREAM_WINDOW_INIT, recvWindow: STREAM_WINDOW_INIT,
      recvUnacked: 0, remoteClosed: false, localClosed: false,
      fetchBuf: null, dead: false, pumpPaused: false,
    };
    this.streams.set(streamId, s);
    // §7.3 step 1: connect gate first
    let sock = null, connectErr = null;
    try {
      sock = await this.connectFn({ hostname: open.host, port: open.port });
      if (sock.opened) await sock.opened;
    } catch (e) { connectErr = e; }
    if (this.dead || !this.streams.has(streamId)) {
      if (sock) { try { sock.close(); } catch {} }
      this.occupancy--;
      this._drainQueue();
      return;
    }
    if (sock) {
      s.gate = GATE.CONNECT; s.socket = sock;
      s.writer = sock.writable.getWriter();
      this._sendFrame(buildFrame(FT.OPEN_OK, streamId, new Uint8Array([GATE.CONNECT])), true);
      this._pumpSocket(s);
      return;
    }
    // §7.3 step 2: specific error text -> fetch fallback (once)
    const msg = String(connectErr && connectErr.message || connectErr || "");
    const special = msg.startsWith(CONNECT_SPECIAL_ERROR);
    const canFallback = special && open.gatePolicy === 0x00 &&
      (open.port === 80 || open.port === 443) &&
      (open.schemeHint === SCHEME.HTTP || open.schemeHint === SCHEME.HTTPS);
    if (canFallback && this.fetchActive < FETCH_CONCURRENCY) {
      s.gate = GATE.FETCH; s.fetchBuf = [];
      this.fetchActive++;
      s.occupiesFetch = true;
      this._sendFrame(buildFrame(FT.OPEN_OK, streamId, new Uint8Array([GATE.FETCH])), true);
      return;
    }
    // §7.3 step 3: map error
    let code = ERR.OUTBOUND_FAILED;
    if (special) code = ERR.CF_SEGMENT_NON_HTTP;
    else if (/refused|timed? ?out|timeout|unreachable/i.test(msg)) code = ERR.TARGET_UNREACHABLE;
    if (canFallback && this.fetchActive >= FETCH_CONCURRENCY) code = ERR.FETCH_FALLBACK_FAILED;
    this.streams.delete(streamId);
    this.occupancy--;
    this._sendFrame(buildFrame(FT.OPEN_REJECT, streamId, rejectPayload(code, 0)), true);
    this._drainQueue();
  }

  _drainQueue() {
    while (this.occupancy < MAX_OCCUPANCY && this.queue.length > 0 && !this.dead) {
      const entry = this.queue.shift();
      clearTimeout(entry.timer);
      this._startOpen(entry.streamId, entry.open);
    }
  }

  _closeSocket(s) {
    if (!s || !s.socket) return;
    try { s.socket.close(); } catch {}
    s.socket = null;
  }

  _freeStream(s, { releaseSlot = true } = {}) {
    if (!this.streams.has(s.id)) return;
    this.streams.delete(s.id);
    this._closeSocket(s);
    if (s.occupiesFetch) { this.fetchActive--; s.occupiesFetch = false; }
    if (releaseSlot) { this.occupancy--; this._drainQueue(); }
  }

  _resetStream(streamId, code) {
    const s = this.streams.get(streamId);
    this._sendFrame(buildFrame(FT.RESET, streamId, resetPayload(code)), true);
    if (s) this._freeStream(s);
  }

  // ---------- data plane ----------
  async _pumpSocket(s) {
    const reader = s.socket.readable.getReader();
    s.reader = reader;
    // Ordered outbound queue: bytes are framed strictly in socket-read order.
    // (A previous version stashed a remainder and read ahead, which reordered
    // the byte stream; this queue is the fix — see the ordering regression
    // test in tests/protocol.test.mjs.)
    s.outBuf = new Uint8Array(0);
    let eof = false;
    try {
      for (;;) {
        while (s.outBuf.length > 0 && !s.dead && !this.dead) {
          const avail = Math.min(s.sendWindow, this.connSendWindow);
          if (avail <= 0) break;
          const take = Math.min(s.outBuf.length, avail, MAX_PAYLOAD);
          const chunk = s.outBuf.subarray(0, take);
          s.outBuf = s.outBuf.subarray(take);
          s.sendWindow -= take; this.connSendWindow -= take;
          this._sendFrame(buildFrame(FT.DATA, s.id, chunk), false);
        }
        if (this.sender) this.sender.flush();
        if (s.outBuf.length === 0 && eof) break;
        if (s.dead || this.dead) break;
        if (s.outBuf.length > 0) {
          // window exhausted: wait for WINDOW_UPDATE (pumpWake) or poll
          await new Promise((r) => { s.pumpWake = r; setTimeout(r, 250); });
          continue;
        }
        const { value, done } = await reader.read();
        if (done) { eof = true; continue; }
        if (value && value.length > 0) {
          s.outBuf = s.outBuf.length ? concat(s.outBuf, value) : value;
        }
      }
    } catch { eof = true; }
    if (!s.dead && !this.dead && this.streams.has(s.id)) {
      // outbound EOF or error: half-close towards client (§6.3). The slot is
      // released when the client's own CLOSE or RESET arrives (outEof).
      this._sendFrame(buildFrame(FT.CLOSE, s.id, new Uint8Array([0x00])), true);
      s.localClosed = true;
      if (s.remoteClosed) this._freeStream(s);
      else s.outEof = true;
    }
  }

  _onData(f) {
    const q = this.queue.findIndex((e) => e.streamId === f.streamId);
    if (q >= 0) { this._noteStreamError(); return; } // DATA on queued stream: ignore+count
    const s = this.streams.get(f.streamId);
    if (!s) return; // data for unknown stream: drop (may race a RESET)
    if (s.remoteClosed) {
      this._resetStream(f.streamId, ERR.PROTOCOL_ERROR);
      this._noteStreamError();
      return;
    }
    // flow control (§6.5): over-window DATA -> RESET flow_control_violation
    if (f.payload.length > s.recvWindow || f.payload.length > this.connRecvWindow) {
      this._resetStream(f.streamId, ERR.FLOW_CONTROL_VIOLATION);
      this._noteStreamError();
      return;
    }
    s.recvWindow -= f.payload.length;
    this.connRecvWindow -= f.payload.length;
    if (s.gate === GATE.CONNECT && s.writer) {
      // §6.5 worker-side backpressure: credit is replenished only when the
      // outbound socket actually accepts the bytes, so a stalled target
      // stops the client's window exactly as the spec intends.
      const len = f.payload.length;
      let wp;
      try { wp = Promise.resolve(s.writer.write(f.payload)); }
      catch { wp = Promise.reject(new Error("write failed")); }
      wp.then(() => this._consume(s, len), () => {});
    } else if (s.gate === GATE.FETCH) {
      const total = (s.fetchLen || 0) + f.payload.length;
      if (total > FETCH_BODY_MAX) {
        this._resetStream(f.streamId, ERR.FETCH_BODY_TOO_LARGE);
        return;
      }
      s.fetchLen = total;
      s.fetchBuf.push(f.payload);
      this._consume(s, f.payload.length);
    }
  }

  _consume(s, n) {
    s.recvUnacked += n;
    this.connRecvUnacked += n;
    if (s.recvUnacked >= HALF_STREAM) {
      const inc = s.recvUnacked; s.recvUnacked = 0; s.recvWindow += inc;
      const p = new Uint8Array(4); new DataView(p.buffer).setUint32(0, inc);
      this._sendFrame(buildFrame(FT.WINDOW_UPDATE, s.id, p), true);
    }
    if (this.connRecvUnacked >= HALF_CONN) {
      const inc = this.connRecvUnacked; this.connRecvUnacked = 0; this.connRecvWindow += inc;
      const p = new Uint8Array(4); new DataView(p.buffer).setUint32(0, inc);
      this._sendFrame(buildFrame(FT.WINDOW_UPDATE, 0, p), true);
    }
  }

  async _onCloseFrame(f) {
    const qi = this.queue.findIndex((e) => e.streamId === f.streamId);
    if (qi >= 0) { clearTimeout(this.queue[qi].timer); this.queue.splice(qi, 1); return; }
    const s = this.streams.get(f.streamId);
    if (!s) return;
    s.remoteClosed = true;
    if (s.gate === GATE.CONNECT) {
      if (s.writer) { try { await s.writer.close(); } catch {} }
      if (s.localClosed || s.outEof) this._freeStream(s);
    } else if (s.gate === GATE.FETCH) {
      this._runFetch(s);
    }
  }

  _onResetFrame(f) {
    const qi = this.queue.findIndex((e) => e.streamId === f.streamId);
    if (qi >= 0) {
      // §7.5: client cancels queueing silently
      clearTimeout(this.queue[qi].timer);
      this.queue.splice(qi, 1);
      return;
    }
    const s = this.streams.get(f.streamId);
    if (s) { s.dead = true; this._freeStream(s); }
  }

  _onWindowUpdate(f) {
    const inc = f.payload.length >= 4
      ? new DataView(f.payload.buffer, f.payload.byteOffset).getUint32(0) : 0;
    if (f.streamId === 0) {
      this.connSendWindow += inc;
      for (const s of this.streams.values()) if (s.pumpWake) { s.pumpWake(); s.pumpWake = null; }
      return;
    }
    const s = this.streams.get(f.streamId);
    if (!s) return;
    s.sendWindow += inc;
    if (s.pumpWake) { s.pumpWake(); s.pumpWake = null; }
  }

  // ---------- §7.4 fetch gate ----------
  async _runFetch(s) {
    const raw = concat(...s.fetchBuf);
    s.fetchBuf = [];
    const fail = (code) => { this._resetStream(s.id, code); };
    // parse request head
    const headEnd = indexOfDoubleCRLF(raw);
    if (headEnd < 0) return fail(ERR.FETCH_PROFILE_UNSUPPORTED);
    const headText = new TextDecoder().decode(raw.subarray(0, headEnd));
    const lines = headText.split("\r\n");
    const m = lines[0].match(/^([A-Z]+)\s+(\S+)\s+HTTP\/1\.[01]$/);
    if (!m) return fail(ERR.FETCH_PROFILE_UNSUPPORTED);
    const [, method, path] = m;
    const headers = {};
    for (const line of lines.slice(1)) {
      const i = line.indexOf(":");
      if (i > 0) headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
    }
    if (headers["upgrade"] || (headers["expect"] || "").includes("100-continue")) {
      return fail(ERR.FETCH_PROFILE_UNSUPPORTED);
    }
    const body = raw.subarray(headEnd + 4);
    const scheme = s.open.schemeHint === SCHEME.HTTPS ? "https" : "http";
    const hostForUrl = s.open.host.includes(":") && !s.open.host.startsWith("[")
      ? `[${s.open.host}]` : s.open.host;
    const url = `${scheme}://${hostForUrl}:${s.open.port}${path.startsWith("/") ? path : "/" + path}`;
    const hop = new Set(["connection", "proxy-connection", "proxy-authorization",
      "transfer-encoding", "keep-alive", "te", "trailer", "upgrade", "host", "content-length"]);
    const outHeaders = {};
    for (const [k, v] of Object.entries(headers)) if (!hop.has(k)) outHeaders[k] = v;
    if (!outHeaders["accept-encoding"]) outHeaders["accept-encoding"] = "identity";
    let resp;
    try {
      resp = await this.fetchFn(url, {
        method,
        headers: outHeaders,
        body: ["GET", "HEAD"].includes(method) ? undefined : body,
        redirect: "manual",
      });
    } catch {
      return fail(ERR.FETCH_FALLBACK_FAILED);
    }
    // synthesize HTTP/1.1 response head (§7.4)
    const statusText = resp.statusText || "";
    let head = `HTTP/1.1 ${resp.status} ${statusText}\r\n`;
    let respBody = null;
    try { respBody = new Uint8Array(await resp.arrayBuffer()); } catch { respBody = new Uint8Array(0); }
    const rh = {};
    resp.headers.forEach((v, k) => { rh[k.toLowerCase()] = v; });
    for (const [k, v] of Object.entries(rh)) {
      if (["connection", "transfer-encoding", "keep-alive"].includes(k)) continue;
      if (k === "content-length") continue; // set our own exact length below
      head += `${k}: ${v}\r\n`;
    }
    head += `content-length: ${respBody.length}\r\n\r\n`;
    const headBytes = new TextEncoder().encode(head);
    const all = concat(headBytes, respBody);
    let off = 0;
    while (off < all.length && !s.dead && !this.dead && this.streams.has(s.id)) {
      const avail = Math.min(s.sendWindow, this.connSendWindow);
      if (avail <= 0) {
        await new Promise((r) => { s.pumpWake = r; setTimeout(r, 250); });
        continue;
      }
      const take = Math.min(all.length - off, avail, MAX_PAYLOAD);
      s.sendWindow -= take; this.connSendWindow -= take;
      this._sendFrame(buildFrame(FT.DATA, s.id, all.subarray(off, off + take)), false);
      off += take;
    }
    if (this.sender) this.sender.flush();
    if (!this.dead && this.streams.has(s.id)) {
      this._sendFrame(buildFrame(FT.CLOSE, s.id, new Uint8Array([0x00])), true);
      s.localClosed = true;
      this._freeStream(s);
    }
  }
}

function indexOfDoubleCRLF(b) {
  for (let i = 0; i + 3 < b.length; i++) {
    if (b[i] === 13 && b[i + 1] === 10 && b[i + 2] === 13 && b[i + 3] === 10) return i;
  }
  return -1;
}
