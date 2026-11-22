// Minimal WebSocket client transport for the Hollow CLI (RFC 6455).
// Hand-rolled because the client must set a custom User-Agent (spec §2-2)
// and observe raw message sizes (F-8); Node's global WebSocket allows neither.
// Client frames are masked as required; TLS via node:https with default
// certificate verification (fail-closed, §2-3).
import https from "node:https";
import http from "node:http";
import crypto from "node:crypto";

export const CLIENT_UA = "HollowClient/0.1"; // §2-2: custom, no proxy/vpn/tunnel words

export function connectWs(urlStr, { userAgent = CLIENT_UA, pingIntervalMs = null, edgeIp = null, timeoutMs = null } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlStr);
    if (url.protocol !== "wss:" && url.protocol !== "ws:") {
      reject(new Error("only ws/wss")); return;
    }
    const key = crypto.randomBytes(16).toString("base64");
    const lib = url.protocol === "wss:" ? https : http;
    const req = lib.request({
      // Edge-IP selection (M2-4): the TCP/TLS connection goes to the chosen
      // anycast IP, while SNI, the Host header and certificate verification
      // stay on the URL hostname — the edge cannot tell it was picked by IP.
      hostname: edgeIp || url.hostname,
      servername: url.hostname,
      port: url.port || (url.protocol === "wss:" ? 443 : 80),
      path: url.pathname + url.search,
      headers: {
        ...(edgeIp ? { Host: url.host } : {}),
        Connection: "Upgrade",
        Upgrade: "websocket",
        "Sec-WebSocket-Key": key,
        "Sec-WebSocket-Version": "13",
        "User-Agent": userAgent,
      },
    });
    let settled = false;
    // NP-1118-49: optional establishment bound. A blackholed path
    // (SYN or upgrade response swallowed) otherwise never settles
    // this promise, and every recovery mechanism above it keys off
    // attempt COMPLETION. Opt-in only: callers that pass no
    // timeoutMs (the CLI) keep the historical unbounded behavior.
    if (timeoutMs) {
      req.setTimeout(timeoutMs, () => {
        if (settled) return;
        settled = true;
        try { req.destroy(); } catch {}
        reject(new Error("connect timed out"));
      });
    }
    req.on("upgrade", (res, socket, head) => {
      try { req.setTimeout(0); } catch {} // disarm: the socket belongs to the transport now
      const accept = res.headers["sec-websocket-accept"];
      const expect = crypto.createHash("sha1")
        .update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
      if (res.statusCode !== 101 || accept !== expect) {
        settled = true;
        reject(new Error("upgrade rejected: " + res.statusCode));
        socket.destroy();
        return;
      }
      settled = true;
      resolve(makeTransport(socket, head, pingIntervalMs));
    });
    req.on("response", (res) => {
      if (!settled) { settled = true; reject(new Error("no upgrade: HTTP " + res.statusCode)); }
    });
    req.on("error", (e) => { if (!settled) { settled = true; reject(e); } });
    req.end();
  });
}
function makeTransport(socket, head, pingIntervalMs) {
  let msgCb = null, closeCb = null;
  let buf = head && head.length ? Buffer.from(head) : Buffer.alloc(0);
  let frags = [];
  let fragOpcode = 0;
  let closed = false;
  let pingTimer = null;

  const transport = {
    rawSizes: [], // received WS message sizes on the wire (records/hello)
    send(data) {
      if (closed) return;
      socket.write(encodeFrame(0x2, Buffer.from(data)));
    },
    close() { closeWith(1000); },
    closeCarrier() { closeWith(1000); },
    onMessage(cb) { msgCb = cb; },
    onClose(cb) { closeCb = cb; },
  };

  function closeWith(code) {
    if (closed) return;
    closed = true;
    try {
      const payload = Buffer.alloc(2);
      payload.writeUInt16BE(code, 0);
      socket.write(encodeFrame(0x8, payload));
      socket.end();
    } catch {}
    if (pingTimer) clearInterval(pingTimer);
    if (closeCb) closeCb(code);
  }

  function encodeFrame(opcode, payload) {
    const mask = crypto.randomBytes(4);
    const len = payload.length;
    let header;
    if (len < 126) { header = Buffer.alloc(2); header[1] = 0x80 | len; }
    else if (len < 65536) { header = Buffer.alloc(4); header[1] = 0x80 | 126; header.writeUInt16BE(len, 2); }
    else { header = Buffer.alloc(10); header[1] = 0x80 | 127; header.writeBigUInt64BE(BigInt(len), 2); }
    header[0] = 0x80 | opcode;
    const masked = Buffer.from(payload);
    for (let i = 0; i < masked.length; i++) masked[i] ^= mask[i % 4];
    return Buffer.concat([header, mask, masked]);
  }

  socket.on("data", (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    for (;;) {
      if (buf.length < 2) return;
      const fin = (buf[0] & 0x80) !== 0;
      const opcode = buf[0] & 0x0f;
      const masked = (buf[1] & 0x80) !== 0;
      let len = buf[1] & 0x7f;
      let off = 2;
      if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
      let maskKey = null;
      if (masked) { if (buf.length < off + 4) return; maskKey = buf.subarray(off, off + 4); off += 4; }
      if (buf.length < off + len) return;
      let payload = Buffer.from(buf.subarray(off, off + len));
      buf = buf.subarray(off + len);
      if (maskKey) for (let i = 0; i < payload.length; i++) payload[i] ^= maskKey[i % 4];
      if (opcode === 0x9) { // ping -> pong
        if (!closed) socket.write(encodeFrame(0xA, payload));
        continue;
      }
      if (opcode === 0xA) continue; // pong
      if (opcode === 0x8) {
        const code = payload.length >= 2 ? payload.readUInt16BE(0) : 1005;
        if (!closed) { closed = true; if (pingTimer) clearInterval(pingTimer); if (closeCb) closeCb(code); }
        socket.destroy();
        return;
      }
      if (opcode === 0x0) { // continuation
        frags.push(payload);
        if (fin) {
          const full = Buffer.concat(frags);
          frags = [];
          transport.rawSizes.push(full.length);
          if (msgCb) msgCb(new Uint8Array(full));
        }
        continue;
      }
      // data frame (binary 0x2 / text 0x1)
      if (!fin) { frags = [payload]; fragOpcode = opcode; continue; }
      transport.rawSizes.push(payload.length);
      if (msgCb) msgCb(new Uint8Array(payload));
    }
  });
  socket.on("close", () => {
    if (!closed) { closed = true; if (pingTimer) clearInterval(pingTimer); if (closeCb) closeCb(1006); }
  });
  socket.on("error", () => {
    if (!closed) { closed = true; if (pingTimer) clearInterval(pingTimer); if (closeCb) closeCb(1006); }
  });

  if (pingIntervalMs) {
    // §2-5: idle liveness probes de-periodized to 75-150s; the caller passes a
    // value already randomized in that range.
    pingTimer = setInterval(() => {
      if (!closed) { try { socket.write(encodeFrame(0x9, Buffer.alloc(0))); } catch {} }
    }, pingIntervalMs);
    pingTimer.unref();
  }
  return transport;
}
