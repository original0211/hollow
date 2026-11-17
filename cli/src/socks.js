// Local proxy entry (spec §3): loopback only, CONNECT only, no UDP/BIND.
// Dual protocol on one port (NP-1117-07): the first byte selects the
// dialect — 0x05 is SOCKS5, 'C' is HTTP CONNECT (what WinINET/browsers
// send when ProxyServer names an HTTP proxy). Both end at the same
// client.openStream and the same pump. Anything else is destroyed.
// Failure mapping is honest: unsupported commands get REP=7, rejected OPENs
// get REP=5 (refused) unless the code says otherwise; nothing hangs silently.
import net from "node:net";
import { ERR } from "../../shared/protocol.js";

const REP = { SUCCESS: 0, GENERAL: 1, NOT_ALLOWED: 2, NET_UNREACH: 3, HOST_UNREACH: 4, REFUSED: 5, CMD_NOT_SUPPORTED: 7, ATYP_NOT_SUPPORTED: 8 };
const repForOpenError = (code) => {
  switch (code) {
    case ERR.TARGET_UNREACHABLE: return REP.REFUSED;
    case ERR.PROHIBITED_PORT: case ERR.PRIVATE_TARGET:
    case ERR.LOOP_TARGET: case ERR.UNSUPPORTED_TARGET: return REP.NOT_ALLOWED;
    case ERR.CONCURRENCY_LIMIT: case ERR.QUOTA_GUARD: return REP.REFUSED;
    default: return REP.GENERAL;
  }
};

// NP-1117-14: bounded local retry for 0x01 (concurrency_limit) OPEN
// rejects. Server admission is finite (16 in flight + 64 queue), so a
// heavy burst can still draw an instant 0x01; instead of failing the
// SOCKS connection on the spot, re-OPEN under a fresh stream id with
// exponential backoff + jitter, honoring the server's retry_after as
// a floor, inside a ~10 s total budget. The SOCKS side stays pending
// the whole time (no REP / no HTTP status is sent until the outcome
// is final). ONLY 0x01 retries — every other code fails immediately.
// Rejected streams are forgotten by client-core on OPEN_REJECT, so
// retries leave nothing behind in the stream table.
export const OPEN_RETRY_BASE_MS = 250;
export const OPEN_RETRY_CAP_MS = 10000;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// Attempts go through getClient() EVERY time (NP-1117-16): a session
// rotation may swap the current client mid-retry, and the next attempt
// then lands on the fresh session — streams arriving during a
// rotation window hang here instead of failing because of it.
// hooks.onOutboundExhausted(client) (NP-1117-16 item 2): a 0x06 from a
// session that is at/over its open budget earns exactly ONE migration
// retry on the rotated session; the hook decides (session manager).
// A 0x06 under budget — and every other code — fails immediately.
async function openWithRetry(getClient, opts, retry = {}, log = () => {}, hooks = {}) {
  const baseMs = retry.baseMs ?? OPEN_RETRY_BASE_MS;
  const capMs = retry.capMs ?? OPEN_RETRY_CAP_MS;
  const t0 = Date.now();
  let delay = baseMs;
  let migrated = false;
  for (;;) {
    const client = getClient();
    if (!client || client.state !== "open") {
      const e = new Error("no live session");
      e.code = undefined;
      throw e;
    }
    const s = client.openStream(opts);
    try {
      await s.opened;
      return s;
    } catch (e) {
      if (e && e.code === ERR.OUTBOUND_FAILED && !migrated && hooks.onOutboundExhausted) {
        migrated = true; // at most one migration per connection, ever
        if (await hooks.onOutboundExhausted(client)) {
          log("open rejected 0x06 on a budget-exhausted session; rotated, retrying once");
          continue;
        }
        throw e;
      }
      if (!e || e.code !== ERR.CONCURRENCY_LIMIT) throw e;
      const elapsed = Date.now() - t0;
      if (elapsed >= capMs) throw e;
      const jittered = delay * (1 + (Math.random() * 0.5 - 0.25));
      const wait = Math.min(capMs - elapsed, Math.max(jittered, e.retryAfterMs || 0));
      log(`open rejected 0x01 (concurrency_limit); retrying in ${Math.round(wait)} ms`);
      await sleep(Math.max(0, Math.round(wait)));
      delay = Math.min(delay * 2, 2000);
    }
  }
}

export function startSocks({ getClient, host = "127.0.0.1", port = 1080, log = () => {}, openRetry = {}, openHooks = {} }) {
  const server = net.createServer((sock) => {
    handleConn(sock, getClient, log, openRetry, openHooks).catch(() => { try { sock.destroy(); } catch {} });
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => resolve(server));
  });
}

// Per-connection buffered reader. All header reads go through one buffer so
// bytes that arrive in the same TCP chunk as later fields (or as pipelined
// payload) are never lost. (A sock.unshift() approach silently drops bytes
// on a flowing socket — that was the v0 bug this replaces.)
function makeReader(sock) {
  let buf = Buffer.alloc(0);
  let waiters = [];
  let closed = false;
  const onData = (c) => { buf = buf.length ? Buffer.concat([buf, c]) : c; pump(); };
  const onDone = () => { closed = true; pump(); };
  sock.on("data", onData);
  sock.once("close", onDone);
  sock.once("error", onDone);
  function pump() {
    while (waiters.length && (buf.length >= waiters[0].n || closed)) {
      const w = waiters.shift();
      if (buf.length >= w.n) {
        const out = buf.subarray(0, w.n);
        buf = buf.subarray(w.n);
        w.res(out);
      } else {
        w.res(null);
      }
    }
  }
  return {
    readN: (n) => new Promise((res) => { waiters.push({ n, res }); pump(); }),
    // Read through the end of an HTTP header block (delimiter inclusive).
    // Resolves null on close or when the block exceeds `max` bytes.
    readUntil: (delim, max) => new Promise((res) => {
      const dl = Buffer.from(delim, "latin1");
      const check = () => {
        const idx = buf.indexOf(dl);
        if (idx >= 0) {
          const out = buf.subarray(0, idx + dl.length);
          buf = buf.subarray(idx + dl.length);
          cleanup(); res(out);
        } else if (buf.length > max || closed) {
          cleanup(); res(null);
        }
      };
      const onMore = () => check();
      const cleanup = () => { sock.off("data", onMore); sock.off("close", onMore); sock.off("error", onMore); };
      sock.on("data", onMore); sock.once("close", onMore); sock.once("error", onMore);
      check();
    }),
    // Stop consuming and hand back any buffered-but-unread bytes (pipelined
    // payload that arrived with the request header).
    detach() {
      sock.off("data", onData);
      const rest = buf;
      buf = Buffer.alloc(0);
      return rest;
    },
  };
}

async function handleConn(sock, getClient, log, openRetry = {}, openHooks = {}) {
  sock.on("error", () => {});
  const reader = makeReader(sock);
  const first = await reader.readN(1);
  if (!first) { sock.destroy(); return; }
  if (first[0] === 0x05) return handleSocks(sock, reader, getClient, log, openRetry, openHooks);
  if (first[0] === 0x43) return handleHttpConnect(sock, reader, first, getClient, log, openRetry, openHooks); // 'C'
  sock.destroy();
}

async function handleSocks(sock, reader, getClient, log, openRetry = {}, openHooks = {}) {
  const readN = reader.readN;
  const nmethods = await readN(1);
  if (!nmethods) { sock.destroy(); return; }
  const methods = await readN(nmethods[0]);
  if (!methods || !methods.includes(0x00)) {
    sock.write(Buffer.from([0x05, 0xff])); sock.end(); return;
  }
  sock.write(Buffer.from([0x05, 0x00]));
  const req = await readN(4);
  if (!req || req[0] !== 0x05) { sock.destroy(); return; }
  const cmd = req[1];
  const atyp = req[3];
  let targetHost;
  if (atyp === 0x01) {
    const a = await readN(4); if (!a) { sock.destroy(); return; }
    targetHost = Array.from(a).join(".");
  } else if (atyp === 0x03) {
    const l = await readN(1); if (!l) { sock.destroy(); return; }
    const d = await readN(l[0]); if (!d) { sock.destroy(); return; }
    targetHost = d.toString("utf8");
  } else if (atyp === 0x04) {
    const a = await readN(16); if (!a) { sock.destroy(); return; }
    const groups = [];
    for (let i = 0; i < 16; i += 2) groups.push(a.readUInt16BE(i).toString(16));
    targetHost = groups.join(":");
  } else {
    reply(sock, REP.ATYP_NOT_SUPPORTED); return;
  }
  const p = await readN(2);
  if (!p) { sock.destroy(); return; }
  const targetPort = p.readUInt16BE(0);
  const pipelined = reader.detach(); // payload bytes that arrived early
  if (cmd !== 0x01) { reply(sock, REP.CMD_NOT_SUPPORTED); return; } // §3: BIND/UDP -> not supported

  const client = getClient();
  if (!client || client.state !== "open") { reply(sock, REP.GENERAL); return; }
  let stream;
  try {
    stream = await openWithRetry(getClient, { host: targetHost, port: targetPort, schemeHint: 0, gatePolicy: 0 }, openRetry, log, openHooks);
  } catch (e) {
    reply(sock, e && e.code !== undefined ? repForOpenError(e.code) : REP.GENERAL);
    return;
  }
  log(`socks stream ${stream.id} -> ${targetHost}:${targetPort} gate=${stream.gate}`);
  reply(sock, REP.SUCCESS);
  attachPump(sock, stream, pipelined);
}

// HTTP CONNECT (NP-1117-07): the other dialect browsers speak to this
// port. Same open path, same pump; failures are HTTP status lines, and
// anything that is not a well-formed CONNECT is destroyed.
async function handleHttpConnect(sock, reader, first, getClient, log, openRetry = {}, openHooks = {}) {
  const headBuf = await reader.readUntil("\r\n\r\n", 16384);
  if (!headBuf) { sock.destroy(); return; }
  const headText = Buffer.concat([first, headBuf]).toString("latin1");
  const requestLine = headText.split("\r\n", 1)[0];
  const m = /^CONNECT[ \t]+(\S+)[ \t]+HTTP\/\d+(?:\.\d+)?[ \t]*$/i.exec(requestLine);
  if (!m) { sock.destroy(); return; }
  const target = parseHostPort(m[1]);
  if (!target) { httpReply(sock, 400, "Bad Request"); return; }
  const pipelined = reader.detach(); // payload bytes that arrived early
  const client = getClient();
  if (!client || client.state !== "open") { httpReply(sock, 502, "Bad Gateway"); return; }
  let stream;
  try {
    stream = await openWithRetry(getClient, { host: target.host, port: target.port, schemeHint: 0, gatePolicy: 0 }, openRetry, log, openHooks);
  } catch {
    httpReply(sock, 502, "Bad Gateway");
    return;
  }
  log(`http-connect stream ${stream.id} -> ${target.host}:${target.port} gate=${stream.gate}`);
  sock.write("HTTP/1.1 200 Connection Established\r\n\r\n");
  attachPump(sock, stream, pipelined);
}

function parseHostPort(s) {
  let host, portStr;
  if (s.startsWith("[")) {
    const end = s.indexOf("]");
    if (end < 0 || s[end + 1] !== ":") return null;
    host = s.slice(1, end);
    portStr = s.slice(end + 2);
  } else {
    const idx = s.lastIndexOf(":");
    if (idx <= 0) return null;
    host = s.slice(0, idx);
    portStr = s.slice(idx + 1);
  }
  const port = Number(portStr);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { host, port };
}

function httpReply(sock, code, text) {
  try { sock.write(`HTTP/1.1 ${code} ${text}\r\nContent-Length: 0\r\n\r\n`); } catch {}
  sock.end();
}

// Bidirectional pump shared by both dialects: stream data to the socket
// with consume-on-drain flow control; socket data into the stream with
// pause-on-pending; half-close discipline per §6.3 / NP-1116-02.
function attachPump(sock, stream, pipelined) {
  let unacked = 0;
  let sockEnded = false;
  stream.onData = (data) => {
    unacked += data.length;
    if (!sock.write(Buffer.from(data))) {
      stream.paused = true;
    }
  };
  sock.on("drain", () => {
    if (unacked > 0) { stream.consume(unacked); unacked = 0; }
    stream.paused = false;
  });
  stream.onEnd = () => {
    // NP-1116-02 (P1; root cause NP-1116-01): the server half-closed
    // (§6.3) — the target will send no more. End the local socket AND
    // fulfil our CLOSE obligation: without it the stream holds a §7.5
    // occupancy slot until the local app happens to close its write
    // side, which may be never. closeWrite is stream-ordered, so app
    // data already queued still flushes before the CLOSE.
    try { sock.end(); } catch {}
    try { stream.closeWrite(); } catch {}
  };
  stream.onReset = () => { try { sock.destroy(); } catch {} };
  stream.onFail = () => { try { sock.destroy(); } catch {} };
  stream.onDrain = () => { try { sock.resume(); } catch {} };
  if (pipelined.length > 0) {
    if (!stream.write(pipelined)) sock.destroy();
    else if (stream.pending.length > 0) sock.pause();
  }
  sock.on("data", (chunk) => {
    if (!stream.write(chunk)) { /* stream gone */ sock.destroy(); return; }
    if (stream.pending.length > 0) sock.pause(); // resumed via onDrain
  });
  sock.on("end", () => {
    sockEnded = true;
    stream.closeWrite();
  });
  sock.on("close", () => {
    if (!sockEnded && stream.state === "open") stream.reset();
  });
}

function reply(sock, rep) {
  const b = Buffer.from([0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
  sock.write(b);
  if (rep !== REP.SUCCESS) sock.end();
}
