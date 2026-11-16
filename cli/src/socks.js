// SOCKS5 local entry (spec §3): loopback only, CONNECT only, no UDP/BIND.
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

export function startSocks({ getClient, host = "127.0.0.1", port = 1080, log = () => {} }) {
  const server = net.createServer((sock) => {
    handleConn(sock, getClient, log).catch(() => { try { sock.destroy(); } catch {} });
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

async function handleConn(sock, getClient, log) {
  sock.on("error", () => {});
  const reader = makeReader(sock);
  const readN = reader.readN;
  const head = await readN(2);
  if (!head || head[0] !== 0x05) { sock.destroy(); return; }
  const methods = await readN(head[1]);
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
    stream = client.openStream({ host: targetHost, port: targetPort, schemeHint: 0, gatePolicy: 0 });
    await stream.opened;
  } catch (e) {
    reply(sock, e && e.code !== undefined ? repForOpenError(e.code) : REP.GENERAL);
    return;
  }
  log(`socks stream ${stream.id} -> ${targetHost}:${targetPort} gate=${stream.gate}`);
  reply(sock, REP.SUCCESS);

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
