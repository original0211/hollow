// Hollow shared protocol core (frozen spec v0.1: files/m1/protocol-spec-v0.1.md).
// Pure byte/framing/record/handshake-derivation logic, no transport, no I/O.
// Crypto comes from shared/crypto.js. Any conflict between this file and the
// frozen spec is a bug in this file, never a spec change.
import {
  sha256, hmac, hkdfExtract, hkdfExpand, chachaSeal, chachaOpen,
} from "./crypto.js";

export const PROTO_VERSION = 0x01;
export const BUCKETS = [512, 4096, 16384];
export const MAX_PAYLOAD = 16373; // §6.1: 16384 - 2 (len head) - 9 (frame head)
export const FRAME_HEAD = 9;
export const CONN_WINDOW_INIT = 1 << 20; // §6.5: 1 MiB
export const STREAM_WINDOW_INIT = 256 * 1024; // §6.5: 256 KiB
// §6.5 as of spec v0.2.1 (NP-1117-25): the INIT values above stay the
// symmetric starting assumption every endpoint may rely on (they are
// what a pre-v0.2.1 peer grants and expects). A v0.2.1 receiver grants
// up to the GRANT targets below, expressed on the wire as an immediate
// WINDOW_UPDATE top-up when the session/stream starts (conn: right
// after the handshake; stream: at creation), so mixed old/new pairs
// interoperate: the old peer simply never receives a smaller grant
// than the INIT it assumed, and a new sender never assumes more than
// the INIT until a top-up actually arrives.
export const CONN_WINDOW_GRANT = 8 << 20; // §6.5 v0.2.1: 8 MiB
export const STREAM_WINDOW_GRANT = 1 << 20; // §6.5 v0.2.1: 1 MiB
export const MERGE_WINDOW_MS = 2; // §6.4
export const MAX_OCCUPANCY = 6; // §7.5 (worst case, U-1 open)
export const QUEUE_DEPTH = 32; // §7.5
export const QUEUE_MAX_WAIT_MS = 5000; // §7.5
export const QUEUE_RETRY_AFTER_MS = 1000; // §7.5 / §8.3
export const FETCH_CONCURRENCY = 2; // §7.4
export const FETCH_BODY_MAX = 4 * 1024 * 1024; // §7.4
export const RECORD_FAIL_LIMIT = 3; // §6.1 consecutive
export const STREAM_ERROR_LIMIT = 10; // §8.2

export const FT = {
  FINISH: 0x00, OPEN: 0x01, OPEN_OK: 0x02, OPEN_REJECT: 0x03, DATA: 0x04,
  CLOSE: 0x05, RESET: 0x06, WINDOW_UPDATE: 0x07, PING: 0x08, PONG: 0x09,
  GOAWAY: 0x0a, OPEN_QUEUED: 0x0b,
};
export const ERR = {
  CONCURRENCY_LIMIT: 0x01, PROHIBITED_PORT: 0x02, PRIVATE_TARGET: 0x03,
  CF_SEGMENT_NON_HTTP: 0x04, TARGET_UNREACHABLE: 0x05, OUTBOUND_FAILED: 0x06,
  FETCH_FALLBACK_FAILED: 0x07, FETCH_PROFILE_UNSUPPORTED: 0x08,
  FETCH_BODY_TOO_LARGE: 0x09, LOOP_TARGET: 0x0a, UNSUPPORTED_TARGET: 0x0b,
  PROTOCOL_ERROR: 0x0c, FLOW_CONTROL_VIOLATION: 0x0d, QUOTA_GUARD: 0x0e,
  SERVER_CLOSING: 0x0f, STREAM_TIMEOUT: 0x10,
};
export const GATE = { CONNECT: 0x00, FETCH: 0x01 };
export const SCHEME = { UNKNOWN: 0x00, HTTP: 0x01, HTTPS: 0x02 };

// ---------- byte helpers (all integers big-endian, §0.4) ----------
export function concat(...parts) {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}
export function u16be(n) { return new Uint8Array([(n >> 8) & 0xff, n & 0xff]); }
export function u32be(n) {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}
export function readU16(b, off) { return (b[off] << 8) | b[off + 1]; }
export function readU32(b, off) {
  return ((b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]) >>> 0;
}
export function utf8(s) { return new TextEncoder().encode(s); }
export function eq(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

// ---------- §1.1 verifier ----------
export async function deriveVerifier(psk) {
  return hmac(psk, utf8("newproto-v0.1-server-verifier"));
}

// ---------- §5.1 / §5.2 hello messages ----------
export function buildClientHello({ versions, keyId, publicRaw, random, padding }) {
  const head = new Uint8Array(1 + 1 + versions.length + 1 + 32 + 32 + 1);
  let o = 0;
  head[o++] = 0x01;
  head[o++] = versions.length;
  for (const v of versions) head[o++] = v;
  head[o++] = keyId;
  head.set(publicRaw, o); o += 32;
  head.set(random, o); o += 32;
  head[o++] = padding.length;
  return concat(head, padding);
}
export function parseClientHello(b) {
  if (b.length < 1 + 1 + 1 + 32 + 32 + 1) return null;
  let o = 0;
  if (b[o++] !== 0x01) return null;
  const vc = b[o++];
  if (vc < 1 || b.length < 1 + 1 + vc + 1 + 32 + 32 + 1) return null;
  const versions = Array.from(b.subarray(o, o + vc)); o += vc;
  const keyId = b[o++];
  const publicRaw = b.slice(o, o + 32); o += 32;
  const random = b.slice(o, o + 32); o += 32;
  const padLen = b[o++];
  if (padLen > 128 || o + padLen !== b.length) return null;
  return { versions, keyId, publicRaw, random };
}
export function buildServerHello({ selectedVersion, publicRaw, random, padding }) {
  const head = new Uint8Array(1 + 1 + 32 + 32 + 1);
  let o = 0;
  head[o++] = 0x02;
  head[o++] = selectedVersion;
  head.set(publicRaw, o); o += 32;
  head.set(random, o); o += 32;
  head[o++] = padding.length;
  return concat(head, padding);
}
export function parseServerHello(b) {
  if (b.length !== 1 + 1 + 32 + 32 + 1 + b[66]) return null; // length must match padding_len exactly
  if (b[0] !== 0x02) return null;
  const padLen = b[66];
  if (padLen > 128) return null;
  return {
    selectedVersion: b[1],
    publicRaw: b.slice(2, 34),
    random: b.slice(34, 66),
  };
}

// ---------- §5.3 session derivation ----------
export async function deriveSession({ dh, verifier, clientRandom, serverRandom, clientHello, serverHello }) {
  const th = await sha256(concat(clientHello, serverHello));
  const ms = await hkdfExtract(concat(clientRandom, serverRandom), concat(dh, verifier));
  const expand = (label, len) => hkdfExpand(ms, concat(utf8(label), th), len);
  const [kC2s, kS2c, ivC2s, ivS2c, fC, fS] = await Promise.all([
    expand("np-v0.1 c2s key", 32), expand("np-v0.1 s2c key", 32),
    expand("np-v0.1 c2s iv", 12), expand("np-v0.1 s2c iv", 12),
    expand("np-v0.1 client finished", 32), expand("np-v0.1 server finished", 32),
  ]);
  return { th, kC2s, kS2c, ivC2s, ivS2c, fC, fS };
}
export async function finishedMac(fKey, th, who) {
  return hmac(fKey, concat(th, utf8(who))); // who: "server" | "client" (§5.4)
}

// ---------- §6.2 stream frames ----------
export function buildFrame(type, streamId, payload = new Uint8Array(0)) {
  const head = new Uint8Array(FRAME_HEAD);
  head[0] = type;
  head.set(u32be(streamId), 1);
  head.set(u32be(payload.length), 5);
  return concat(head, payload);
}
// Parse one record's frames_blob.
// Returns { frames, recordError, oversize: [{streamId}] }.
// R-1113-05-01 split (§6.1 / §8.2):
// - frames not exactly exhausting frames_len (overrun / trailing bytes /
//   truncated head) -> recordError (record-level failure counting, §6.1)
// - a frame whose payload_len exceeds the 16,373 hard cap but otherwise fits
//   exactly inside the blob -> stream-level error for that stream (RESET, §8.2)
export function parseFrames(blob) {
  const frames = [];
  const oversize = [];
  let off = 0;
  while (off < blob.length) {
    if (blob.length - off < FRAME_HEAD) return { frames, recordError: true, oversize };
    const type = blob[off];
    const streamId = readU32(blob, off + 1);
    const payloadLen = readU32(blob, off + 5);
    if (off + FRAME_HEAD + payloadLen > blob.length) {
      return { frames, recordError: true, oversize };
    }
    const payload = blob.slice(off + FRAME_HEAD, off + FRAME_HEAD + payloadLen);
    if (payloadLen > MAX_PAYLOAD) oversize.push({ streamId });
    else frames.push({ type, streamId, payload });
    off += FRAME_HEAD + payloadLen;
  }
  return { frames, recordError: false, oversize };
}

// ---------- §6.1 record layer ----------
export function bucketFor(framesLen) {
  for (const b of BUCKETS) if (2 + framesLen <= b) return b;
  return null;
}
export function nonceFor(iv, seq) {
  const nonce = new Uint8Array(iv);
  // XOR with (0x00000000 || u64be(seq)): only the last 8 bytes change.
  let s = BigInt(seq);
  for (let i = 11; i >= 4; i--) {
    nonce[i] ^= Number(s & 0xffn);
    s >>= 8n;
  }
  return nonce;
}
// Seal a list of frames into one or more WS messages (records). Frames never
// split across records (§6.1-3); records are bucket-sized + 16B tag on the wire.
export function sealRecords(key, iv, startSeq, frames) {
  const records = [];
  let seq = startSeq;
  let blob = [];
  let blobLen = 0;
  const flush = () => {
    if (blob.length === 0) return;
    const framesBlob = concat(...blob);
    const bucket = bucketFor(framesBlob.length);
    const pt = new Uint8Array(bucket);
    pt.set(u16be(framesBlob.length), 0);
    pt.set(framesBlob, 2); // remainder is zero padding by construction
    records.push(chachaSeal(key, nonceFor(iv, seq), pt));
    seq++;
    blob = []; blobLen = 0;
  };
  for (const f of frames) {
    if (f.length > MAX_PAYLOAD + FRAME_HEAD) throw new Error("frame too large");
    if (blobLen + f.length > BUCKETS[2] - 2) flush();
    blob.push(f); blobLen += f.length;
  }
  flush();
  return { records, nextSeq: seq };
}
// Stateful receiver for one direction. Failure counting (§6.1): AEAD and
// record-structure failures increment inside open(); frame-exhaustion
// failures are reported by the session via noteFailure() after parseFrames;
// a fully valid record is confirmed via noteSuccess() (resets the
// consecutive counter). This keeps mixed failure kinds consecutive.
export class RecordReceiver {
  constructor(key, iv) {
    this.key = key; this.iv = iv;
    this.expectSeq = 0;
    this.consecFails = 0;
  }
  noteFailure() { this.consecFails++; }
  noteSuccess() { this.consecFails = 0; }
  // Returns { framesBlob } when the record decrypts and is structurally
  // sound at record level, null on record-level failure (§6.1).
  open(msgBytes) {
    const pt = chachaOpen(this.key, nonceFor(this.iv, this.expectSeq), msgBytes);
    if (pt === null) { this.consecFails++; return null; }
    const framesLen = readU16(pt, 0);
    const bucket = BUCKETS.includes(pt.length) ? pt.length : null;
    if (bucket === null || 2 + framesLen > pt.length) { this.consecFails++; return null; }
    for (let i = 2 + framesLen; i < pt.length; i++) {
      if (pt[i] !== 0) { this.consecFails++; return null; } // padding must be all zero
    }
    this.expectSeq++;
    return { framesBlob: pt.slice(2, 2 + framesLen) };
  }
}

// ---------- §6.4 record sender with merge window ----------
// Control frames flush immediately when pushed; DATA frames may wait up to
// MERGE_WINDOW_MS to coalesce into one record (bucket efficiency, §6.4).
export class RecordSender {
  constructor(key, iv, send) {
    this.key = key; this.iv = iv; this.seq = 0; this.send = send;
    this.queue = []; this.timer = null;
  }
  push(frameBytes, immediate) {
    this.queue.push(frameBytes);
    if (immediate) this.flush();
    else if (!this.timer) {
      this.timer = setTimeout(() => this.flush(), MERGE_WINDOW_MS);
    }
  }
  flush() {
    if (this.timer) { clearTimeout(this.timer); this.timer = null; }
    if (this.queue.length === 0) return;
    const frames = this.queue; this.queue = [];
    const { records, nextSeq } = sealRecords(this.key, this.iv, this.seq, frames);
    this.seq = nextSeq;
    for (const r of records) this.send(r);
  }
}

// ---------- §6.3 OPEN payload ----------
export function buildOpenPayload({ host, port, schemeHint = 0, gatePolicy = 0 }) {
  let addrType, addr;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    addrType = 0x01;
    addr = new Uint8Array(host.split(".").map(Number));
  } else if (host.includes(":")) {
    addrType = 0x02;
    addr = ipv6ToBytes(host);
  } else {
    const name = utf8(host);
    if (name.length > 253) throw new Error("domain too long");
    addrType = 0x03;
    addr = concat(new Uint8Array([name.length]), name);
  }
  return concat(new Uint8Array([addrType]), addr, u16be(port),
    new Uint8Array([schemeHint, gatePolicy]));
}
export function parseOpenPayload(p) {
  if (p.length < 1 + 2 + 1 + 1) return null;
  const addrType = p[0];
  let o = 1, host, addrBytes = null;
  if (addrType === 0x01) {
    if (p.length < o + 4 + 4) return null;
    addrBytes = p.slice(o, o + 4);
    host = Array.from(addrBytes).join(".");
    o += 4;
  } else if (addrType === 0x02) {
    if (p.length < o + 16 + 4) return null;
    addrBytes = p.slice(o, o + 16);
    host = ipv6FromBytes(addrBytes);
    o += 16;
  } else if (addrType === 0x03) {
    const len = p[o++];
    if (len < 1 || len > 253 || p.length < o + len + 4) return null;
    host = new TextDecoder().decode(p.subarray(o, o + len));
    o += len;
  } else return null;
  const port = readU16(p, o); o += 2;
  const schemeHint = p[o++];
  const gatePolicy = p[o++];
  if (o !== p.length) return null;
  return { addrType, host, addrBytes, port, schemeHint, gatePolicy };
}
export function ipv6ToBytes(host) {
  // Minimal parser for literal IPv6 (full + "::" compressed), used by clients.
  const halves = host.split("::");
  let groups = [];
  const parseSide = (s) => (s ? s.split(":").map((g) => parseInt(g, 16)) : []);
  if (halves.length === 2) {
    const left = parseSide(halves[0]), right = parseSide(halves[1]);
    const fill = 8 - left.length - right.length;
    if (fill < 0) throw new Error("bad ipv6");
    groups = [...left, ...Array(fill).fill(0), ...right];
  } else {
    groups = parseSide(host);
  }
  // IPv4-mapped tail like ::ffff:1.2.3.4 (host string kept simple: not supported)
  if (groups.length !== 8 || groups.some((g) => Number.isNaN(g) || g < 0 || g > 0xffff)) {
    throw new Error("bad ipv6");
  }
  const out = new Uint8Array(16);
  groups.forEach((g, i) => { out[i * 2] = g >> 8; out[i * 2 + 1] = g & 0xff; });
  return out;
}
export function ipv6FromBytes(b) {
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push(((b[i] << 8) | b[i + 1]).toString(16));
  return groups.join(":");
}

// ---------- §7.2 ban list (literal IPs) ----------
export function isPrivateIPv4Bytes(b) {
  const [a, c] = [b[0], b[1]];
  if (a === 127 || a === 10 || a === 0) return true;
  if (a === 172 && c >= 16 && c <= 31) return true;
  if (a === 192 && c === 168) return true;
  if (a === 169 && c === 254) return true;
  return false;
}
export function isPrivateIPv6Bytes(b) {
  if (b.every((x, i) => x === (i === 15 ? 1 : 0))) return true; // ::1
  if ((b[0] & 0xfe) === 0xfc) return true; // fc00::/7
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return true; // fe80::/10
  // IPv4-mapped ::ffff:a.b.c.d judged by its IPv4 ranges (defensive)
  if (b.subarray(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff) {
    return isPrivateIPv4Bytes(b.subarray(12, 16));
  }
  if (b.every((x) => x === 0)) return true; // :: unspecified
  return false;
}

// ---------- §8.3 payloads ----------
export function rejectPayload(code, retryAfterMs = 0) {
  return concat(new Uint8Array([code]), u16be(retryAfterMs), new Uint8Array([0]));
}
export function resetPayload(code) {
  return concat(new Uint8Array([code]), u16be(0));
}
