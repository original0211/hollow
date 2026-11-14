// Golden vector generator (NP-1114-31). Policy: ../VECTORS.md.
// Runs the JS canonical implementation (shared/) and records outputs.
// Primitive anchors asserted BEFORE writing: HKDF/HMAC vs RFC constants,
// X25519 vs an independent BigInt ladder below. ChaCha's independence
// anchor is the Go side (x/crypto) asserting these very vectors.
import { writeFileSync } from "node:fs";
import {
  hmac, hkdfExtract, hkdfExpand, chachaSeal, chachaOpen,
  x25519Generate, x25519Derive,
} from "../../../shared/crypto.js";
import {
  PROTO_VERSION, FT, GATE, deriveVerifier, buildClientHello, parseClientHello,
  buildServerHello, parseServerHello, deriveSession, finishedMac,
  buildFrame, parseFrames, sealRecords, RecordReceiver, bucketFor,
  buildOpenPayload, parseOpenPayload, isPrivateIPv4Bytes, isPrivateIPv6Bytes,
  rejectPayload, resetPayload,
} from "../../../shared/protocol.js";
import { HollowClient } from "../../../shared/client-core.js";
import { HollowServer } from "../../../shared/server-core.js";

const hx = (b) => Buffer.from(b).toString("hex");
const un = (h) => new Uint8Array(Buffer.from(h, "hex"));
const rep = (byte, n) => new Uint8Array(n).fill(byte);
function assertEq(name, got, want) {
  if (hx(got) !== want) throw new Error(`ANCHOR FAIL ${name}: got ${hx(got)} want ${want}`);
  console.log("anchor ok:", name);
}

// ---- independent BigInt X25519 (RFC 7748 ladder), generator-only ----
function x25519Pure(privRaw, pubRaw) {
  const p = (1n << 255n) - 19n;
  const le = (b) => { let x = 0n; for (let i = 31; i >= 0; i--) x = (x << 8n) | BigInt(b[i]); return x; };
  const clamp = (b) => { const c = new Uint8Array(b); c[0] &= 248; c[31] &= 127; c[31] |= 64; return le(c); };
  const k = clamp(privRaw);
  const x1 = le(pubRaw) & ((1n << 255n) - 1n);
  let x2 = 1n, z2 = 0n, x3 = x1, z3 = 1n, swap = 0n;
  const a24 = 121665n;
  const mod = (x) => ((x % p) + p) % p;
  for (let t = 254; t >= 0; t--) {
    const bit = (k >> BigInt(t)) & 1n;
    swap ^= bit;
    if (swap === 1n) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
    swap = bit;
    const A = mod(x2 + z2), AA = mod(A * A), B = mod(x2 - z2), BB = mod(B * B);
    const E = mod(AA - BB), C = mod(x3 + z3), D = mod(x3 - z3);
    const DA = mod(D * A), CB = mod(C * B);
    x3 = mod((DA + CB) * (DA + CB)); z3 = mod(x1 * mod((DA - CB) * (DA - CB)));
    x2 = mod(AA * BB); z2 = mod(E * mod(AA + a24 * E));
  }
  if (swap === 1n) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
  const modPow = (base, exp) => { let r = 1n, b = mod(base); while (exp > 0n) { if (exp & 1n) r = mod(r * b); b = mod(b * b); exp >>= 1n; } return r; };
  const res = mod(x2 * modPow(z2, p - 2n));
  const out = new Uint8Array(32);
  let v = res; for (let i = 0; i < 32; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

const V = { specVersion: "v0.1.2", generatedBy: "shared/ JS canonical implementation via testvectors/generate.mjs" };

// ---------- primitives ----------
{
  const ikm = rep(0x0b, 22), salt = un("000102030405060708090a0b0c"), info = un("f0f1f2f3f4f5f6f7f8f9");
  const prk = await hkdfExtract(salt, ikm);
  assertEq("hkdf-extract RFC5869-1", prk, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
  const okm = await hkdfExpand(prk, info, 42);
  assertEq("hkdf-expand RFC5869-1", okm, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
  V.hkdf = [{ ikm: hx(ikm), salt: hx(salt), info: hx(info), prk: hx(prk), okm42: hx(okm) }];
}
{
  const out = await hmac(rep(0x0b, 20), new TextEncoder().encode("Hi There"));
  assertEq("hmac RFC4231-1", out, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  V.hmac = [{ key: hx(rep(0x0b, 20)), msg: hx(new TextEncoder().encode("Hi There")), out: hx(out) }];
}
{
  // X25519: fixed private scalars; public keys and shared secrets via the
  // implementation, cross-checked against the independent ladder.
  const aPriv = un("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
  const bPriv = un(Array.from({ length: 32 }, (_, i) => (0x40 + i).toString(16).padStart(2, "0")).join("")); // fixed scalar 0x40..0x5f
  const base = new Uint8Array(32); base[0] = 9;
  const aPub = x25519Pure(aPriv, base), bPub = x25519Pure(bPriv, base);
  const sharedPure = x25519Pure(aPriv, bPub);
  // via WebCrypto: import raw private keys through JWK
  const b64 = (b) => Buffer.from(b).toString("base64url");
  const importPriv = (priv, pub) => crypto.subtle.importKey("jwk",
    { kty: "OKP", crv: "X25519", x: b64(pub), d: b64(priv) }, { name: "X25519" }, false, ["deriveBits"]);
  const dh = await x25519Derive(await importPriv(aPriv, aPub), bPub);
  assertEq("x25519 vs BigInt ladder", dh, hx(sharedPure));
  V.x25519 = [{ aPriv: hx(aPriv), bPriv: hx(bPriv), aPub: hx(aPub), bPub: hx(bPub), shared: hx(dh) }];
}
{
  const key = un("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  const nonce = un("000102030405060708090a0b");
  const pt = new TextEncoder().encode("hello hollow record layer");
  const ct = chachaSeal(key, nonce, pt);
  const back = chachaOpen(key, nonce, ct);
  if (hx(back) !== hx(pt)) throw new Error("chacha roundtrip broken");
  const tampered = new Uint8Array(ct); tampered[3] ^= 1;
  if (chachaOpen(key, nonce, tampered) !== null) throw new Error("chacha tamper not detected");
  V.chacha = [{ key: hx(key), nonce: hx(nonce), plaintext: hx(pt), sealed: hx(ct) }];
}

// ---------- handshake chain ----------
const psk = un("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
const verifier = await deriveVerifier(psk);
const clientPub = un(V.x25519[0].aPub), serverPub = un(V.x25519[0].bPub);
const clientRandom = un("c000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".slice(0, 64));
const serverRandom = un("50000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".slice(0, 64));
const padC = un("aa".repeat(17)), padS = un("bb".repeat(9));
const clientHello = buildClientHello({ versions: [PROTO_VERSION], keyId: 1, publicRaw: clientPub, random: clientRandom, padding: padC });
const serverHello = buildServerHello({ selectedVersion: PROTO_VERSION, publicRaw: serverPub, random: serverRandom, padding: padS });
if (!parseClientHello(clientHello) || !parseServerHello(serverHello)) throw new Error("hello parse broken");
const dh = un(V.x25519[0].shared);
const sess = await deriveSession({ dh, verifier, clientRandom, serverRandom, clientHello, serverHello });
const finS = await finishedMac(sess.fS, sess.th, "server");
const finC = await finishedMac(sess.fC, sess.th, "client");
V.handshake = {
  psk: hx(psk), verifier: hx(verifier),
  clientHello: hx(clientHello), serverHello: hx(serverHello),
  th: hx(sess.th), kC2s: hx(sess.kC2s), kS2c: hx(sess.kS2c),
  ivC2s: hx(sess.ivC2s), ivS2c: hx(sess.ivS2c),
  finishedServerMac: hx(finS), finishedClientMac: hx(finC),
};

// ---------- records ----------
{
  const frames = [
    buildFrame(FT.FINISH, 0, finC),
    buildFrame(FT.DATA, 1, new TextEncoder().encode("abc")),
    buildFrame(FT.DATA, 1, rep(0x61, 5000)), // forces a second bucket
    buildFrame(FT.PING, 0, un("01020304")),
  ];
  const { records, nextSeq } = sealRecords(sess.kC2s, sess.ivC2s, 0, frames);
  const rx = new RecordReceiver(sess.kC2s, sess.ivC2s);
  const blobs = records.map((r) => {
    const opened = rx.open(r);
    if (!opened) throw new Error("record open failed in generator");
    return hx(opened.framesBlob);
  });
  V.records = {
    key: hx(sess.kC2s), iv: hx(sess.ivC2s),
    framesHex: frames.map(hx), recordsHex: records.map(hx), nextSeq, framesBlobsHex: blobs,
    bucketFor: [0, 100, 510, 511, 4094, 4095, 16382].map((n) => [n, bucketFor(n)]),
  };
}

// ---------- frame parsing ----------
{
  const good = Buffer.concat([
    buildFrame(FT.OPEN, 1, buildOpenPayload({ host: "example.com", port: 443 })),
    buildFrame(FT.DATA, 1, un("deadbeef")), buildFrame(FT.CLOSE, 1, un("00")),
  ]);
  const p1 = parseFrames(new Uint8Array(good));
  const trailing = parseFrames(new Uint8Array(Buffer.concat([good, un("0102030405")])));
  const oversizePayload = new Uint8Array(16374); // MAX_PAYLOAD+1, fits blob exactly
  const oversizeBlob = buildFrame(FT.DATA, 7, oversizePayload);
  const p3 = parseFrames(oversizeBlob);
  V.frames = {
    goodBlob: hx(good), goodCount: p1.frames.length, goodRecordError: p1.recordError,
    trailingRecordError: trailing.recordError,
    oversizeBlobLen: oversizeBlob.length, oversizeCount: p3.oversize.length, oversizeFrames: p3.frames.length,
  };
}

// ---------- open payload / misc ----------
{
  const cases = [
    { host: "example.com", port: 443, schemeHint: 2, gatePolicy: 0 },
    { host: "192.0.2.7", port: 80, schemeHint: 1, gatePolicy: 0 },
    { host: "2001:db8::1", port: 8443, schemeHint: 0, gatePolicy: 0 },
  ];
  V.openPayload = cases.map((c) => {
    const p = buildOpenPayload(c);
    const back = parseOpenPayload(p);
    // NOTE: the JS ipv6FromBytes renders UNCOMPRESSED groups
    // ("2001:db8:0:0:0:0:0:1"). The vector records that exact rendering —
    // the Go port must match the canonical implementation's behavior,
    // not the prettier form (behavioral lock, VECTORS.md).
    const wantHost = c.host.includes(":") ? "2001:db8:0:0:0:0:0:1" : c.host;
    if (!back || back.host !== wantHost || back.port !== c.port) throw new Error("open payload roundtrip broken: " + JSON.stringify(back) + " vs " + JSON.stringify(c));
    return { ...c, parsedHost: back.host, payload: hx(p) };
  });
  V.misc = {
    rejectPayload: hx(rejectPayload(0x01, 1000)), resetPayload: hx(resetPayload(0x0c)),
    banV4: ["127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "172.32.0.1", "192.168.1.1", "169.254.1.1", "8.8.8.8", "0.0.0.0"].map((s) => [s, isPrivateIPv4Bytes(new Uint8Array(s.split(".").map(Number)))]),
  };
}

// ---------- session transcript (real JS client <-> real JS server) ----------
{
  // Deterministic padding lengths (content stays recorded fact below).
  let seed = 42;
  Math.random = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x80000000; };

  const transcript = [];
  function endpoint(dir) {
    return {
      _cb: null, _closeCb: null, _peer: null,
      send(b) { transcript.push({ dir, hex: hx(b) }); const p = this._peer; queueMicrotask(() => p._cb && p._cb(new Uint8Array(b))); },
      onMessage(cb) { this._cb = cb; },
      onClose(cb) { this._closeCb = cb; },
      close() { const p = this._peer; queueMicrotask(() => p._closeCb && p._closeCb()); },
      closeCarrier() { this.close(); },
    };
  }
  const ct = endpoint("c2s"), st = endpoint("s2c");
  ct._peer = st; st._peer = ct;

  let readCtl; const targetGot = [];
  const readable = new ReadableStream({ start(c) { readCtl = c; } });
  const writable = new WritableStream({ write(chunk) { targetGot.push(new Uint8Array(chunk)); } });
  const sock = { readable, writable, opened: Promise.resolve(), close() { try { readCtl.close(); } catch {} } };

  const server = new HollowServer({
    transport: st, verifiers: new Map([[1, verifier]]),
    ownHost: "hollow.test", zoneSuffix: "hollow.test",
    connectFn: async () => sock, fetchFn: null,
  });
  const client = new HollowClient({ transport: ct, psk, keyId: 1 });
  const clientGot = [];
  const settle = async () => {
    let last = -1;
    while (last !== transcript.length) { last = transcript.length; await new Promise((r) => setTimeout(r, 40)); }
  };

  await client.handshake();
  await settle();
  const stream = client.openStream({ host: "example.com", port: 443, schemeHint: 2 });
  stream.onData = (d) => clientGot.push(new Uint8Array(d));
  await stream.opened;
  await settle();

  const up = rep(0x75, 100 * 1024); // 100 KiB client -> target
  stream.write(up);
  client.sender.flush();
  await settle();
  const upGot = targetGot.reduce((s, c) => s + c.length, 0);
  if (upGot !== up.length) throw new Error(`transcript: target got ${upGot} != ${up.length}`);

  const down = rep(0x64, 100 * 1024);
  for (let i = 0; i < 3; i++) { readCtl.enqueue(new Uint8Array(down)); await settle(); }
  const downGot = clientGot.reduce((s, c) => s + c.length, 0);
  if (downGot !== 300 * 1024) throw new Error(`transcript: client got ${downGot} != ${300 * 1024}`);

  server._sendFrame(buildFrame(FT.PING, 0, un("01020304")), true);
  await settle();

  stream.closeWrite();
  await settle();
  readCtl.close(); // target EOF -> server CLOSE
  await settle();
  if (client.streams.size !== 0) throw new Error("transcript: stream not freed at end");
  if (client.state !== "open") throw new Error("transcript: session not open at end");

  const jwk = await crypto.subtle.exportKey("jwk", client._eph.privateKey);
  const privRaw = new Uint8Array(Buffer.from(jwk.d, "base64url"));
  const helloBytes = un(transcript[0].hex);
  // Parse padding out of the recorded ClientHello bytes directly.
  const vc = helloBytes[1];
  const padOff = 1 + 1 + vc + 1 + 32 + 32;
  const padLenReal = helloBytes[padOff];
  const padding = helloBytes.slice(padOff + 1, padOff + 1 + padLenReal);
  V.transcript = {
    psk: hx(psk), clientPrivRaw: hx(privRaw),
    clientRandom: hx(client._clientRandom), clientPadding: hx(padding),
    messages: transcript,
  };
  console.log(`transcript ok: ${transcript.length} wire messages`);
}

writeFileSync(new URL("./vectors-v0.1.2.json", import.meta.url), JSON.stringify(V, null, 1) + "\n");
console.log("vectors written");
