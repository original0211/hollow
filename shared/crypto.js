// Hollow shared crypto adapter (spec v0.1 §0.4, §5.3, §6.1).
// One implementation for Node (CLI) and Workers (nodejs_compat):
// - X25519 / HMAC-SHA256 / SHA-256 via WebCrypto (proven on both runtimes).
// - HKDF (RFC 5869) built from HMAC: Extract = HMAC(salt, IKM); Expand per RFC.
// - ChaCha20-Poly1305 (RFC 8439) via node:crypto — Workers WebCrypto does NOT
//   offer CHACHA20-POLY1305 (live-verified NP-1113-06), nodejs_compat does.
// All primitives are the standard, mature ones named by the spec; no custom
// algorithm is introduced anywhere in this file.
import { createCipheriv, createDecipheriv } from "node:crypto";

export function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

export async function hmac(key, msg) {
  const k = await crypto.subtle.importKey(
    "raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, msg));
}

// HKDF-Extract (RFC 5869): PRK = HMAC(salt, IKM)
export async function hkdfExtract(salt, ikm) {
  return hmac(salt, ikm);
}

// HKDF-Expand (RFC 5869), len <= 32 in this protocol (one block suffices,
// loop kept general).
export async function hkdfExpand(prk, info, len) {
  const out = new Uint8Array(len);
  let t = new Uint8Array(0);
  let off = 0;
  for (let i = 1; off < len; i++) {
    const buf = new Uint8Array(t.length + info.length + 1);
    buf.set(t, 0);
    buf.set(info, t.length);
    buf[buf.length - 1] = i;
    t = await hmac(prk, buf);
    const take = Math.min(32, len - off);
    out.set(t.subarray(0, take), off);
    off += take;
  }
  return out;
}

export async function x25519Generate() {
  const kp = await crypto.subtle.generateKey(
    { name: "X25519" }, true, ["deriveBits"]);
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  return { privateKey: kp.privateKey, publicRaw: pub };
}

// Returns 32-byte shared secret, or null on failure / low-order peer key.
export async function x25519Derive(privateKey, peerPublicRaw) {
  try {
    const pub = await crypto.subtle.importKey(
      "raw", peerPublicRaw, { name: "X25519" }, false, []);
    const bits = await crypto.subtle.deriveBits(
      { name: "X25519", public: pub }, privateKey, 256);
    const dh = new Uint8Array(bits);
    if (dh.every((b) => b === 0)) return null; // RFC 7748 low-order check (§5.3-1)
    return dh;
  } catch {
    return null;
  }
}

// RFC 8439 AEAD seal: returns ciphertext || tag(16).
export function chachaSeal(key, nonce, plaintext) {
  const c = createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return new Uint8Array(Buffer.concat([ct, c.getAuthTag()]));
}

// Returns plaintext, or null on tag verification failure.
export function chachaOpen(key, nonce, ctTag) {
  try {
    const buf = Buffer.from(ctTag);
    const tag = buf.subarray(buf.length - 16);
    const ct = buf.subarray(0, buf.length - 16);
    const d = createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
    d.setAuthTag(tag);
    return new Uint8Array(Buffer.concat([d.update(ct), d.final()]));
  } catch {
    return null;
  }
}
