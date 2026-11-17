// Hollow shared crypto adapter (spec v0.1 §0.4, §5.3, §6.1).
// One implementation for Node (CLI) and Workers (nodejs_compat):
// - X25519 / HMAC-SHA256 / SHA-256 via WebCrypto (proven on both runtimes).
// - HKDF (RFC 5869) built from HMAC: Extract = HMAC(salt, IKM); Expand per RFC.
// - ChaCha20-Poly1305 (RFC 8439) via node:crypto — Workers WebCrypto does NOT
//   offer CHACHA20-POLY1305 (live-verified NP-1113-06), nodejs_compat does.
//   NP-1117-04: some runtimes' node:crypto lacks the algorithm entirely
//   (Electron 34's BoringSSL build throws ERR_CRYPTO_UNKNOWN_CIPHER). The
//   AEAD layer therefore probes node:crypto once at load and falls back to
//   the vendored pure-JS @noble/ciphers implementation (shared/vendor/,
//   pinned) when the native algorithm is missing. Protocol bytes are
//   identical on both backends (golden-vector locked, tests/aead.test.mjs).
// All primitives are the standard, mature ones named by the spec; no custom
// algorithm is introduced anywhere in this file.
import { createCipheriv, createDecipheriv } from "node:crypto";
import { nobleChacha20Poly1305 } from "./vendor/noble-ciphers-chacha20poly1305.js";

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

// ---- X25519 capability classification (NP-1117-06) ----
// Same pattern as the AEAD classification (NP-1117-04): a runtime that
// cannot run X25519 at all (WebCrypto lacks the algorithm) is a named,
// thrown error; a bad peer key stays a returned null (below).
export class X25519UnavailableError extends Error {
  constructor(message = "X25519 unavailable in this runtime (WebCrypto)") {
    super(message);
    this.name = "X25519UnavailableError";
    this.code = "X25519_UNAVAILABLE";
  }
}

let x25519Capability = null; // null = unprobed; boolean after the probe
async function probeX25519() {
  if (x25519Capability !== null) return x25519Capability;
  try {
    if (!globalThis.crypto || !crypto.subtle) { x25519Capability = false; return false; }
    await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
    x25519Capability = true;
  } catch (e) {
    // Only a definitive NotSupportedError marks the capability missing;
    // any other probe failure leaves the verdict to the operation itself.
    x25519Capability = e && e.name === "NotSupportedError" ? false : true;
  }
  return x25519Capability;
}

// Test-only hook (tests/x25519.test.mjs): forget the probe verdict so a
// stubbed WebCrypto is re-probed. Not used by any production path.
export function _resetX25519ProbeForTest() { x25519Capability = null; }

export async function x25519Generate() {
  try {
    const kp = await crypto.subtle.generateKey(
      { name: "X25519" }, true, ["deriveBits"]);
    const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    return { privateKey: kp.privateKey, publicRaw: pub };
  } catch (e) {
    if (e && e.name === "NotSupportedError") {
      x25519Capability = false;
      throw new X25519UnavailableError();
    }
    throw e;
  }
}

// Returns 32-byte shared secret, or null on failure / low-order peer key.
// Throws X25519UnavailableError when the runtime lacks X25519 entirely.
export async function x25519Derive(privateKey, peerPublicRaw) {
  if (!(await probeX25519())) throw new X25519UnavailableError();
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

// ---- AEAD backend selection + error classification (NP-1117-04) ----
// "Capability missing" (the runtime cannot run chacha20-poly1305 at all)
// is a named, thrown error — never folded into the null that means
// "authentication failed", so callers can report the real cause.
export class AeadUnavailableError extends Error {
  constructor(message = "chacha20-poly1305 AEAD unavailable in this runtime") {
    super(message);
    this.name = "AeadUnavailableError";
    this.code = "AEAD_UNAVAILABLE";
  }
}

function probeNativeAead() {
  try {
    createCipheriv("chacha20-poly1305", Buffer.alloc(32), Buffer.alloc(12), { authTagLength: 16 });
    return true;
  } catch {
    return false;
  }
}

const nativeAeadOk = probeNativeAead();
const jsAeadOk = typeof nobleChacha20Poly1305 === "function";
let aeadBackend = nativeAeadOk ? "native" : jsAeadOk ? "js" : "none";

// Which backend chachaSeal/chachaOpen will use: "native" | "js" | "none".
export function getAeadBackend() { return aeadBackend; }

// Test-only hook (tests/aead.test.mjs): force a backend, or null to
// restore the probed selection. Not used by any production path.
export function _forceAeadBackendForTest(backend) {
  if (backend === null) { aeadBackend = nativeAeadOk ? "native" : jsAeadOk ? "js" : "none"; return; }
  if (backend !== "native" && backend !== "js") throw new Error("unknown AEAD backend: " + backend);
  aeadBackend = backend;
}

function isUnknownCipher(e) {
  return e && (e.code === "ERR_CRYPTO_UNKNOWN_CIPHER" || /unknown cipher/i.test(String(e.message || e)));
}

function sealNative(key, nonce, plaintext) {
  try {
    const c = createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
    const ct = Buffer.concat([c.update(plaintext), c.final()]);
    return new Uint8Array(Buffer.concat([ct, c.getAuthTag()]));
  } catch (e) {
    if (isUnknownCipher(e)) throw new AeadUnavailableError();
    throw e;
  }
}

function openNative(key, nonce, ctTag) {
  try {
    const buf = Buffer.from(ctTag);
    const tag = buf.subarray(buf.length - 16);
    const ct = buf.subarray(0, buf.length - 16);
    const d = createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
    d.setAuthTag(tag);
    return new Uint8Array(Buffer.concat([d.update(ct), d.final()]));
  } catch (e) {
    if (isUnknownCipher(e)) throw new AeadUnavailableError();
    return null; // tag verification failure (fail-closed, unchanged)
  }
}

function sealJs(key, nonce, plaintext) {
  return nobleChacha20Poly1305(key, nonce).encrypt(plaintext);
}

function openJs(key, nonce, ctTag) {
  try {
    return nobleChacha20Poly1305(key, nonce).decrypt(ctTag);
  } catch {
    return null; // tag verification failure (fail-closed, unchanged)
  }
}

// RFC 8439 AEAD seal: returns ciphertext || tag(16).
// Throws AeadUnavailableError when no backend can run in this runtime.
export function chachaSeal(key, nonce, plaintext) {
  if (aeadBackend === "native") return sealNative(key, nonce, plaintext);
  if (aeadBackend === "js") return sealJs(key, nonce, plaintext);
  throw new AeadUnavailableError();
}

// Returns plaintext, or null on tag verification failure.
// Throws AeadUnavailableError when no backend can run in this runtime.
export function chachaOpen(key, nonce, ctTag) {
  if (aeadBackend === "native") return openNative(key, nonce, ctTag);
  if (aeadBackend === "js") return openJs(key, nonce, ctTag);
  throw new AeadUnavailableError();
}
