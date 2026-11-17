// X25519 error-classification tests (NP-1117-06): capability missing
// (WebCrypto has no X25519) must throw the named X25519UnavailableError,
// while low-order and malformed peer keys keep returning null — the
// fail-closed semantics the red team froze.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  x25519Generate, x25519Derive,
  X25519UnavailableError, _resetX25519ProbeForTest,
} from "../shared/crypto.js";

test("X25519UnavailableError is a named Error subclass", () => {
  const e = new X25519UnavailableError();
  assert.ok(e instanceof Error);
  assert.equal(e.name, "X25519UnavailableError");
  assert.equal(e.code, "X25519_UNAVAILABLE");
});

test("normal derive: both sides agree on a 32-byte secret", async () => {
  const a = await x25519Generate();
  const b = await x25519Generate();
  const s1 = await x25519Derive(a.privateKey, b.publicRaw);
  const s2 = await x25519Derive(b.privateKey, a.publicRaw);
  assert.ok(s1 && s1.length === 32);
  assert.deepEqual(s1, s2);
});

test("low-order peer key (all zero) still returns null", async () => {
  const a = await x25519Generate();
  const s = await x25519Derive(a.privateKey, new Uint8Array(32));
  assert.equal(s, null);
});

test("malformed peer keys still return null", async () => {
  const a = await x25519Generate();
  assert.equal(await x25519Derive(a.privateKey, new Uint8Array(31)), null);
  assert.equal(await x25519Derive(a.privateKey, new Uint8Array(33)), null);
  assert.equal(await x25519Derive(a.privateKey, new Uint8Array(0)), null);
});

test("capability missing (stubbed WebCrypto) throws the named error", async () => {
  const subtle = globalThis.crypto.subtle;
  const a = await x25519Generate(); // a real keypair, made before stubbing
  const origGenerateKey = subtle.generateKey;
  subtle.generateKey = async () => {
    throw new DOMException("X25519 not supported", "NotSupportedError");
  };
  try {
    _resetX25519ProbeForTest();
    await assert.rejects(x25519Derive(a.privateKey, a.publicRaw), (e) => {
      assert.ok(e instanceof X25519UnavailableError);
      assert.equal(e.code, "X25519_UNAVAILABLE");
      return true;
    });
    await assert.rejects(x25519Generate(), X25519UnavailableError);
  } finally {
    subtle.generateKey = origGenerateKey;
    _resetX25519ProbeForTest();
  }
  // capability restored: derive works again (probe re-runs clean)
  const b = await x25519Generate();
  const s = await x25519Derive(a.privateKey, b.publicRaw);
  assert.ok(s && s.length === 32);
});
