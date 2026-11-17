// AEAD backend tests (NP-1117-04): the vendored pure-JS fallback must be
// byte-identical to node:crypto's chacha20-poly1305, both must reproduce
// the RFC 8439 A.5 golden vector, the vendored file must match its pin,
// and auth failure must stay null (fail-closed) on both backends while
// capability loss is a named thrown error.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { createCipheriv } from "node:crypto";
import { fileURLToPath } from "node:url";
import {
  chachaSeal, chachaOpen, getAeadBackend, _forceAeadBackendForTest,
  AeadUnavailableError,
} from "../shared/crypto.js";
import { nobleChacha20Poly1305 } from "../shared/vendor/noble-ciphers-chacha20poly1305.js";

const hx = (s) => Uint8Array.from(s.replace(/\s/g, "").match(/../g).map((h) => parseInt(h, 16)));
const hex = (b) => Buffer.from(b).toString("hex");

// RFC 8439 Appendix A.5 ( ChaCha20-Poly1305 AEAD, with AAD ).
const A5 = {
  key: "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
  nonce: "000000000102030405060708",
  aad: "f33388860000000000004e91",
  pt: "496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d",
  ctPrefix: "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf",
  tag: "eead9d67890cbb22392336fea1851f38",
};

test("vendored noble bundle matches its PIN.json sha256", () => {
  const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "shared", "vendor");
  const pin = JSON.parse(fs.readFileSync(path.join(dir, "PIN.json"), "utf8"));
  const file = fs.readFileSync(path.join(dir, pin.vendoredFile));
  assert.equal(crypto.createHash("sha256").update(file).digest("hex"), pin.vendoredSha256);
  assert.equal(pin.package, "@noble/ciphers");
});

test("RFC 8439 A.5 golden vector — JS backend (noble, with AAD)", () => {
  const out = nobleChacha20Poly1305(hx(A5.key), hx(A5.nonce), hx(A5.aad)).encrypt(hx(A5.pt));
  assert.equal(out.length, 265 + 16);
  assert.ok(hex(out).startsWith(A5.ctPrefix));
  // The Poly1305 tag authenticates the whole ciphertext + AAD, so an
  // exact tag match pins every ciphertext byte to the RFC.
  assert.equal(hex(out.slice(-16)), A5.tag);
  const back = nobleChacha20Poly1305(hx(A5.key), hx(A5.nonce), hx(A5.aad)).decrypt(out);
  assert.equal(hex(back), A5.pt);
});

test("RFC 8439 A.5 golden vector — native backend (node:crypto, with AAD)", () => {
  const c = createCipheriv("chacha20-poly1305", hx(A5.key), hx(A5.nonce), { authTagLength: 16 });
  c.setAAD(Buffer.from(hx(A5.aad)));
  const ct = Buffer.concat([c.update(Buffer.from(hx(A5.pt))), c.final()]);
  assert.ok(ct.toString("hex").startsWith(A5.ctPrefix));
  assert.equal(c.getAuthTag().toString("hex"), A5.tag);
});

test("wrapper backends are byte-identical (no AAD, protocol shape)", () => {
  const key = hx("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  const nonce = hx("202122232425262728292a2b");
  for (const len of [0, 1, 63, 64, 265, 512, 4096, 16384]) {
    const pt = Uint8Array.from({ length: len }, (_, i) => (i * 31 + len) & 0xff);
    _forceAeadBackendForTest("native");
    const sealedNative = chachaSeal(key, nonce, pt);
    _forceAeadBackendForTest("js");
    const sealedJs = chachaSeal(key, nonce, pt);
    assert.equal(hex(sealedJs), hex(sealedNative), `seal mismatch at len=${len}`);
    // cross-open both ways
    _forceAeadBackendForTest("native");
    assert.equal(hex(chachaOpen(key, nonce, sealedJs)), hex(pt));
    _forceAeadBackendForTest("js");
    assert.equal(hex(chachaOpen(key, nonce, sealedNative)), hex(pt));
  }
  _forceAeadBackendForTest(null);
});

test("auth failure stays null on both backends (fail-closed)", () => {
  const key = hx("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  const nonce = hx("202122232425262728292a2b");
  for (const backend of ["native", "js"]) {
    _forceAeadBackendForTest(backend);
    const sealed = chachaSeal(key, nonce, new TextEncoder().encode("hello"));
    const tampered = Uint8Array.from(sealed);
    tampered[tampered.length - 1] ^= 1;
    assert.equal(chachaOpen(key, nonce, tampered), null, `${backend} must return null on bad tag`);
  }
  _forceAeadBackendForTest(null);
});

test("auto-selection picks native where node:crypto offers the algorithm", () => {
  _forceAeadBackendForTest(null);
  assert.equal(getAeadBackend(), "native");
});

test("AeadUnavailableError is a named Error subclass", () => {
  const e = new AeadUnavailableError();
  assert.ok(e instanceof Error);
  assert.equal(e.name, "AeadUnavailableError");
  assert.equal(e.code, "AEAD_UNAVAILABLE");
});
