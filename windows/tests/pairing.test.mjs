// Pairing tests (M2-3, NP-1114-07): payload forms, validation, export rules,
// preview hygiene (never carries the PSK), QR roundtrip, and the config-side
// red-team notes (corrupt PSK is a hard error; ACL args from OS identity).
import { test as _test } from "node:test";
const test = (name, fn) => _test(name, { timeout: 15000 }, fn);
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { buildLink, parseLink, buildExportObject, parseExportObject, parseAnyPayload, previewOf, qrPixels, decodeQrFromPixels, bgraToRgba } from "../src/pairing.js";
import { verifierHex } from "../src/config.js";

const PSK = new Uint8Array(crypto.randomBytes(32));
const URL_OK = "wss://newproto-hollow.newproto.workers.dev/";

test("link roundtrip with and without PSK", () => {
  const withKey = parseLink(buildLink({ workerUrl: URL_OK, keyId: 1, psk: PSK }));
  assert.equal(withKey.workerUrl, URL_OK);
  assert.deepEqual(withKey.psk, PSK);
  const noKey = parseLink(buildLink({ workerUrl: URL_OK }));
  assert.equal(noKey.psk, null);
  assert.equal(noKey.keyId, 1);
});

test("export object: PSK absent by default; parse roundtrip", () => {
  const plain = buildExportObject({ workerUrl: URL_OK });
  assert.equal("pskBase64" in plain, false);
  const withKey = buildExportObject({ workerUrl: URL_OK, psk: PSK });
  const parsed = parseExportObject(JSON.stringify(withKey));
  assert.deepEqual(parsed.psk, PSK);
  assert.equal(parsed.workerUrl, URL_OK);
});

test("parseAnyPayload dispatches by form and rejects junk", () => {
  assert.equal(parseAnyPayload(buildLink({ workerUrl: URL_OK })).workerUrl, URL_OK);
  assert.equal(parseAnyPayload(JSON.stringify(buildExportObject({ workerUrl: URL_OK }))).workerUrl, URL_OK);
  assert.throws(() => parseAnyPayload("https://evil.example/phish"), /unrecognized/);
  assert.throws(() => parseAnyPayload(""), /unrecognized|too large/);
  assert.throws(() => parseAnyPayload("x".repeat(9000)), /unrecognized|too large/);
});

test("validation bites: bad schemes, short PSK, wrong app marker", () => {
  assert.throws(() => buildLink({ workerUrl: "http://insecure.example/" }), /wss/);
  assert.throws(() => buildLink({ workerUrl: "ws://remote.example/" }), /wss/);
  assert.equal(parseLink(buildLink({ workerUrl: "ws://localhost:8787/" })).workerUrl, "ws://localhost:8787/");
  assert.throws(() => buildLink({ workerUrl: URL_OK, psk: new Uint8Array(16) }), /32 bytes/);
  assert.throws(() => parseExportObject(JSON.stringify({ app: "other", version: 1, workerUrl: URL_OK })), /not a hollow/);
  assert.throws(() => parseLink("hollow://v1?worker=wss%3A%2F%2Fx.example%2F&psk=@@bad"), /base64url/);
});

test("preview shows worker + verifier, never the PSK (correction 4 surface)", () => {
  const parsed = parseLink(buildLink({ workerUrl: URL_OK, psk: PSK }));
  const pv = previewOf(parsed, { currentPskExists: true, verifierOf: verifierHex });
  assert.equal(pv.workerUrl, URL_OK);
  assert.equal(pv.hasPsk, true);
  assert.equal(pv.overwritesPsk, true);
  assert.equal(pv.pskVerifier, verifierHex(PSK));
  const serialized = JSON.stringify(pv);
  assert.ok(!serialized.includes(Buffer.from(PSK).toString("base64url")), "preview must not contain the PSK");
  assert.ok(!serialized.includes(Buffer.from(PSK).toString("hex")), "preview must not contain the PSK (hex)");
});

test("QR roundtrip: own pixels -> decode -> payload parses", () => {
  const link = buildLink({ workerUrl: URL_OK, keyId: 1, psk: PSK });
  const { rgba, width, height } = qrPixels(link);
  const decoded = decodeQrFromPixels(rgba, width, height);
  assert.equal(decoded, link);
  assert.deepEqual(parseAnyPayload(decoded).psk, PSK);
});

test("bgraToRgba swaps the right channels", () => {
  const out = bgraToRgba(new Uint8Array([10, 20, 30, 40, 1, 2, 3, 4]));
  assert.deepEqual([...out], [30, 20, 10, 40, 3, 2, 1, 4]);
  assert.throws(() => decodeQrFromPixels(new Uint8ClampedArray(64 * 64 * 4).fill(255), 64, 64), /no QR/);
});

test("config: corrupt psk.bin is a hard error — file untouched, no regeneration", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hollow-cfg-"));
  process.env.HOLLOW_HOME = dir;
  const { loadPsk, loadOrCreatePsk, writePsk, PskCorruptError, pskAclArgs } = await import("../src/config.js?case=corrupt");
  fs.writeFileSync(path.join(dir, "psk.bin"), Buffer.alloc(12, 7));
  const before = fs.readFileSync(path.join(dir, "psk.bin"));
  assert.throws(() => loadPsk(), (e) => e instanceof PskCorruptError && e.code === "PSK_CORRUPT");
  assert.throws(() => loadOrCreatePsk(), /PSK_CORRUPT|bytes/);
  assert.deepEqual(fs.readFileSync(path.join(dir, "psk.bin")), before); // untouched
  // healthy path: absent -> generate once -> stable thereafter
  fs.rmSync(path.join(dir, "psk.bin"));
  const a = loadOrCreatePsk();
  const b = loadOrCreatePsk();
  assert.equal(a.length, 32);
  assert.deepEqual(a, b);
  writePsk(new Uint8Array(32).fill(9));
  assert.deepEqual(loadPsk(), new Uint8Array(32).fill(9));
  // ACL args: identity baked as given (the OS supplies it), SYSTEM included
  assert.deepEqual(pskAclArgs("C:\\x\\psk.bin", "alice"), ["C:\\x\\psk.bin", "/inheritance:r", "/grant:r", "alice:F", "/grant:r", "SYSTEM:F"]);
  delete process.env.HOLLOW_HOME;
});
