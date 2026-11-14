// Generates the shared pairing fixture set (NP-1114-36) from the
// CANONICAL JS implementation (windows/src/pairing.js). The Go port
// (android/core/pairing) and the Windows tests both assert against the
// file this writes: shared/testvectors/pairing-v1.json. Regenerate only
// when the grammar changes — and then both sides' tests move together.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildLink, buildExportObject, parseAnyPayload, previewOf } from "../src/pairing.js";
import { verifierHex } from "../src/config.js";

const out = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "shared", "testvectors", "pairing-v1.json");
const PSK = Uint8Array.from({ length: 32 }, (_, i) => i); // 00..1f
const PSK_HEX = Buffer.from(PSK).toString("hex");
const hx = (b) => (b ? Buffer.from(b).toString("hex") : null);
const shape = (p) => ({ workerUrl: p.workerUrl, keyId: p.keyId, pskHex: hx(p.psk), metaPath: p.metaPath, edgesPath: p.edgesPath });

const buildInputs = [
  { name: "minimal", in: { workerUrl: "wss://newproto-hollow.newproto.workers.dev/", keyId: 1 } },
  { name: "full", in: { workerUrl: "wss://example.com/socket?x=1", keyId: 7, psk: PSK, metaPath: "/m~abc/seg-1", edgesPath: "/e_xyz" } },
  { name: "localhost-ws", in: { workerUrl: "ws://localhost:8787/", keyId: 0 } },
  { name: "default-keyid", in: { workerUrl: "wss://a.b/" } },
];
const builds = buildInputs.map(({ name, in: input }) => ({
  name,
  input: { workerUrl: input.workerUrl, keyId: input.keyId ?? null, pskHex: input.psk ? PSK_HEX : null, metaPath: input.metaPath ?? null, edgesPath: input.edgesPath ?? null },
  link: buildLink(input),
  exportJson: JSON.stringify(buildExportObject(input)),
}));

const okTexts = [
  ["link-full", builds[1].link],
  ["link-minimal", builds[0].link],
  ["file-full", builds[1].exportJson],
  ["file-pretty", JSON.stringify(JSON.parse(builds[1].exportJson), null, 2) + "\n"],
  ["file-nopsk", builds[0].exportJson],
  ["link-trimmed", "  \n" + builds[1].link + "  "],
];
const parses = okTexts.map(([name, text]) => ({ name, text, ok: shape(parseAnyPayload(text)) }));

const errCases = [
  ["http-url", JSON.stringify({ app: "hollow", version: 1, workerUrl: "http://x.example/", keyId: 1 })],
  ["ws-nonlocal", "hollow://v1?worker=ws%3A%2F%2Fexample.com%2F&keyId=1"],
  ["psk-31", JSON.stringify({ app: "hollow", version: 1, workerUrl: "wss://a.b/", keyId: 1, pskBase64: Buffer.alloc(31).toString("base64") })],
  ["bad-b64url", "hollow://v1?worker=wss%3A%2F%2Fa.b%2F&keyId=1&psk=!!!"],
  ["wrong-app", JSON.stringify({ app: "other", version: 1, workerUrl: "wss://a.b/" })],
  ["keyid-300", JSON.stringify({ app: "hollow", version: 1, workerUrl: "wss://a.b/", keyId: 300 })],
  ["bad-metapath", JSON.stringify({ app: "hollow", version: 1, workerUrl: "wss://a.b/", metaPath: "no-slash" })],
  ["garbage", "hello world"],
  ["wrong-version", "hollow://v2?worker=wss%3A%2F%2Fa.b%2F"],
  ["bad-pskbase64", JSON.stringify({ app: "hollow", version: 1, workerUrl: "wss://a.b/", pskBase64: "a*b" })],
  ["keyid-nan", "hollow://v1?worker=wss%3A%2F%2Fa.b%2F&keyId=abc"],
];
const errors = errCases.map(([name, text]) => {
  try { parseAnyPayload(text); return { name, text, error: null }; }
  catch (e) { return { name, text, error: e.message }; }
});
if (errors.some((e) => !e.error)) throw new Error("an error case parsed cleanly — fixture invalid");

const parsedFull = parseAnyPayload(builds[1].link);
const previews = [true, false].map((exists) => ({
  currentPskExists: exists,
  preview: previewOf(parsedFull, { currentPskExists: exists, verifierOf: verifierHex }),
}));

fs.writeFileSync(out, JSON.stringify({ version: 1, builds, parses, errors, previews }, null, 2) + "\n");
console.log(`pairing fixtures written: ${builds.length} builds, ${parses.length} parses, ${errors.length} errors, ${previews.length} previews`);
