// M2-3 fresh-machine pairing rehearsal (NP-1114-07, sandbox segment): a
// "new machine" config dir imports Machine A's payload through the same
// parse -> confirm-apply path the app uses, then proves pairing with a real
// handshake. Control: a locally generated (unpaired) PSK fails the same
// handshake. Elapsed time is the sandbox stand-in for the <=15 min budget;
// the real-device timing belongs to the M2-5 checklist.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const t0 = Date.now();
const elapsed = () => ((Date.now() - t0) / 1000).toFixed(2) + "s";
const winDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
execFileSync("node", [path.join(winDir, "tools", "prepare-vendor.mjs")], { stdio: "ignore" });
process.env.HOLLOW_HOME = fs.mkdtempSync(path.join(os.tmpdir(), "hollow-fresh-"));

const { loadConfig, saveConfig, loadPsk, writePsk, verifierHex } = await import("../src/config.js");
const { buildLink, parseAnyPayload, previewOf } = await import("../src/pairing.js");
const { HollowClient } = await import("../vendor/shared/client-core.js");
const { connectWs } = await import("../vendor/cli/src/ws-client.js");

// Machine A = the existing paired install (~/.hollow, default config dir of
// the dev environment). Read its PSK WITHOUT the env override:
delete process.env.HOLLOW_HOME;
const { loadPsk: loadPskA, loadConfig: loadConfigA } = await import("../src/config.js?a");
const pskA = loadPskA();
const cfgA = loadConfigA();
console.log(`A: existing install, verifier ${verifierHex(pskA).slice(0, 12)}…`);
const link = buildLink({ workerUrl: cfgA.workerUrl, keyId: cfgA.keyId, psk: pskA });
console.log(`A: exported hollow:// link (${link.length} chars, PSK included) at ${elapsed()}`);

// Machine B: fresh dir, import via parse -> preview -> confirm-apply.
process.env.HOLLOW_HOME = fs.mkdtempSync(path.join(os.tmpdir(), "hollow-fresh-b-"));
const parsed = parseAnyPayload(link);
const preview = previewOf(parsed, { currentPskExists: false, verifierOf: verifierHex });
console.log(`B: preview -> worker ${preview.workerUrl}, hasPsk=${preview.hasPsk}, V matches A: ${preview.pskVerifier === verifierHex(pskA)}`);
writePsk(parsed.psk);
saveConfig({ ...loadConfig(), workerUrl: parsed.workerUrl, keyId: parsed.keyId });
console.log(`B: applied at ${elapsed()}; psk on disk: ${loadPsk().length} bytes`);

async function handshake(psk, keyId, url) {
  const transport = await connectWs(url, { userAgent: "HollowClient/0.1" });
  const client = new HollowClient({ transport, psk, keyId });
  try { await client.handshake(); client.close(); return true; }
  catch { try { client.close(); } catch { /* ignore */ } return false; }
}
const okB = await handshake(loadPsk(), parsed.keyId, parsed.workerUrl);
console.log(`B: real handshake with imported PSK -> ${okB ? "OK" : "FAIL"} at ${elapsed()}`);

const { loadOrCreatePsk } = await import("../src/config.js?b");
process.env.HOLLOW_HOME = fs.mkdtempSync(path.join(os.tmpdir(), "hollow-fresh-c-"));
const okC = await handshake(loadOrCreatePsk(), 1, cfgA.workerUrl);
console.log(`C (control, self-generated unpaired PSK): handshake -> ${okC ? "OK (UNEXPECTED!)" : "rejected as expected"} at ${elapsed()}`);

const pass = okB && !okC && preview.pskVerifier === verifierHex(pskA);
console.log(`PAIRING REHEARSAL: ${pass ? "ALL PASS" : "FAILED"} — total ${elapsed()} (budget 15 min, sandbox segment)`);
process.exit(pass ? 0 : 1);
