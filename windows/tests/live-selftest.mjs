// M2-1 live self-test (NP-1114-03 acceptance, executor side): drives the
// production CoreBridge against the deployed Worker exactly as the app does.
//   1. connect -> Connected
//   2. SOCKS up on the default port; real curl through it -> HTTP 200
//   3. disconnect -> the SOCKS port refuses connections
//   4. wrong-PSK bridge -> Error terminal state (fatal class), no SOCKS
// Writes a JSON verdict per step to stdout. PSK from the config dir only.
import net from "node:net";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import crypto from "node:crypto";
import { CoreBridge } from "../src/core-bridge.js";
import { loadConfig, loadOrCreatePsk } from "../src/config.js";

const run = promisify(execFile);
const out = [];
const step = (name, ok, detail = "") => { out.push({ name, ok, detail }); console.log(`${ok ? "PASS" : "FAIL"} ${name} ${detail}`); };
const waitFor = async (fn, ms = 20000) => {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { if (fn()) return true; await new Promise((r) => setTimeout(r, 100)); }
  return false;
};
const cfg = loadConfig();
const psk = loadOrCreatePsk();

const bridge = new CoreBridge({ workerUrl: cfg.workerUrl, psk, keyId: cfg.keyId, log: () => {} });
await bridge.connect();
step("connect", await waitFor(() => bridge.state === "connected"), `state=${bridge.state}`);
const port = await bridge.startSocks(cfg.socksPort || 1080);
step("socks-start", port > 0, `port=${port}`);
try {
  const { stdout } = await run("curl", ["-s", "-o", "/dev/null", "-w", "%{http_code}", "--socks5-hostname", `127.0.0.1:${port}`, "--max-time", "20", "http://info.cern.ch/"]);
  step("curl-through-socks", stdout.trim() === "200", `http=${stdout.trim()}`);
} catch (e) { step("curl-through-socks", false, String(e.message || e)); }
await bridge.disconnect();
const refused = await new Promise((res) => {
  const s = net.connect(port, "127.0.0.1");
  s.once("connect", () => { s.destroy(); res(false); });
  s.once("error", () => res(true));
});
step("port-closed-after-disconnect", refused && bridge.state === "disconnected", `state=${bridge.state}`);

const bad = new CoreBridge({ workerUrl: cfg.workerUrl, psk: new Uint8Array(crypto.randomBytes(32)), keyId: cfg.keyId, log: () => {} });
await bad.connect();
const wentError = await waitFor(() => bad.state === "error", 30000);
step("wrong-psk-fatal", wentError, `state=${bad.state} detail=${bad.stateDetail}`);
await bad.disconnect();

const failed = out.filter((x) => !x.ok);
console.log(failed.length === 0 ? "LIVE SELFTEST: ALL PASS" : `LIVE SELFTEST: ${failed.length} FAILED`);
process.exit(failed.length === 0 ? 0 : 1);
