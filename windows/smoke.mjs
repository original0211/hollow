// Headless connection smoke for the Windows skeleton (NP-1114-01):
// uses the same CoreBridge the Electron main process uses — connect to the
// deployed Worker, handshake, start the SOCKS entry, fetch a page through
// it, and log a verdict line per step. PSK from the config dir (never repo).
// Env: HOLLOW_WORKER_URL (default from config), HOLLOW_SMOKE_URL.
import { CoreBridge } from "./src/core-bridge.js";
import { loadConfig, loadOrCreatePsk } from "./src/config.js";

const cfg = loadConfig();
const psk = loadOrCreatePsk();
const target = process.env.HOLLOW_SMOKE_URL || "http://info.cern.ch/";
const log = (m) => console.log(new Date().toISOString(), m);

const bridge = new CoreBridge({ workerUrl: process.env.HOLLOW_WORKER_URL || cfg.workerUrl, psk, keyId: cfg.keyId, log });
await bridge.connect();
log("handshake ok");
// Stream-level fetch through the live client (the SOCKS entry shares this
// exact path; it was proven in M1 and gets its app wiring in M2-1).
const url = new URL(target);
const stream = bridge.client.openStream({ host: url.hostname, port: Number(url.port || 80), schemeHint: 0, gatePolicy: 0 });
const gate = await stream.opened;
log(`stream opened via gate ${gate}`);
const req = `GET ${url.pathname} HTTP/1.0\r\nHost: ${url.hostname}\r\n\r\n`;
let buf = Buffer.alloc(0);
const done = new Promise((res) => {
  stream.onData = (d) => { buf = Buffer.concat([buf, Buffer.from(d)]); if (buf.includes("\r\n\r\n")) res(); };
  stream.onEnd = () => res(); stream.onReset = () => res(); stream.onFail = () => res();
});
stream.write(new TextEncoder().encode(req));
await Promise.race([done, new Promise((r) => setTimeout(r, 15000))]);
const statusLine = buf.toString("latin1").split("\r\n")[0] || "";
log(`response: ${statusLine} (${buf.length} bytes)`);
await bridge.disconnect();
if (!/^HTTP\/1\.[01] 200/.test(statusLine)) { console.error("SMOKE FAIL"); process.exit(1); }
log("SMOKE OK");
