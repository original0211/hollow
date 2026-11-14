// End-to-end demo with wire capture (NP-1113-06 item IV):
// CLI -> Worker -> tcpbin.com:4242 echo, capturing every WS message byte in
// both directions, then verifying: (1) echo payload correct; (2) the
// plaintext token appears NOWHERE in post-handshake wire bytes (all traffic
// is AEAD records); (3) every post-handshake message size is bucket+16.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { HollowClient } from "../../shared/client-core.js";
import { connectWs } from "../../cli/src/ws-client.js";

const URL = process.env.HOLLOW_WORKER_URL;
if (!URL) throw new Error("HOLLOW_WORKER_URL is not set — the production endpoint is never recorded in this repo (NP-1114-47); supply it out-of-band");
const PSK = new Uint8Array(fs.readFileSync(path.join(os.homedir(), ".hollow", "psk.bin")));

const raw = await connectWs(URL);
const wire = []; // {dir, len, bytes}
const transport = {
  send(b) { wire.push({ dir: "c2s", len: b.length, bytes: Buffer.from(b) }); raw.send(b); },
  close() { raw.close(); },
  closeCarrier() { raw.close(); },
  onMessage(cb) { raw.onMessage((b) => { wire.push({ dir: "s2c", len: b.length, bytes: Buffer.from(b) }); cb(b); }); },
  onClose(cb) { raw.onClose(cb); },
};
const client = new HollowClient({ transport, psk: PSK, keyId: 1 });
await client.handshake();
const handshakeMsgs = wire.length;
console.log(`handshake done: ${handshakeMsgs} wire messages (ClientHello/ServerHello plaintext inside TLS + 2 Finished records)`);

const s = client.openStream({ host: "tcpbin.com", port: 4242, schemeHint: 0, gatePolicy: 0 });
const gate = await s.opened;
const token = "PLAINTEXT-CANARY-" + Math.random().toString(36).slice(2, 12);
const got = [];
s.onData = (d) => got.push(Buffer.from(d));
s.write(new TextEncoder().encode(token + "\r\n"));
const t0 = Date.now();
while (!Buffer.concat(got).toString().includes(token) && Date.now() - t0 < 10000) {
  await new Promise((r) => setTimeout(r, 50));
}
const echoed = Buffer.concat(got).toString().includes(token);
console.log(`OPEN_OK gate=${gate} (0=connect)  echo received intact: ${echoed}`);

const post = wire.slice(handshakeMsgs);
const allowed = new Set([528, 4112, 16400]);
const badSizes = post.filter((m) => !allowed.has(m.len));
const canary = Buffer.from(token);
const leaks = post.filter((m) => m.bytes.includes(canary));
console.log(`post-handshake wire messages: ${post.length}, sizes: ${JSON.stringify(post.map((m) => m.len))}`);
console.log(`non-bucket sizes: ${badSizes.length}; messages containing the plaintext token: ${leaks.length}`);
console.log(echoed && badSizes.length === 0 && leaks.length === 0
  ? "DEMO PASS: end-to-end echo works; the wire carries only bucket-sized AEAD records, no plaintext"
  : "DEMO FAIL");
client.close();
process.exit(echoed && badSizes.length === 0 && leaks.length === 0 ? 0 : 1);
