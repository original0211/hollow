#!/usr/bin/env node
// Hollow CLI (M1 prototype, NP-1113-06).
// Commands:
//   --version | --health
//   psk init [--file PATH]        generate the 32B PSK locally (0600, never in repo)
//   psk verifier [--file PATH]    print V (hex) for the owner to set as the Worker secret
//   serve [--listen 127.0.0.1:1080] [--url wss://...] [--psk-file PATH]
//                                 SOCKS5 entry + carrier with §8.4 reconnect backoff
// Secrets discipline (spec §1.1): the PSK exists only in the local key file;
// the server stores only V. Nothing here hardcodes or logs the PSK itself.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "../../shared/crypto.js";
import { deriveVerifier } from "../../shared/protocol.js";
import { establishClient } from "./establish.js";
import { SessionManager } from "../../shared/session-manager.js";
import { startSocks } from "./socks.js";

export const NAME = "hollow-cli";
export const VERSION = "0.1.0";

const DEFAULT_PSK = path.join(os.homedir(), ".hollow", "psk.bin");

function argVal(argv, name, dflt) {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : dflt;
}

async function pskInit(argv) {
  const file = argVal(argv, "--file", DEFAULT_PSK);
  if (fs.existsSync(file)) {
    console.error(`psk file already exists: ${file} (refusing to overwrite)`);
    return 1;
  }
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const psk = randomBytes(32);
  fs.writeFileSync(file, psk, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
  const v = await deriveVerifier(new Uint8Array(psk));
  console.log(`PSK written to ${file} (0600, 32 bytes)`);
  console.log(`key_id: 1`);
  console.log(`verifier V (hex, for the Worker secret PSK_V_HEX): ${Buffer.from(v).toString("hex")}`);
  return 0;
}

function loadPsk(file) {
  const b = fs.readFileSync(file);
  if (b.length !== 32) throw new Error(`psk file must be 32 bytes, got ${b.length}`);
  return new Uint8Array(b);
}

async function pskVerifier(argv) {
  const file = argVal(argv, "--file", DEFAULT_PSK);
  const v = await deriveVerifier(loadPsk(file));
  console.log(Buffer.from(v).toString("hex"));
  return 0;
}

async function serve(argv) {
  const listen = argVal(argv, "--listen", "127.0.0.1:1080");
  const [lhost, lport] = listen.split(":");
  const url = argVal(argv, "--url", process.env.HOLLOW_WORKER_URL || "");
  if (!url) { console.error("--url wss://<worker> is required (or HOLLOW_WORKER_URL)"); return 1; }
  const psk = loadPsk(argVal(argv, "--psk-file", DEFAULT_PSK));
  const keyId = Number(argVal(argv, "--key-id", "1"));
  // NP-1117-23: session pool size (striping), 1-8, default 4.
  const poolSize = Math.max(1, Math.min(8, Number(argVal(argv, "--sessions", "4")) || 4));

  let stopped = false;
  let failures = 0;
  const log = (...a) => console.log(new Date().toISOString(), ...a);

  // NP-1117-16: the shared session manager owns rotations (15-min
  // timer + the 40-open budget) with drain semantics — the same
  // machine the Windows bridge uses. This loop keeps the CLI's own
  // reconnect/backoff policy for the first session of a lineage.
  const sessions = new SessionManager({
    establish: async () => {
      const pingMs = 75000 + Math.floor(Math.random() * 75000); // §2-5: 75–150s randomized
      // NP-1118-66 (S1): one shared 20 s establishment deadline
      // (cli/src/establish.js) — a blackholed entry can no longer
      // park the supervisor inside its first attempt forever.
      return establishClient({ url, psk, keyId, pingIntervalMs: pingMs });
    },
    log: (m) => log(m),
    size: poolSize,
    onSwap: () => { log("carrier up (rotated)"); },
  });

  // NP-1117-23: one supervisor loop per pool slot; a lineage ending
  // is replenished by its own loop and never blocks the others.
  async function runCarrier(slotIndex) {
    while (!stopped) {
      try {
        const client = await sessions.establish();
        failures = 0;
        log(`carrier up: ${url}`);
        await sessions.adopt(client, slotIndex);
        log("carrier down; will reconnect");
      } catch (e) {
        log("carrier attempt failed:", e && e.message || e);
      }
      if (stopped) break;
      failures++;
      const base = Math.min(60000, 1000 * 2 ** Math.min(failures - 1, 6));
      const delay = Math.round(base * (1 + (Math.random() * 0.5 - 0.25))); // §8.4: ±25% jitter
      log(`reconnect in ${delay}ms (failure ${failures})`);
      await new Promise((r) => setTimeout(r, delay));
    }
  }

  const server = await startSocks({
    getClient: (exclude) => sessions.pick(exclude),
    host: lhost, port: Number(lport),
    log: (...a) => log(...a),
    openHooks: { onOutboundExhausted: (c) => sessions.noteOutboundFailure(c) },
  });
  log(`socks5 listening on ${lhost}:${lport} (loopback only)`);
  process.on("SIGINT", () => { stopped = true; sessions.stop(); server.close(); process.exit(0); });
  process.on("SIGTERM", () => { stopped = true; sessions.stop(); server.close(); process.exit(0); });
  for (let i = 0; i < poolSize; i++) runCarrier(i);
  await new Promise(() => {}); // serve forever; signals exit explicitly
  return 0;
}

async function main(argv) {
  const cmd = argv[2];
  if (cmd === "--version" || cmd === "-v" || cmd === "version") {
    console.log(`${NAME} ${VERSION}`);
    return 0;
  }
  if (cmd === "--health" || cmd === "health") {
    console.log(JSON.stringify({ name: NAME, version: VERSION, status: "ok" }));
    return 0;
  }
  if (cmd === "psk" && argv[3] === "init") return pskInit(argv);
  if (cmd === "psk" && argv[3] === "verifier") return pskVerifier(argv);
  if (cmd === "serve") return serve(argv);
  console.log(`usage: ${NAME} [--version|--health|psk init|psk verifier|serve]`);
  return cmd === undefined || cmd === "--help" || cmd === "-h" ? 0 : 1;
}

import { fileURLToPath } from "node:url";
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exit(await main(process.argv));
}
