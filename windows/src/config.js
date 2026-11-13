// Config + PSK storage for the Windows client (NP-1114-01 skeleton).
// Layout (per plan §3): config dir holds psk.bin (32 bytes) + config.json.
// Windows: %APPDATA%\Hollow, ACL tightened to the current user (0600-equivalent).
// POSIX/dev: ~/.hollow (0600 file mode). No key material ever enters the repo.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";

export function configDir() {
  if (process.env.HOLLOW_HOME) return process.env.HOLLOW_HOME;
  if (process.platform === "win32" && process.env.APPDATA) return path.join(process.env.APPDATA, "Hollow");
  return path.join(os.homedir(), ".hollow");
}

const DEFAULTS = {
  workerUrl: "wss://newproto-hollow.newproto.workers.dev/",
  keyId: 1,
  socksPort: 1080,
  proxyMode: "off", // off | global | pac (pac lands in M2-4)
  preferredEdgeIp: null, // plan §5, M2-4
  exitRegion: null, // plan §7 reserve: read but ignored until the spec supplement lands
};

export function loadConfig() {
  const dir = configDir();
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, "config.json");
  let cfg = { ...DEFAULTS };
  if (fs.existsSync(file)) {
    try { cfg = { ...cfg, ...JSON.parse(fs.readFileSync(file, "utf8")) }; } catch { /* keep defaults */ }
  }
  return cfg;
}

export function saveConfig(cfg) {
  const dir = configDir();
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "config.json"), JSON.stringify(cfg, null, 2) + "\n");
}

function tightenAcl(file) {
  if (process.platform === "win32") {
    const user = process.env.USERNAME || "";
    if (user) {
      try { execFileSync("icacls", [file, "/inheritance:r", "/grant:r", `${user}:F`], { stdio: "ignore" }); } catch { /* best effort */ }
    }
  } else {
    try { fs.chmodSync(file, 0o600); } catch { /* best effort */ }
  }
}

// Load the PSK, generating and persisting a fresh one on first run.
export function loadOrCreatePsk() {
  const dir = configDir();
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, "psk.bin");
  if (fs.existsSync(file)) {
    const psk = new Uint8Array(fs.readFileSync(file));
    if (psk.length === 32) return psk;
  }
  const psk = new Uint8Array(crypto.randomBytes(32));
  fs.writeFileSync(file, Buffer.from(psk));
  tightenAcl(file);
  return psk;
}

// The server-side verifier V = HMAC-SHA256(PSK, label) — what the user pastes
// into the Worker secret. The PSK itself is never displayed (plan §3).
export function verifierHex(psk) {
  return crypto.createHmac("sha256", Buffer.from(psk)).update("newproto-v0.1-server-verifier").digest("hex");
}
