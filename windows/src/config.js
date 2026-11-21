// Config + PSK storage for the Windows client (plan §3).
// Layout: config dir holds psk.bin (32 bytes) + config.json.
// Windows: %APPDATA%\Hollow, ACL tightened to the current user (0600-equiv).
// POSIX/dev: ~/.hollow (0600 file mode). No key material ever enters the repo.
//
// Red-team notes applied (NP-1114-07):
// - A present-but-invalid psk.bin is a hard error (PskCorruptError), never a
//   silent regeneration — silent regen would break pairing without a trace.
// - The ACL identity comes from the OS (os.userInfo), never from a
//   controllable environment variable; tightening runs at creation, on every
//   startup check, and after every import write.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { execFile } from "node:child_process";

export function configDir() {
  if (process.env.HOLLOW_HOME) return process.env.HOLLOW_HOME;
  if (process.platform === "win32" && process.env.APPDATA) return path.join(process.env.APPDATA, "Hollow");
  return path.join(os.homedir(), ".hollow");
}

const DEFAULTS = {
  workerUrl: "wss://hollow.example.workers.dev/",
  keyId: 1,
  socksPort: 1080,
  proxyMode: "off", // off | global | pac | tun (M2-4; tun added T-4 — mode families off/sysproxy/tun are mutually exclusive)
  directHosts: [], // PAC direct list (M2-4)
  pacPort: 18080, // preferred loopback port for the PAC endpoint (M2-4)
  edgeMode: "default", // default | auto | manual (M2-4)
  edgeResults: {}, // last per-IP measurement cache (M2-4)
  edgeListCache: null, // last edges refresh (M2-4)
  metaPath: null, // deployment-specific endpoint paths (NP-1114-15), learned
  edgesPath: null, // via the pairing payload or the settings page — never in the repo
  pacSeg: null, // per-install random PAC path segment (H-15-01)
  preferredEdgeIp: null, // plan §5, M2-4 (manual selection)
  exitRegion: null, // plan §7 reserve: read but ignored until the spec supplement lands
  poolSize: 4, // NP-1117-23: session pool (striping) size, 1-8
  autoConnect: true, // NP-1118-01 (h): resume the last working configuration at startup
  lastConnectedAt: null, // NP-1118-01 (h): set when a connection first succeeds; gates auto-connect + first-run
};

// NP-1117-19 (item 1): port validation shared by every layer that
// turns a port into a string. validPort coerces (numeric strings are
// fine) and returns the int or null; assertPort throws instead. A
// malformed endpoint must never reach the registry or a PAC file —
// the audit reproduced a PAC emitting "SOCKS5 127.0.0.1:null" out of
// a polluted config.
export function validPort(v) {
  const n = typeof v === "string" && v.trim() !== "" ? Number(v) : v;
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
}
export function assertPort(v, name = "port") {
  const p = validPort(v);
  if (p === null) throw new Error(`invalid ${name}: ${JSON.stringify(v) ?? String(v)} (expected integer 1-65535)`);
  return p;
}

export function loadConfig() {
  const dir = configDir();
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, "config.json");
  let cfg = { ...DEFAULTS };
  if (fs.existsSync(file)) {
    try { cfg = { ...cfg, ...JSON.parse(fs.readFileSync(file, "utf8")) }; } catch { /* keep defaults */ }
  }
  // NP-1117-19 (item 1): coerce the port fields at the source — a
  // polluted config.json (null / string / out of range) falls back to
  // the defaults instead of propagating into PAC/registry strings.
  for (const k of ["socksPort", "pacPort"]) {
    const p = validPort(cfg[k]);
    cfg[k] = p === null ? DEFAULTS[k] : p;
  }
  // NP-1117-23: pool size clamps into [1, 8]; anything unusable
  // falls back to the default rather than poisoning the bridge.
  const poolN = Math.floor(Number(cfg.poolSize));
  cfg.poolSize = Number.isFinite(poolN) ? Math.max(1, Math.min(8, poolN)) : DEFAULTS.poolSize;
  return cfg;
}

export function saveConfig(cfg) {
  const dir = configDir();
  fs.mkdirSync(dir, { recursive: true });
  // Atomic (M2-5 hardening): a crash or a file-lock hiccup mid-write must not
  // leave a truncated config.json behind — write a sibling tmp, then rename.
  const file = path.join(dir, "config.json");
  const tmp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2) + "\n");
  fs.renameSync(tmp, file);
}

// ---- PSK ----
export class PskCorruptError extends Error {
  constructor(msg) { super(msg); this.code = "PSK_CORRUPT"; }
}
function pskFile() { return path.join(configDir(), "psk.bin"); }

// The PSK, or null when no file exists. Throws PskCorruptError when the file
// exists but is not exactly 32 bytes.
export function loadPsk() {
  const file = pskFile();
  if (!fs.existsSync(file)) return null;
  const data = fs.readFileSync(file);
  if (data.length !== 32) throw new PskCorruptError(`psk.bin is ${data.length} bytes (expected 32)`);
  return new Uint8Array(data);
}
export function writePsk(psk) {
  if (!(psk instanceof Uint8Array) || psk.length !== 32) throw new Error("psk must be 32 bytes");
  fs.mkdirSync(configDir(), { recursive: true });
  // Atomic for the same reason as saveConfig: a partial psk.bin would read
  // back as corrupt (by design a hard error) — don't manufacture that state.
  const file = pskFile();
  const tmp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, Buffer.from(psk), { mode: 0o600 });
  fs.renameSync(tmp, file);
}
// First run: generate + persist. A corrupt existing file throws (see above).
export function loadOrCreatePsk() {
  const existing = loadPsk();
  if (existing) return existing;
  const psk = new Uint8Array(crypto.randomBytes(32));
  writePsk(psk);
  void tightenPskAcl();
  return psk;
}

// Cloudflare API token for the deployment wizard (NP-1118-42):
// stored with the PSK's discipline — its own file in the config
// dir, atomic write, 0600 + ACL tightening. The token is a
// deploy-time credential: the app never logs it, never includes
// it in diagnostics or exports, and the UI shows only its last
// four characters. Deleting it does not affect a deployed Worker.
function cfTokenFile() { return path.join(configDir(), "cftoken.txt"); }
export function loadCfToken() {
  const file = cfTokenFile();
  if (!fs.existsSync(file)) return null;
  const t = fs.readFileSync(file, "utf8").trim();
  return t || null;
}
export function writeCfToken(token) {
  if (typeof token !== "string" || !token.trim()) throw new Error("cf token must be a non-empty string");
  fs.mkdirSync(configDir(), { recursive: true });
  const file = cfTokenFile();
  const tmp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, token.trim(), { mode: 0o600 });
  fs.renameSync(tmp, file);
  void tightenFileAcl(file);
}
export function deleteCfToken() {
  try { fs.unlinkSync(cfTokenFile()); } catch { /* already gone */ }
}
export function cfTokenTail() {
  const t = loadCfToken();
  return t ? t.slice(-4) : null;
}
export async function tightenFileAcl(file, log = () => {}) {
  if (!fs.existsSync(file)) return false;
  if (process.platform !== "win32") {
    try { fs.chmodSync(file, 0o600); return true; } catch { return false; }
  }
  const user = os.userInfo().username;
  return new Promise((resolve) => {
    execFile("icacls", pskAclArgs(file, user), (err) => {
      if (err) log(`acl tighten failed for ${path.basename(file)}: ${err.message}`);
      resolve(!err);
    });
  });
}

// ACL tightening (Windows): inheritance off; full control only for the
// current process identity + SYSTEM. POSIX: 0600. Idempotent; the app runs
// it at creation, after import writes, and once on every startup.
export function pskAclArgs(file, user) {
  return [file, "/inheritance:r", "/grant:r", `${user}:F`, "/grant:r", "SYSTEM:F"];
}
export async function tightenPskAcl(log = () => {}) {
  const file = pskFile();
  if (!fs.existsSync(file)) return false;
  if (process.platform !== "win32") {
    try { fs.chmodSync(file, 0o600); return true; } catch { return false; }
  }
  const user = os.userInfo().username; // OS identity — not an env variable
  return new Promise((resolve) => {
    execFile("icacls", pskAclArgs(file, user), (err) => {
      if (err) log(`psk acl tighten failed: ${err.message}`);
      resolve(!err);
    });
  });
}

// The server-side verifier V = HMAC-SHA256(PSK, label) — what the user pastes
// into the Worker secret. The PSK itself is never displayed (plan §3).
export function verifierHex(psk) {
  return crypto.createHmac("sha256", Buffer.from(psk)).update("newproto-v0.1-server-verifier").digest("hex");
}

// PSK file status for the settings/pairing pages: existence, size, state and
// (when valid) the verifier — never the material. Never creates a key.
export function pskStatus() {
  const file = pskFile();
  if (!fs.existsSync(file)) return { exists: false, bytes: 0, state: "missing", verifier: null };
  const data = fs.readFileSync(file);
  const ok = data.length === 32;
  return {
    exists: true, bytes: data.length, state: ok ? "ok" : "corrupt",
    verifier: ok ? verifierHex(new Uint8Array(data)) : null,
  };
}
