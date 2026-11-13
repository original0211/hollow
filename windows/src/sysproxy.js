// Windows system proxy save/set/restore (plan §2, M2-2 / NP-1114-05).
// HKCU only, no admin. All policy lives in `createSysProxy` over an injected
// registry adapter, so the full discipline is testable off-Windows:
//
//  R1 (iron snapshot rule): while a backup file exists, it is NEVER
//     overwritten — whatever the registry currently holds.
//  R2 (robust backup): the backup is written atomically (tmp + rename). A
//     corrupt/unreadable backup degrades restore to a direct no-proxy state
//     (logged + reported), never a silent no-op; every restore re-reads the
//     four values and asserts them against the expected state, keeping the
//     backup when verification fails.
//  R3 (self-heal by exact comparison): the backup records the full written
//     state; startup heals only when the live values match the written state
//     item-by-item (already-restored and partial/damaged states are handled
//     explicitly). No value guessing (no 127.0.0.1 pattern matching) — a
//     user's own local proxy tool must never be mistaken for ours.
//
// Value representation: canonical JS values — ProxyEnable: number 0/1,
// others: string, or null when the registry value is absent.
import fs from "node:fs";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { configDir } from "./config.js";

const run = promisify(execFile);
export const KEY_PATH = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
export const VALUE_NAMES = ["ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"];
export const BYPASS = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>";
export const NO_PROXY = { ProxyEnable: 0, ProxyServer: null, ProxyOverride: null, AutoConfigURL: null };
export const writtenFor = (port) => ({ ProxyEnable: 1, ProxyServer: `127.0.0.1:${port}`, ProxyOverride: BYPASS, AutoConfigURL: null });

const eq4 = (a, b) => VALUE_NAMES.every((n) => (a?.[n] ?? null) === (b?.[n] ?? null));
const pick4 = (o) => Object.fromEntries(VALUE_NAMES.map((n) => [n, o?.[n] ?? null]));

// ---- backup file (atomic) ----
function backupPath(dir) { return path.join(dir, "proxy-backup.json"); }
function writeBackupAtomic(dir, data) {
  fs.mkdirSync(dir, { recursive: true });
  const tmp = path.join(dir, `proxy-backup.${process.pid}.tmp`);
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + "\n");
  fs.renameSync(tmp, backupPath(dir));
}
function readBackup(dir) {
  const file = backupPath(dir);
  if (!fs.existsSync(file)) return { kind: "none" };
  try {
    const data = JSON.parse(fs.readFileSync(file, "utf8"));
    if (!data || data.version !== 2 || !data.original || !data.written) return { kind: "corrupt" };
    return { kind: "ok", data: { ...data, original: pick4(data.original), written: pick4(data.written) } };
  } catch { return { kind: "corrupt" }; }
}

// ---- policy core (adapter-injected) ----
// adapter: { get(name)->value|null, set(name, value), refresh() }
export function createSysProxy({ adapter, dir, log = () => {}, now = () => new Date().toISOString() }) {
  async function readCurrent() {
    const cur = {};
    for (const n of VALUE_NAMES) cur[n] = await adapter.get(n);
    return cur;
  }
  async function applyState(state) {
    for (const n of VALUE_NAMES) await adapter.set(n, state[n] ?? null);
    await adapter.refresh();
  }
  async function verifyAgainst(expected) {
    const cur = await readCurrent();
    const mismatches = VALUE_NAMES.filter((n) => (cur[n] ?? null) !== (expected[n] ?? null));
    return { ok: mismatches.length === 0, mismatches, current: cur };
  }

  async function enableGlobal(port) {
    const held = readBackup(dir);
    let written;
    if (held.kind === "ok") {
      log("proxy: backup already held — snapshot kept verbatim (iron rule), enabling with recorded state");
      written = held.data.written;
      // RF-06-02: the recorded written state must name the port SOCKS
      // actually bound this time. Only the written port field may move —
      // the snapshotted original is never touched.
      const want = writtenFor(port);
      if (written.ProxyServer !== want.ProxyServer) {
        written = { ...written, ProxyServer: want.ProxyServer };
        writeBackupAtomic(dir, { ...held.data, written });
        log("proxy: held backup written-port updated to the actually bound port (original untouched)");
      }
    } else if (held.kind === "corrupt") {
      log("proxy: WARNING existing backup unreadable — keeping it untouched; restore will degrade safely");
      written = writtenFor(port);
    } else {
      const original = await readCurrent();
      written = writtenFor(port);
      writeBackupAtomic(dir, { version: 2, takenAt: now(), original, written });
      log("proxy: snapshot saved");
    }
    await applyState(written);
    const v = await verifyAgainst(written);
    if (!v.ok) throw new Error(`proxy enable verification failed on: ${v.mismatches.join(",")}`);
    return written;
  }

  // Shared restore tail: apply + verify; drop the backup only when verified.
  async function finishRestore(expected, mode) {
    await applyState(expected);
    const v = await verifyAgainst(expected);
    if (!v.ok) {
      log(`proxy: RESTORE VERIFICATION FAILED (${mode}) on: ${v.mismatches.join(",")} — backup kept for retry`);
      return { restored: false, mode, verified: false, mismatches: v.mismatches };
    }
    fs.rmSync(backupPath(dir), { force: true });
    log(`proxy: restored (${mode}) and verified`);
    return { restored: true, mode, verified: true };
  }

  async function restore() {
    const held = readBackup(dir);
    if (held.kind === "none") return { restored: false, mode: "none", verified: true };
    if (held.kind === "corrupt") {
      log("proxy: WARNING backup corrupt — degrading to direct no-proxy restore");
      return finishRestore(NO_PROXY, "degraded-corrupt-backup");
    }
    return finishRestore(held.data.original, "snapshot");
  }

  // Startup self-heal (R3): exact comparison against the recorded states.
  async function selfHealOnStartup() {
    const held = readBackup(dir);
    if (held.kind === "none") return { healed: false, mode: "none" };
    if (held.kind === "corrupt") {
      log("proxy: startup found corrupt backup — degrading to direct no-proxy restore");
      const r = await finishRestore(NO_PROXY, "degraded-corrupt-backup");
      return { healed: r.restored, mode: r.mode, verified: r.verified };
    }
    const cur = await readCurrent();
    const { original, written } = held.data;
    if (eq4(cur, written)) {
      const r = await finishRestore(original, "snapshot");
      return { healed: r.restored, mode: "self-heal", verified: r.verified };
    }
    if (eq4(cur, original)) {
      fs.rmSync(backupPath(dir), { force: true });
      log("proxy: startup found values already at the original state — stale backup dropped");
      return { healed: false, mode: "already-original" };
    }
    // RF-06-01: a partial state is only OURS to degrade when it carries our
    // fingerprint — the recorded ProxyServer or ProxyOverride (the fixed
    // bypass list) still present. With neither, the live values are someone
    // else's complete configuration: touch nothing, keep the backup, and
    // leave a trace for manual handling (--restore-proxy still works).
    const hasFingerprint =
      (cur.ProxyServer !== null && cur.ProxyServer === written.ProxyServer) ||
      (cur.ProxyOverride !== null && cur.ProxyOverride === written.ProxyOverride);
    if (!hasFingerprint) {
      log("proxy: startup found a FOREIGN proxy state (no Hollow fingerprint) with a backup held — registry left untouched; manual handling advised (--restore-proxy remains available)");
      return { healed: false, mode: "foreign-state" };
    }
    log("proxy: startup found a PARTIAL/damaged proxy state carrying the Hollow fingerprint — degrading to direct no-proxy restore");
    const r = await finishRestore(NO_PROXY, "degraded-partial-state");
    return { healed: r.restored, mode: r.mode, verified: r.verified };
  }

  return { enableGlobal, restore, selfHealOnStartup, readCurrent };
}

// ---- win32 adapter (reg.exe + PowerShell WinINET refresh) ----
export function parseRegQuery(stdout, name) {
  // Pure parser (unit-tested): one `reg query` output -> canonical value.
  const m = String(stdout).match(new RegExp(name + "\\s+(REG_\\w+)\\s+(.*)"));
  if (!m) return null;
  const [, type, raw] = m;
  const val = raw.trim();
  if (type === "REG_DWORD") return parseInt(val, 16) || 0; // reg prints hex (0x1)
  return val;
}
export function win32Adapter() {
  return {
    async get(name) {
      try {
        const { stdout } = await run("reg", ["query", KEY_PATH, "/v", name]);
        return parseRegQuery(stdout, name);
      } catch { return null; } // value absent
    },
    async set(name, value) {
      if (value === null || value === undefined) {
        try { await run("reg", ["delete", KEY_PATH, "/v", name, "/f"]); } catch { /* already absent */ }
        return;
      }
      if (name === "ProxyEnable") {
        await run("reg", ["add", KEY_PATH, "/v", name, "/t", "REG_DWORD", "/d", String(value), "/f"]);
      } else {
        await run("reg", ["add", KEY_PATH, "/v", name, "/t", "REG_SZ", "/d", String(value), "/f"]);
      }
    },
    async refresh() {
      const ps = "Add-Type -Namespace W -Name I -MemberDefinition '[DllImport(\"wininet.dll\", SetLastError=true)] public static extern bool InternetSetOption(IntPtr h, int o, IntPtr b, int l);'; [W.I]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null; [W.I]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null";
      try { await run("powershell", ["-NoProfile", "-NonInteractive", "-Command", ps]); } catch { /* best effort */ }
    },
  };
}

// Default instance bound to the real config dir (used by the app main).
// The adapter is stateless, so a fresh wrapper per call is fine.
export function defaultSysProxy(log = () => {}) {
  if (process.platform !== "win32") return null;
  return createSysProxy({ adapter: win32Adapter(), dir: configDir(), log });
}
export async function enableGlobal(port, log) {
  const sp = defaultSysProxy(log);
  if (!sp) throw new Error("system proxy control is Windows-only");
  return sp.enableGlobal(port);
}
export async function restore(log) {
  const sp = defaultSysProxy(log);
  if (!sp) return { restored: false, mode: "not-windows", verified: true };
  return sp.restore();
}
export async function selfHealOnStartup(log) {
  const sp = defaultSysProxy(log);
  if (!sp) return { healed: false, mode: "not-windows" };
  return sp.selfHealOnStartup();
}
