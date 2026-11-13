// Windows system proxy save/set/restore (plan §2). HKCU only, no admin.
// Discipline: snapshot the four Internet Settings values before touching
// them; restore them verbatim on disable/exit; never overwrite an existing
// snapshot with our own written values; `--restore-proxy` and the startup
// self-check recover from crashes. Off-Windows this module refuses loudly.
import fs from "node:fs";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { configDir } from "./config.js";

const run = promisify(execFile);
const KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
const VALUES = ["ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"];
const BYPASS = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>";

function assertWin32() {
  if (process.platform !== "win32") throw new Error("system proxy control is Windows-only");
}
function backupFile() { return path.join(configDir(), "proxy-backup.json"); }

async function queryValue(name) {
  try {
    const { stdout } = await run("reg", ["query", KEY, "/v", name]);
    const m = stdout.match(new RegExp(name + "\\s+REG_\\w+\\s+(.*)"));
    return m ? m[1].trim() : null;
  } catch { return null; } // value absent
}
async function setValue(name, type, data) {
  if (data === null || data === undefined) {
    try { await run("reg", ["delete", KEY, "/v", name, "/f"]); } catch { /* already absent */ }
    return;
  }
  await run("reg", ["add", KEY, "/v", name, "/t", type, "/d", String(data), "/f"]);
}
async function refreshWinInet() {
  // Notify WinINET clients (browsers) that settings changed, via a small
  // PowerShell P/Invoke — no compiled native module needed (plan §2).
  const ps = "Add-Type -Namespace W -Name I -MemberDefinition '[DllImport(\"wininet.dll\", SetLastError=true)] public static extern bool InternetSetOption(IntPtr h, int o, IntPtr b, int l);'; [W.I]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null; [W.I]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null";
  try { await run("powershell", ["-NoProfile", "-NonInteractive", "-Command", ps]); } catch { /* best effort */ }
}

export async function readCurrent() {
  assertWin32();
  const cur = {};
  for (const v of VALUES) cur[v] = await queryValue(v);
  return cur;
}

export async function enableGlobal(socksPort) {
  assertWin32();
  const mine = `127.0.0.1:${socksPort}`;
  const cur = await readCurrent();
  if (!fs.existsSync(backupFile()) || cur.ProxyServer !== mine) {
    // Anti-overwrite guard: only snapshot values that are not already ours.
    if (cur.ProxyServer !== mine) {
      fs.mkdirSync(configDir(), { recursive: true });
      fs.writeFileSync(backupFile(), JSON.stringify({ takenAt: new Date().toISOString(), values: cur }, null, 2));
    }
  }
  await setValue("ProxyServer", "REG_SZ", mine);
  await setValue("ProxyOverride", "REG_SZ", BYPASS);
  await setValue("ProxyEnable", "REG_DWORD", 1);
  await refreshWinInet();
  return mine;
}

export async function restore() {
  assertWin32();
  if (!fs.existsSync(backupFile())) return false;
  const { values } = JSON.parse(fs.readFileSync(backupFile(), "utf8"));
  await setValue("ProxyEnable", "REG_DWORD", values.ProxyEnable === null ? 0 : parseInt(values.ProxyEnable, 16) || 0);
  await setValue("ProxyServer", "REG_SZ", values.ProxyServer);
  await setValue("ProxyOverride", "REG_SZ", values.ProxyOverride);
  await setValue("AutoConfigURL", "REG_SZ", values.AutoConfigURL);
  await refreshWinInet();
  fs.rmSync(backupFile(), { force: true });
  return true;
}

// Startup self-check (plan §2): if a previous run died while our proxy was
// set, restore before doing anything else.
export async function selfHealOnStartup() {
  if (process.platform !== "win32") return false;
  if (!fs.existsSync(backupFile())) return false;
  const cur = await readCurrent();
  const { values } = JSON.parse(fs.readFileSync(backupFile(), "utf8"));
  void values;
  if (cur.ProxyEnable === "0x1" && /^127\.0\.0\.1:\d+$/.test(cur.ProxyServer || "")) {
    return restore();
  }
  return false;
}
