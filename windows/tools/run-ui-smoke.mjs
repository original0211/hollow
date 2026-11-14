// UI smoke launcher (NP-1114-35): runs the app — source tree by default,
// or a packaged executable with --exe <path> — with HOLLOW_UI_SMOKE=1 and
// a hermetic throwaway HOLLOW_HOME, and turns the app's own exit code
// into this script's verdict. The assertions live in src/main.js
// (runUiSmoke): bridge exposed, first-frame state + verifier rendered.
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const winDir = path.join(here, "..");
const exeIdx = process.argv.indexOf("--exe");
const home = fs.mkdtempSync(path.join(os.tmpdir(), "hollow-ui-smoke-"));
const outFile = path.join(home, "verdict.json");
const env = {
  ...process.env,
  HOLLOW_UI_SMOKE: "1",
  HOLLOW_UI_SMOKE_OUT: outFile,
  HOLLOW_HOME: home, // hermetic: config/PSK/Chromium all land in the temp dir
};
let cmd, args;
if (exeIdx >= 0) {
  cmd = process.argv[exeIdx + 1];
  args = [];
} else {
  const electron = path.join(winDir, "node_modules", "electron", "dist",
    process.platform === "win32" ? "electron.exe" : "electron");
  cmd = electron;
  args = ["--no-sandbox", winDir];
}
const child = spawn(cmd, args, { env, stdio: "inherit" });
const killer = setTimeout(() => { child.kill(); }, 60000);
child.on("exit", (code) => {
  clearTimeout(killer);
  let verdict = null;
  try { verdict = JSON.parse(fs.readFileSync(outFile, "utf8")); } catch { /* no file */ }
  console.log(`ui-smoke: exit=${code} verdict=${JSON.stringify(verdict)} home=${home}`);
  process.exit(code === 0 && verdict && verdict.healthy ? 0 : 1);
});
