// Static tripwire for NP-1114-35: the sandboxed preload MUST stay
// CommonJS. The behavioral ui-smoke is the main guard; this is the
// cheap second pin so an ESM "cleanup" fails the check suite even
// before any Electron run.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const file = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src", "preload.cjs");
// Strip comments first: this file's own prose mentions the forbidden
// shapes ("pairing & import (M2-3)" would trip the dynamic-import pin).
const src = fs.readFileSync(file, "utf8")
  .replace(/\/\*[\s\S]*?\*\//g, "")
  .split("\n")
  .filter((line) => !line.trim().startsWith("//"))
  .join("\n");
const bad = [
  [/^\s*import\s/m, "ESM import statement"],
  [/^\s*export\s/m, "ESM export statement"],
  [/\bimport\s*\(/, "dynamic import()"],
];
for (const [re, what] of bad) {
  if (re.test(src)) {
    console.error(`check-preload FAIL: preload.cjs contains ${what} — sandboxed preloads must be CommonJS (NP-1114-35)`);
    process.exit(1);
  }
}
if (!src.includes('require("electron")')) {
  console.error("check-preload FAIL: preload.cjs does not require(\"electron\") — unexpected shape");
  process.exit(1);
}
console.log("check-preload ok (CommonJS pin holds)");
