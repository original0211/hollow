// Vendor integrity (NP-1114-05 side item): after prepare-vendor, prove the
// vendored core is byte-identical to the repo sources and that every
// relative import used by the app resolves — so a future whitelist edit in
// prepare-vendor can never silently drop a module the core needs.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const winDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const repoRoot = path.dirname(winDir);
const vendor = path.join(winDir, "vendor");
const sha = (f) => crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex");

let failures = 0;
// (a) byte-identity of every vendored file against its source
function* walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) yield* walk(p); else yield p;
  }
}
let checked = 0;
// Files whose vendor name intentionally differs from their repo
// source path (NP-1118-42: the wizard's Worker bundle is the
// committed worker/src/index.js, vendored under a data name so
// nothing mistakes it for an app module).
const SOURCE_OVERRIDES = { "worker-bundle.txt": path.join("worker", "src", "index.js") };
for (const f of walk(vendor)) {
  const rel = path.relative(vendor, f);
  const src = path.join(repoRoot, SOURCE_OVERRIDES[rel] ?? rel);
  if (!fs.existsSync(src)) { console.error(`vendor file without source: ${rel}`); failures++; continue; }
  if (sha(f) !== sha(src)) { console.error(`vendor hash mismatch: ${rel}`); failures++; }
  checked++;
}
console.log(`vendor byte-identity: ${checked} files checked`);

// (b) every relative import in app sources resolves to a real file — and, per
// NP-1114-08, the same scan runs over the vendored files themselves: if a
// vendored file grows a new cross-file dependency and the prepare whitelist
// misses it, this goes red instead of shipping a broken bundle.
const importRe = /(?:from\s+|import\s*\(\s*|import\s+)["'](\.[^"']+)["']/g;
const appFiles = [
  ...fs.readdirSync(path.join(winDir, "src")).filter((f) => f.endsWith(".js")).map((f) => path.join(winDir, "src", f)),
  path.join(winDir, "smoke.mjs"),
  ...[...walk(vendor)].filter((f) => f.endsWith(".js")),
];
let imports = 0;
for (const f of appFiles) {
  const text = fs.readFileSync(f, "utf8");
  for (const m of text.matchAll(importRe)) {
    imports++;
    const target = path.resolve(path.dirname(f), m[1]);
    if (!fs.existsSync(target)) { console.error(`unresolved import in ${path.basename(f)}: ${m[1]}`); failures++; }
  }
}
console.log(`import resolution: ${imports} relative imports checked`);
if (failures) { console.error(`verify-vendor: ${failures} FAILURE(S)`); process.exit(1); }
console.log("verify-vendor: OK");
