// Vendor preparation (NP-1114-01): the Windows app must run the M1-verified
// core byte-identical, without a second implementation. We copy the repo's
// shared/ and the two CLI modules the bridge needs into windows/vendor/
// (generated, gitignored) so dev, smoke and the packaged app all resolve
// imports through the exact same relative layout.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const winDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const repoRoot = path.dirname(winDir);
const vendor = path.join(winDir, "vendor");

fs.rmSync(vendor, { recursive: true, force: true });
// Mirror the repo's depth (cli/src is two levels below root) so relative
// imports inside the vendored files (e.g. socks.js -> ../../shared) resolve
// exactly as they do in the repo.
fs.mkdirSync(path.join(vendor, "cli", "src"), { recursive: true });
fs.cpSync(path.join(repoRoot, "shared"), path.join(vendor, "shared"), { recursive: true });
for (const f of ["ws-client.js", "socks.js"]) {
  fs.copyFileSync(path.join(repoRoot, "cli", "src", f), path.join(vendor, "cli", "src", f));
}
// The deployment wizard (NP-1118-42) ships the Worker bundle
// inside the app (design: bundled, same-version). worker/src/
// index.js is the committed bundle built by tools/build-worker.mjs.
fs.copyFileSync(path.join(repoRoot, "worker", "src", "index.js"), path.join(vendor, "worker-bundle.txt"));
console.log("vendor prepared:", path.relative(winDir, vendor));
