#!/usr/bin/env node
// Named-import binding check (M2-5 hardening, NP-1114-14): `node --check`
// proves syntax, not that an imported name actually exists in the target
// module — a missing export is a startup-time crash that no unit test here
// would catch (main.js needs Electron and is never imported by tests).
// For every relative import in windows/src, resolve the target file and
// assert each named binding is among its exports.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const winDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const srcDir = path.join(winDir, "src");
let failures = 0, checked = 0;

function exportsOf(file) {
  const src = fs.readFileSync(file, "utf8");
  const names = new Set();
  for (const m of src.matchAll(/^export\s+(?:async\s+)?(?:function|const|let|var|class)\s+([A-Za-z_$][\w$]*)/gm)) names.add(m[1]);
  for (const m of src.matchAll(/^export\s*\{([^}]*)\}/gm)) {
    for (const part of m[1].split(",")) {
      const n = part.trim().split(/\s+as\s+/).pop().trim();
      if (n) names.add(n);
    }
  }
  if (/^export\s+default/m.test(src)) names.add("default");
  return names;
}

const importRe = /import\s+(?:([A-Za-z_$][\w$]*)\s*,\s*)?(?:\{([^}]*)\})?\s*(?:[A-Za-z_$][\w$]*\s*)?from\s*["'](\.[^"']+)["']/g;
const nsImportRe = /import\s*\*\s*as\s+([A-Za-z_$][\w$]*)\s+from\s*["'](\.[^"']+)["']/g;
for (const f of fs.readdirSync(srcDir).filter((x) => x.endsWith(".js"))) {
  const file = path.join(srcDir, f);
  const src = fs.readFileSync(file, "utf8");
  // Namespace imports (NP-1114-19, from the NP-1114-18 sweep): every
  // `ns.member` used in the importing file must be exported by the target.
  for (const m of src.matchAll(nsImportRe)) {
    const [, ns, spec] = m;
    const target = path.resolve(srcDir, spec);
    if (!fs.existsSync(target)) { console.error(`unresolved import target in ${f}: ${spec}`); failures++; continue; }
    const exps = exportsOf(target);
    // Scan member uses with import statements stripped — otherwise the
    // module path itself ("./sysproxy.js") reads as a member use.
    const body = src.replace(/import\s[^;]*?from\s*["'][^"']+["'];?/g, "");
    const useRe = new RegExp(`\\b${ns}\\.([A-Za-z_$][\\w$]*)`, "g");
    const members = new Set();
    for (const u of body.matchAll(useRe)) members.add(u[1]);
    for (const member of members) {
      checked++;
      if (!exps.has(member)) { console.error(`missing export: ${f} uses ${ns}.${member} from ${spec}, not exported there`); failures++; }
    }
  }
}
for (const f of fs.readdirSync(srcDir).filter((x) => x.endsWith(".js"))) {
  const file = path.join(srcDir, f);
  const src = fs.readFileSync(file, "utf8");
  for (const m of src.matchAll(importRe)) {
    const [, def, named, spec] = m;
    const target = path.resolve(srcDir, spec);
    if (!fs.existsSync(target)) { console.error(`unresolved import target in ${f}: ${spec}`); failures++; continue; }
    const exps = exportsOf(target);
    const wanted = [];
    if (def) wanted.push("default");
    if (named) for (const part of named.split(",")) { const n = part.trim().split(/\s+as\s+/)[0].trim(); if (n) wanted.push(n); }
    for (const w of wanted) {
      checked++;
      if (!exps.has(w)) { console.error(`missing export: ${f} imports { ${w} } from ${spec}, not exported there`); failures++; }
    }
  }
}
console.log(`import bindings: ${checked} checked`);
if (failures) { console.error(`check-imports: ${failures} FAILURE(S)`); process.exit(1); }
console.log("check-imports: OK");
