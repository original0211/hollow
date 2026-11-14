// Generates the JS<->Go form-encoding equivalence scan fixture
// (NP-1114-41): expected values come from the canonical serializer
// (URLSearchParams, WHATWG urlencoded). The Go pairing test asserts
// its formEncode against every entry. Corpus: full printable ASCII
// (bare and embedded), multibyte samples, and the known-difference
// charset (~ first among them: JS %7E, naive Go encoders leave it raw).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const corpus = [];
for (let c = 0x20; c <= 0x7e; c++) {
  const ch = String.fromCharCode(c);
  corpus.push(ch, `a${ch}b`);
}
corpus.push(
  "é", "ü", "中", "文", "🙂", "é", "€",
  "~", "a~b", "/m~abc/seg-1", "%7E", "a+b", "a b", "100%",
  "&=", "?", "#", "/", "\\", "wss://x/?a=b&c=d", "key=va lue&x=1",
);
const cases = [...new Set(corpus)].map((input) => ({
  input,
  encoded: new URLSearchParams({ x: input }).toString().slice(2),
}));
const out = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "shared", "testvectors", "form-encoding-v1.json");
fs.writeFileSync(out, JSON.stringify({ version: 1, cases }, null, 2) + "\n");
console.log(`form-encoding fixtures: ${cases.length} cases`);
