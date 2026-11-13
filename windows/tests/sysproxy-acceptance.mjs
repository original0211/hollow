// M2-2 acceptance raw record (NP-1114-05): prints the verbatim registry
// states for (A) enable -> restore byte comparison and (B) the kill -9
// self-heal path, over the fake-registry harness (the win32 adapter itself
// is exercised on a real Windows machine; the policy logic recorded here is
// the exact code the app runs).
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createSysProxy } from "../src/sysproxy.js";

function fakeRegistry(initial = {}) {
  const store = new Map(Object.entries({ ProxyEnable: 0, ...initial }));
  return {
    async get(n) { return store.has(n) ? store.get(n) : null; },
    async set(n, v) { if (v === null) store.delete(n); else store.set(n, v); },
    async refresh() {},
    snapshot() {
      return {
        ProxyEnable: store.get("ProxyEnable") ?? 0,
        ProxyServer: store.get("ProxyServer") ?? null,
        ProxyOverride: store.get("ProxyOverride") ?? null,
        AutoConfigURL: store.get("AutoConfigURL") ?? null,
      };
    },
  };
}
const USER = { ProxyEnable: 1, ProxyServer: "proxy.user.example:8080", ProxyOverride: "user-bypass", AutoConfigURL: "http://user.example/pac" };
const dirA = fs.mkdtempSync(path.join(os.tmpdir(), "hollow-acc-a-"));
const dirB = fs.mkdtempSync(path.join(os.tmpdir(), "hollow-acc-b-"));

console.log("== A. verbatim restore ==");
const regA = fakeRegistry({ ...USER });
const spA = createSysProxy({ adapter: regA, dir: dirA, log: (m) => console.log("  log:", m) });
console.log("before enable :", JSON.stringify(regA.snapshot()));
await spA.enableGlobal(1080);
console.log("after enable  :", JSON.stringify(regA.snapshot()));
const rA = await spA.restore();
console.log("after restore :", JSON.stringify(regA.snapshot()));
console.log("restore result:", JSON.stringify(rA));
console.log("VERBATIM MATCH:", JSON.stringify(regA.snapshot()) === JSON.stringify(USER));

console.log("== B. kill -9 self-heal ==");
const regB = fakeRegistry({ ...USER });
const spB = createSysProxy({ adapter: regB, dir: dirB, log: (m) => console.log("  log:", m) });
await spB.enableGlobal(1080);
console.log("after enable  :", JSON.stringify(regB.snapshot()));
console.log("** process killed here — no restore, no cleanup **");
const fresh = createSysProxy({ adapter: regB, dir: dirB, log: (m) => console.log("  log:", m) });
const rB = await fresh.selfHealOnStartup();
console.log("heal result   :", JSON.stringify(rB));
console.log("after heal    :", JSON.stringify(regB.snapshot()));
console.log("VERBATIM MATCH:", JSON.stringify(regB.snapshot()) === JSON.stringify(USER));
