// Analyze cpu-tail.jsonl against the phase marks (spec §9.1 gates).
// Events are attributed to phases by eventTimestamp vs mark wall times.
// Usage: node analyze-cpu.mjs <cpu-tail.jsonl>
import fs from "node:fs";

const file = process.argv[2];
const marks = fs.readFileSync(file + ".marks.jsonl", "utf8").trim().split("\n").map((l) => JSON.parse(l));
const SCRIPT_NAME = process.env.HOLLOW_WORKER_NAME;
if (!SCRIPT_NAME) throw new Error("HOLLOW_WORKER_NAME is not set — the production script name is never recorded in this repo (NP-1114-47)");
const events = fs.readFileSync(file, "utf8").trim().split("\n").map((l) => JSON.parse(l));
const m = Object.fromEntries(marks.map((x) => [x.name, x.at]));
// tail eventTimestamp is epoch ms; marks use Date.now() — same clock basis.

function bucket(name, from, to) {
  const rows = events.filter((e) => e.eventTimestamp >= from && e.eventTimestamp < to && e.scriptName === SCRIPT_NAME);
  const cpus = rows.map((e) => e.cpuTime).sort((a, b) => a - b);
  const stats = cpus.length ? {
    n: cpus.length,
    min: cpus[0],
    p50: cpus[Math.floor(cpus.length * 0.5)],
    p95: cpus[Math.floor(cpus.length * 0.95)],
    max: cpus[cpus.length - 1],
    over10ms: cpus.filter((c) => c >= 10).length,
    outcomes: rows.reduce((acc, e) => { acc[e.outcome] = (acc[e.outcome] || 0) + 1; return acc; }, {}),
  } : { n: 0 };
  console.log(name, JSON.stringify(stats));
  return stats;
}

console.log("total tail events:", events.length);
const g1 = bucket("G1 handshake-only (gate: n>=50, max cpuTime < 10ms)", m["g1-start"], m["g1-end"]);
const g2 = bucket("G2 one 16KiB record each way (gate: n>=200, max cpuTime < 10ms)", m["g2-start"], m["g2-end"]);
const g4 = bucket("G4 unauthenticated (gate: max cpuTime < 10ms, zero outbound)", m["g4-start"], m["g4-end"] + 30000);
console.log("G1 verdict:", g1.n >= 50 && g1.max < 10 ? "PASS" : "CHECK");
console.log("G2 verdict:", g2.n >= 200 && g2.max < 10 ? "PASS" : "CHECK");
console.log("G4 verdict:", g4.n >= 10 && g4.max < 10 ? "PASS (cpu side)" : "CHECK");
