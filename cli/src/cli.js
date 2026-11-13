#!/usr/bin/env node
// newproto cli — minimal shell (M1 scaffold, NP-1113-02).
// Only --version / --health. No protocol logic yet:
// protocol implementation lands after spec v0.1 passes review.

export const NAME = "newproto-cli";
export const VERSION = "0.0.1";

function main(argv) {
  const cmd = argv[2];
  if (cmd === "--version" || cmd === "-v" || cmd === "version") {
    console.log(`${NAME} ${VERSION}`);
    return 0;
  }
  if (cmd === "--health" || cmd === "health") {
    console.log(JSON.stringify({ name: NAME, version: VERSION, status: "ok" }));
    return 0;
  }
  console.log(`usage: ${NAME} [--version|--health]`);
  return cmd === undefined || cmd === "--help" || cmd === "-h" ? 0 : 1;
}

import { fileURLToPath } from "node:url";
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exit(main(process.argv));
}
