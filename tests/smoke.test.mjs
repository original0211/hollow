// Smoke tests: CLI shell behavior + shared module loading.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { VERSION as CLI_VERSION } from "../cli/src/cli.js";
import { MAX_PAYLOAD } from "../shared/protocol.js";

const cliPath = fileURLToPath(new URL("../cli/src/cli.js", import.meta.url));

test("spec constant: single-frame payload hard cap is 16,373", () => {
  assert.equal(MAX_PAYLOAD, 16373);
});

test("cli --version prints version", () => {
  const out = execFileSync(process.execPath, [cliPath, "--version"], { encoding: "utf8" });
  assert.match(out, new RegExp(CLI_VERSION.replaceAll(".", "\\.")));
});

test("cli --health prints ok json", () => {
  const out = execFileSync(process.execPath, [cliPath, "--health"], { encoding: "utf8" });
  const body = JSON.parse(out);
  assert.equal(body.status, "ok");
  assert.equal(body.version, CLI_VERSION);
});
