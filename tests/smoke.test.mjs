// Smoke tests for the M1 scaffold shells (worker + cli).
// Node built-in test runner, no external dependencies.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import worker, { VERSION as WORKER_VERSION } from "../worker/src/index.js";
import { VERSION as CLI_VERSION } from "../cli/src/cli.js";

const cliPath = fileURLToPath(new URL("../cli/src/cli.js", import.meta.url));

test("worker /health returns ok with version", async () => {
  const res = await worker.fetch(new Request("http://local/health"));
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.status, "ok");
  assert.equal(body.version, WORKER_VERSION);
});

test("worker unknown path returns 404", async () => {
  const res = await worker.fetch(new Request("http://local/nope"));
  assert.equal(res.status, 404);
});

test("cli --version prints version", () => {
  const out = execFileSync(process.execPath, [cliPath, "--version"], {
    encoding: "utf8",
  });
  assert.match(out, new RegExp(CLI_VERSION.replaceAll(".", "\\.")));
});

test("cli --health prints ok json", () => {
  const out = execFileSync(process.execPath, [cliPath, "--health"], {
    encoding: "utf8",
  });
  const body = JSON.parse(out);
  assert.equal(body.status, "ok");
  assert.equal(body.version, CLI_VERSION);
});
