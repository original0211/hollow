// NP-1118-49: connectWs establishment timeout (opt-in). A server
// that accepts the TCP connection and then never speaks is the
// blackhole shape from NP-1118-47: without a bound the upgrade
// request never settles.
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { connectWs } from "../cli/src/ws-client.js";

test("connectWs: timeoutMs rejects a blackholed upgrade; omitting it keeps the historical unbounded wait", async () => {
  const srv = net.createServer(() => {}); // accept and say nothing
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  try {
    const t0 = Date.now();
    await assert.rejects(connectWs(`ws://127.0.0.1:${port}/`, { timeoutMs: 300 }), /connect timed out/);
    assert.ok(Date.now() - t0 < 2500, "rejected at the bound, not by an OS timeout");

    let settled = false;
    connectWs(`ws://127.0.0.1:${port}/`).then(() => { settled = true; }, () => { settled = true; });
    await new Promise((r) => setTimeout(r, 600));
    assert.equal(settled, false); // no bound was passed: still waiting, as before
  } finally {
    srv.close();
  }
});
