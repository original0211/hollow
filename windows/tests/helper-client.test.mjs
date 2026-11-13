import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import { HelperClient } from "../src/helper-client.js";

// A scripted fake helper on the other end of a PassThrough pair.
function fakeHelper(script) {
  const appSide = new PassThrough();
  const helperSide = new PassThrough();
  appSide.pipe(helperSide, { end: false }); // not duplex-real; wire manually below
  // Simpler: two independent channels via object-mode-ish forwarding.
  const toHelper = [];
  const toApp = [];
  const sock = {
    _handlers: {},
    setEncoding() {},
    on(ev, fn) { (this._handlers[ev] ??= []).push(fn); return this; },
    once(ev, fn) { return this.on(ev, fn); },
    write(data, cb) {
      toHelper.push(data);
      script(JSON.parse(data.trim()), (frame) => {
        const line = JSON.stringify(frame) + "\n";
        for (const fn of this._handlers.data ?? []) fn(line);
      });
      if (cb) cb();
    },
    destroy() { for (const fn of this._handlers.close ?? []) fn(); },
    connecting: false,
  };
  return { sock, toHelper, toApp };
}

test("helper client: request/reply round trip + heartbeat surfacing", async () => {
  const heartbeats = [];
  const { sock } = fakeHelper((frame, reply) => {
    if (frame.verb === "ping") reply({ id: frame.id, ok: true });
    if (frame.verb === "status") reply({ id: frame.id, ok: true, result: { mode: "tun" } });
  });
  const c = new HelperClient({ connect: () => sock, onHeartbeat: (s) => heartbeats.push(s) });
  await c.connect();
  assert.equal(await c.ping(), true);
  const st = await c.request("status");
  assert.deepEqual(st.result, { mode: "tun" });
  // Inject a heartbeat frame as the helper would emit it.
  for (const fn of sock._handlers.data) fn(JSON.stringify({ event: "heartbeat", seq: 42, uptimeMs: 1000 }) + "\n");
  assert.deepEqual(heartbeats, [42]);
});

test("helper client: helper error rejects; silence times out; close rejects pending", async () => {
  const { sock } = fakeHelper((frame, reply) => {
    if (frame.verb === "enable_tun") reply({ id: frame.id, ok: false, error: "not elevated" });
    // "status" never answered
  });
  const c = new HelperClient({ connect: () => sock });
  await c.connect();
  await assert.rejects(() => c.request("enable_tun", { socksPort: 1 }), /not elevated/);
  await assert.rejects(() => c.request("status", null, 60), /timed out/);
  const pending = c.request("status", null, 5000);
  const assertion = assert.rejects(pending, /pipe closed/);
  c.close();
  await assertion;
});
