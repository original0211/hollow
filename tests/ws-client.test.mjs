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

// NP-1118-66 (S2): pong deadline. A peer that completes the
// upgrade but then never speaks again (and never pongs) is a
// half-dead carrier: after two ping cycles of total inbound
// silence the transport must declare death through onClose.
import http from "node:http";
import crypto from "node:crypto";

function wsUpgradeServer({ pong }) {
  const srv = http.createServer();
  srv.on("upgrade", (req, socket) => {
    const accept = crypto.createHash("sha1")
      .update(req.headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
      .digest("base64");
    socket.write(
      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
      `Sec-WebSocket-Accept: ${accept}\r\n\r\n`);
    if (pong) socket.on("data", () => { try { socket.write(Buffer.from([0x8a, 0x00])); } catch {} });
    socket.on("error", () => {});
  });
  return srv;
}

test("S2: a silent peer is declared dead after two ping cycles of inbound silence", async () => {
  const srv = wsUpgradeServer({ pong: false });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  try {
    const transport = await connectWs(`ws://127.0.0.1:${port}/`, { pingIntervalMs: 100 });
    const closed = new Promise((res) => transport.onClose((code) => res(code)));
    const t0 = Date.now();
    const code = await Promise.race([closed, new Promise((r) => setTimeout(() => r(null), 3000))]);
    assert.equal(code, 1006, "silence must end in the ordinary abnormal-close path");
    assert.ok(Date.now() - t0 < 3000, "death must be declared at the deadline, not by TCP");
  } finally {
    srv.close();
  }
});

test("S2 control: a ponging peer stays alive well past the deadline", async () => {
  const srv = wsUpgradeServer({ pong: true });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  try {
    const transport = await connectWs(`ws://127.0.0.1:${port}/`, { pingIntervalMs: 100 });
    let closedCode = null;
    transport.onClose((code) => { closedCode = code; });
    await new Promise((r) => setTimeout(r, 900)); // ~9 ping cycles
    assert.equal(closedCode, null, "a peer answering pings must not be declared dead");
    transport.close();
  } finally {
    srv.close();
  }
});
