// NP-1116-02 (P1): the SOCKS pump must fulfil the CLOSE obligation when
// the server half-closes (stream onEnd) — regression for NP-1116-01.
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { startSocks } from "../cli/src/socks.js";

function fakeStream() {
  return {
    id: 7, gate: 1, state: "open", pending: [], paused: false,
    opened: Promise.resolve(1),
    onData: null, onEnd: null, onReset: null, onFail: null, onDrain: null,
    closeWriteCalls: 0, resetCalls: 0,
    write() { return true; },
    consume() {},
    closeWrite() { this.closeWriteCalls += 1; },
    reset() { this.resetCalls += 1; },
  };
}

test("socks pump: onEnd ends the local socket AND closeWrites the stream", async () => {
  const stream = fakeStream();
  const fakeClient = { state: "open", openStream: () => stream };
  const server = await startSocks({ getClient: () => fakeClient, port: 0, host: "127.0.0.1" });
  const port = server.address().port;
  const sock = net.connect(port, "127.0.0.1");
  await new Promise((r) => sock.once("connect", r));
  const recv = [];
  sock.on("data", (d) => recv.push(d));
  sock.write(Buffer.from([0x05, 0x01, 0x00])); // greeting: no-auth
  await new Promise((r) => setTimeout(r, 50));
  // CONNECT 1.2.3.4:80
  sock.write(Buffer.from([0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80]));
  await new Promise((r) => setTimeout(r, 100));
  const bytes = Buffer.concat(recv);
  assert.equal(bytes[bytes.length - 10 + 1], 0x00); // REP.SUCCESS in the reply
  assert.equal(stream.closeWriteCalls, 0);
  const finP = new Promise((r) => sock.once("end", r));
  stream.onEnd(); // server half-close arrives
  await finP; // local socket got its FIN (sock.end())
  assert.equal(stream.closeWriteCalls, 1); // and the obligation was fulfilled
  sock.destroy();
  server.close();
});
