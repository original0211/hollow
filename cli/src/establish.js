// NP-1118-66 (audit NP-1118-63 S1): the CLI's carrier
// establishment, extracted from cli.js so its bound is testable.
// Before this change the CLI passed no timeout to connectWs and
// raced nothing against the handshake: on a blackholed entry path
// the supervisor loop hung inside its FIRST establishment forever
// and the §8.4 backoff never started (the bridge got the same fix
// in NP-1118-49; ws-client's timeoutMs stayed opt-in and the CLI
// never opted in).
//
// The bound is the bridge's shape: ONE shared deadline
// (ESTABLISH_TIMEOUT_MS = 20 s) across connect + handshake. The
// connect is also handed timeoutMs so the socket itself is
// destroyed at the transport layer; the race here is the
// guarantee even if a transport implementation ignores it. On
// expiry both layers are closed, and a client that completes
// after the deadline is closed on arrival instead of leaking.
import { HollowClient } from "../../shared/client-core.js";
import { connectWs } from "./ws-client.js";

export const ESTABLISH_TIMEOUT_MS = 20000;

export async function establishClient({
  url, psk, keyId, pingIntervalMs,
  timeoutMs = ESTABLISH_TIMEOUT_MS,
  connectWsImpl = connectWs,
  HollowClientImpl = HollowClient,
} = {}) {
  let transport = null, client = null, timedOut = false;
  const work = (async () => {
    transport = await connectWsImpl(url, { pingIntervalMs, timeoutMs });
    client = new HollowClientImpl({ transport, psk, keyId });
    await client.handshake();
    return client;
  })();
  work.catch(() => { /* the race owns the outcome */ });
  // A completion after the deadline must not leak a live client.
  work.then((c) => { if (timedOut && c) { try { c.close(); } catch { /* ignore */ } } }, () => {});
  let timer = null;
  try {
    return await Promise.race([
      work,
      new Promise((_, rej) => {
        timer = setTimeout(() => {
          timedOut = true;
          rej(new Error(`establishment timed out after ${timeoutMs}ms`));
        }, timeoutMs);
      }),
    ]);
  } catch (e) {
    try { client?.close(); } catch { /* ignore */ }
    try { transport?.close(); } catch { /* ignore */ }
    throw e;
  } finally {
    if (timer) clearTimeout(timer);
  }
}
