// NP-1118-66 (audit NP-1118-63 B3/B4): the deployment wizard's
// real effects, extracted from main.js so their bounds are
// unit-testable. Every wait here is bounded:
//
//   B3 — every Cloudflare API fetch carries a 30 s abort signal
//     (CF_API_TIMEOUT_MS, the bridge establishment family): a
//     blackholed path to api.cloudflare.com (TCP up, never
//     answering) otherwise parks the wizard on "in progress"
//     forever, because the orchestration can only wait for its
//     effects to return.
//   B4 — the liveness probe follows the testConnection precedent:
//     the facade/meta fetches carry the same 30 s signal, and the
//     handshake is raced at 15 s (WIZARD_PROBE_TIMEOUT_MS) with
//     the connect given the same budget and BOTH the client and
//     the transport closed on every path — a single hung probe
//     otherwise blows through the orchestration's 180 s liveness
//     window, which is only consulted after the probe returns.
//
// The functions take their platform pieces (fetch implementation,
// connectWs, HollowClient) as parameters; main.js binds the real
// ones, tests bind fakes and short budgets.

export const CF_API_TIMEOUT_MS = 30000;
export const WIZARD_PROBE_TIMEOUT_MS = 15000;
const CF_API_BASE = "https://api.cloudflare.com/client/v4";

function timeoutSignal(ms) {
  if (typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function") {
    return AbortSignal.timeout(ms);
  }
  const ac = new AbortController();
  setTimeout(() => { try { ac.abort(); } catch { /* ignore */ } }, ms);
  return ac.signal;
}

export function cfApiFor(fetchImpl, token, { timeoutMs = CF_API_TIMEOUT_MS, base = CF_API_BASE } = {}) {
  return async (method, apiPath, body) => {
    const res = await fetchImpl(base + apiPath, {
      method,
      headers: { "Authorization": `Bearer ${token}`, ...(body ? { "Content-Type": "application/json" } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
      signal: timeoutSignal(timeoutMs),
    });
    let json = null;
    try { json = await res.json(); } catch { /* non-JSON error page */ }
    return { ok: res.ok && json?.success === true, status: res.status, result: json?.result ?? null, errors: json?.errors ?? null };
  };
}

export async function cfDeployScript(fetchImpl, token, { accountId, scriptName, bundle, metadata }, { timeoutMs = CF_API_TIMEOUT_MS, base = CF_API_BASE } = {}) {
  const form = new FormData();
  form.append("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }));
  form.append("index.js", new Blob([bundle], { type: "application/javascript+module" }));
  const res = await fetchImpl(`${base}/accounts/${accountId}/workers/scripts/${scriptName}`, {
    method: "PUT", headers: { "Authorization": `Bearer ${token}` }, body: form,
    signal: timeoutSignal(timeoutMs),
  });
  let json = null;
  try { json = await res.json(); } catch { /* ignore */ }
  return { ok: res.ok && json?.success === true, status: res.status, errors: json?.errors ?? null };
}

export async function probeWizardLiveness(pairing, { fetchImpl, connectWs, HollowClient, fetchTimeoutMs = CF_API_TIMEOUT_MS, probeTimeoutMs = WIZARD_PROBE_TIMEOUT_MS } = {}) {
  const httpBase = pairing.workerUrl.replace(/^wss:/, "https:");
  const parts = { facade: false, meta: false, handshake: false };
  try {
    const r = await fetchImpl(httpBase + "/", { signal: timeoutSignal(fetchTimeoutMs) });
    const body = await r.text();
    parts.facade = r.status === 200 && body.length === 81;
  } catch { /* stays false */ }
  try {
    const r = await fetchImpl(httpBase + "/" + pairing.metaPath, { signal: timeoutSignal(fetchTimeoutMs) });
    parts.meta = r.status === 200;
    if (r.ok) { try { await r.json(); } catch { parts.meta = false; } }
  } catch { /* stays false */ }
  // B4: the testConnection shape — the whole establishment
  // (connect + handshake) races one 15 s budget; whatever the
  // outcome, both layers are closed so a still-flying attempt
  // cannot dangle.
  let transport = null, client = null, timer = null;
  try {
    const work = (async () => {
      transport = await connectWs(pairing.workerUrl, { timeoutMs: probeTimeoutMs });
      client = new HollowClient({ transport, psk: pairing.psk, keyId: pairing.keyId ?? 1 });
      await client.handshake();
    })();
    work.catch(() => { /* the race owns the outcome */ });
    await Promise.race([
      work,
      new Promise((_, rej) => { timer = setTimeout(() => rej(new Error("handshake timeout")), probeTimeoutMs); }),
    ]);
    parts.handshake = true;
  } catch { /* stays false */ } finally {
    if (timer) clearTimeout(timer);
    try { client?.close(); } catch { /* ignore */ }
    try { transport?.close(); } catch { /* ignore */ }
  }
  return parts;
}
