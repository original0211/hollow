// TUN bearer pinning policy (notes v2 §3, mandatory change C; NP-1114-20).
// Pure planning functions — the caller (main process) executes the plans:
//
//   plan = planTunEnable(...)          -> pins to add (helper enable_tun /
//                                          set_exclusions), bearer IP to
//                                          lock the bridge to
//   plan = planCandidateRefresh(...)   -> full new set to send the helper,
//                                          and the bearer consequence
//
// The one ledger rule: candidate set === exclusion set. Every IP the
// bearer may dial has a /32 (v6: /128) host route around the tunnel, and
// nothing else is ever dialed while TUN is up. Sequencing (spec R5): the
// helper confirms the new set BEFORE the bridge is pointed at a new IP.

const uniq = (xs) => [...new Set(xs.filter(Boolean))];

// edgeMode: "default" | "auto" | "manual" (config.edgeMode).
// candidates: the current candidate IPs (edges list / cache / builtin).
// resolvedIps: fresh DNS answers for the Worker hostname — required when
//   edgeMode is "default" (that mode is disabled under TUN; enabling TUN
//   first resolves the name and pins the answers, per notes v2 §3).
export function planTunEnable({ edgeMode, preferredEdgeIp = null, autoBestIp = null, candidates = [], resolvedIps = [] }) {
  const base = uniq(candidates);
  let chosen = null;
  if (edgeMode === "manual") chosen = preferredEdgeIp;
  else if (edgeMode === "auto") chosen = autoBestIp;
  else chosen = resolvedIps[0] ?? null; // "default": pin a resolved answer

  if (!chosen) {
    return {
      ok: false,
      reason: edgeMode === "default"
        ? "default-resolution mode has no resolved IP to pin — resolve the Worker hostname first (TUN forbids live DNS dialing)"
        : `no bearer IP selected in ${edgeMode} mode`,
      pins: base,
      bearerIp: null,
    };
  }
  // The chosen IP joins the set if it is not already a candidate (a manual
  // pick outside the edges list still gets its /32 — one ledger).
  const pins = uniq([...base, ...resolvedIps, chosen]);
  return { ok: true, pins, bearerIp: chosen };
}

// A live candidate-list refresh while TUN is up. The helper applies the
// new set add-before-delete internally; the bridge may only switch its
// bearer AFTER the helper confirms (the caller sequences: set_exclusions
// -> await ok -> bridge.setBearerLock / setEdgeIp).
export function planCandidateRefresh(oldSet, newSet, bearerIp) {
  const next = uniq(newSet);
  const bearerStillValid = bearerIp !== null && next.includes(bearerIp);
  return {
    pinsToSend: next,
    added: next.filter((ip) => !oldSet.includes(ip)),
    retired: oldSet.filter((ip) => !next.includes(ip)),
    bearerStillValid,
    nextBearerIp: bearerStillValid ? bearerIp : (next[0] ?? null),
  };
}

// UI rule (notes v2 §3): the "follow default resolution" choice is
// disabled while TUN is on.
export function edgeModeDisabledInTun(mode, tunActive) {
  return Boolean(tunActive) && mode === "default";
}

export function isDialAllowed(ip, lockSet) {
  if (lockSet === null) return true; // no TUN, no lock
  return ip !== null && lockSet.includes(ip);
}
