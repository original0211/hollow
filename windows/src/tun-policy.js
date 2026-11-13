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
// bearer may dial has a /32 host route around the tunnel, and nothing
// else is ever dialed while TUN is up. IPv6 candidates are stripped at
// this layer with the reason reported (RF-21-05) — no /128 routes exist
// this phase. Sequencing (spec R5): the helper confirms the new set
// BEFORE the bridge is pointed at a new IP.

const uniq = (xs) => [...new Set(xs.filter(Boolean))];

// RF-21-05: IPv6 candidates are STRIPPED at this policy layer — no v6
// host routes exist in the takeover set (the Windows netsh surface for
// them was untestable in-sandbox and the design keeps exclusions v4-only
// this phase). Stripping is reported, never silent, and never fails the
// whole plan: the v4 remainder proceeds. (The helper's Enable applies the
// same strip as defense in depth.)
export const V6_STRIP_REASON = "ipv6 candidate stripped: TUN exclusions are IPv4 /32 only this phase (RF-21-05)";
const isV6 = (ip) => typeof ip === "string" && ip.includes(":");
function partitionV6(ips) {
  const v4 = [];
  const stripped = [];
  for (const ip of uniq(ips)) {
    if (isV6(ip)) stripped.push({ ip, reason: V6_STRIP_REASON });
    else v4.push(ip);
  }
  return { v4, stripped };
}

// edgeMode: "default" | "auto" | "manual" (config.edgeMode).
// candidates: the current candidate IPs (edges list / cache / builtin).
// resolvedIps: fresh DNS answers for the Worker hostname — required when
//   edgeMode is "default" (that mode is disabled under TUN; enabling TUN
//   first resolves the name and pins the answers, per notes v2 §3).
export function planTunEnable({ edgeMode, preferredEdgeIp = null, autoBestIp = null, candidates = [], resolvedIps = [] }) {
  const candParts = partitionV6(candidates);
  const resParts = partitionV6(resolvedIps);
  const stripped = [...candParts.stripped, ...resParts.stripped];
  const base = candParts.v4;
  let chosen = null;
  if (edgeMode === "manual") chosen = preferredEdgeIp;
  else if (edgeMode === "auto") chosen = autoBestIp;
  else chosen = resParts.v4[0] ?? null; // "default": pin a resolved answer
  if (chosen && isV6(chosen)) {
    // A v6 bearer cannot be pinned either — report and refuse cleanly
    // rather than planning a set the helper would strip asymmetrically.
    stripped.push({ ip: chosen, reason: V6_STRIP_REASON });
    return { ok: false, reason: "selected bearer IP is IPv6 — no v6 bearer under TUN this phase (RF-21-05)", pins: base, bearerIp: null, stripped };
  }

  if (!chosen) {
    return {
      ok: false,
      reason: edgeMode === "default"
        ? "default-resolution mode has no resolved IP to pin — resolve the Worker hostname first (TUN forbids live DNS dialing)"
        : `no bearer IP selected in ${edgeMode} mode`,
      pins: base,
      bearerIp: null,
      stripped,
    };
  }
  // The chosen IP joins the set if it is not already a candidate (a manual
  // pick outside the edges list still gets its /32 — one ledger).
  const pins = uniq([...base, ...resParts.v4, chosen]);
  return { ok: true, pins, bearerIp: chosen, stripped };
}

// A live candidate-list refresh while TUN is up. The helper applies the
// new set add-before-delete internally; the bridge may only switch its
// bearer AFTER the helper confirms (the caller sequences: set_exclusions
// -> await ok -> bridge.setBearerLock / setEdgeIp).
// A live candidate-list refresh while TUN is up — TWO PHASES
// (RF-21-03②): phase 1 sends the UNION (new pins added, NOTHING retired,
// so the current bearer's /32 provably survives the switch); only after
// the bridge confirms it has moved to nextBearerIp does phase 2 send the
// final set, retiring the old pins. Deleting the old bearer's exclusion
// before the bridge switched would route the live bearer through the
// tunnel — the exact loop this prevents.
export function planCandidateRefresh(oldSet, newSet, bearerIp) {
  const parts = partitionV6(newSet);
  const next = parts.v4;
  const phase1Pins = uniq([...oldSet, ...next]);
  const bearerStillValid = bearerIp !== null && next.includes(bearerIp);
  return {
    pinsToSend: phase1Pins, // phase 1: union — adds only, zero retirements
    finalPins: next, // phase 2: send after the bridge confirms the switch
    added: next.filter((ip) => !oldSet.includes(ip)),
    retired: oldSet.filter((ip) => !next.includes(ip)), // informational
    retiredAfterConfirm: oldSet.filter((ip) => !next.includes(ip)),
    bearerStillValid,
    nextBearerIp: bearerStillValid ? bearerIp : (next[0] ?? null),
    stripped: parts.stripped,
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
