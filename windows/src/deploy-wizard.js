// Guided deployment wizard (NP-1118-42, design NP-1118-41):
// deploy the user's OWN Hollow Worker from inside the app — no
// console. The six steps mirror the verified production deploy
// procedure (NP-1117-01): verify the token, generate the pairing
// locally, PUT the bundled Worker with both secrets, enable the
// workers.dev subdomain, prove liveness (facade + /meta + real
// handshake, riding out the version-propagation lag), and only
// then persist the config and connect.
//
// Pure orchestration with injected effects (house style); main.js
// wires the real Cloudflare API / bundle / storage effects. Every
// step is idempotent — a failure names its step and code, changes
// nothing locally, and re-running converges. The token is used
// only through deps.api and is never logged or returned.
//
// Failure codes: TOKEN_INVALID, TOKEN_FORBIDDEN (missing a
// required permission), NO_ACCOUNT, MULTI_ACCOUNT (caller picks),
// DEPLOY_FAILED (with a workersNotEnabled hint flag when the API
// error says so), SUBDOMAIN_FAILED, LIVENESS_FAILED (with the
// per-part results), FINALIZE_FAILED.

export const WIZARD_SCRIPT_NAME = "hollow";
export const WIZARD_STEPS = ["verify", "generate", "deploy", "subdomain", "liveness", "finalize"];

export function buildDeployMetadata({ vHex, metaSeg }) {
  return {
    main_module: "index.js",
    compatibility_date: "2025-10-01",
    compatibility_flags: ["nodejs_compat"],
    usage_model: "standard",
    bindings: [
      { name: "META_SEG", type: "secret_text", text: metaSeg },
      { name: "PSK_V_HEX", type: "secret_text", text: vHex },
    ],
  };
}

// A claimable workers.dev subdomain candidate from the account
// name: lowercase slug + a short random suffix (collisions are
// retried by the caller with a fresh suffix).
export function subdomainCandidate(accountName, suffix) {
  const slug = String(accountName || "hollow")
    .toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 24) || "hollow";
  return `${slug}-${suffix}`;
}

function fail(step, code, detail, extra = {}) {
  return { ok: false, step, code, detail, ...extra };
}

export async function runWizard(deps, input) {
  const progress = deps.progress ?? (() => {});
  const step = async (name, fn) => { progress({ step: name, state: "start" }); const r = await fn(); progress({ step: name, state: r && r.__fail ? "fail" : "done" }); return r; };

  // Step 0 — verify the token and resolve the account.
  const v = await step("verify", async () => {
    let ver;
    try { ver = await deps.api("GET", "/user/tokens/verify"); }
    catch (e) { return { __fail: fail("verify", "TOKEN_INVALID", `令牌校验请求失败：${e.message}`) }; }
    if (!ver.ok) {
      return { __fail: fail("verify", ver.status === 403 ? "TOKEN_FORBIDDEN" : "TOKEN_INVALID", `令牌被 Cloudflare 拒绝（HTTP ${ver.status}）`) };
    }
    let accs;
    try { accs = await deps.api("GET", "/accounts"); }
    catch (e) { return { __fail: fail("verify", "TOKEN_INVALID", `账号列表请求失败：${e.message}`) }; }
    if (!accs.ok) return { __fail: fail("verify", "TOKEN_FORBIDDEN", `读不到账号列表（HTTP ${accs.status}）——令牌缺 Account Settings: Read？`) };
    const list = accs.result ?? [];
    if (list.length === 0) return { __fail: fail("verify", "NO_ACCOUNT", "该令牌下没有任何 Cloudflare 账号") };
    if (!input.accountId && list.length > 1) {
      return { __fail: fail("verify", "MULTI_ACCOUNT", "令牌下有多个账号，请选择部署目标", { accounts: list.map((a) => ({ id: a.id, name: a.name })) }) };
    }
    const account = list.find((a) => a.id === input.accountId) ?? list[0];
    if (input.accountId && account.id !== input.accountId) return { __fail: fail("verify", "NO_ACCOUNT", "所选账号不在该令牌下") };
    return { account };
  });
  if (v.__fail) return v.__fail;
  const account = v.account;
  // The token proved itself — the caller persists it now so a
  // later failure still leaves one-click retry/update possible.
  if (deps.onTokenVerified) { try { await deps.onTokenVerified(input.token, account); } catch { /* storage trouble must not fail the deploy */ } }

  // Step 1 — generate the pairing locally.
  const g = await step("generate", async () => {
    const psk = deps.randomBytes(32);
    const metaSeg = deps.randomHex(16);
    const vHex = await deps.deriveVerifierHex(psk);
    return { psk, metaSeg, vHex, keyId: 1 };
  });

  // Step 2 — deploy the bundled Worker with both secrets.
  const d = await step("deploy", async () => {
    const bundle = await deps.getBundle();
    let r;
    try {
      r = await deps.deployScript({
        accountId: account.id, scriptName: WIZARD_SCRIPT_NAME, bundle,
        metadata: buildDeployMetadata({ vHex: g.vHex, metaSeg: g.metaSeg }),
      });
    } catch (e) { return { __fail: fail("deploy", "DEPLOY_FAILED", `部署请求失败：${e.message}`) }; }
    if (!r.ok) {
      const text = JSON.stringify(r.errors ?? r);
      const workersNotEnabled = /not.*enabled|workers.*disabled|10063/i.test(text);
      return { __fail: fail("deploy", "DEPLOY_FAILED", `部署被拒（HTTP ${r.status}）：${text.slice(0, 240)}`, { workersNotEnabled }) };
    }
    return {};
  });
  if (d.__fail) return d.__fail;

  // Step 3 — workers.dev subdomain: read the account subdomain,
  // claim one if the account never had it, enable the script's.
  const s = await step("subdomain", async () => {
    let subName = null;
    try {
      const r = await deps.api("GET", `/accounts/${account.id}/workers/subdomain`);
      if (r.ok) subName = r.result?.subdomain ?? null;
    } catch { /* treated as unset below */ }
    if (!subName) {
      for (let attempt = 0; attempt < 3 && !subName; attempt++) {
        const candidate = subdomainCandidate(account.name, deps.randomHex(2));
        try {
          const r = await deps.api("PUT", `/accounts/${account.id}/workers/subdomain`, { subdomain: candidate });
          if (r.ok) subName = candidate;
        } catch { /* next attempt */ }
      }
      if (!subName) return { __fail: fail("subdomain", "SUBDOMAIN_FAILED", "账号尚无 workers.dev 子域且自动领取失败——请在 Cloudflare 控制台的 Workers 页面领取一次子域后重试") };
    }
    try {
      const r = await deps.api("POST", `/accounts/${account.id}/workers/scripts/${WIZARD_SCRIPT_NAME}/subdomain`, { enabled: true });
      if (!r.ok) return { __fail: fail("subdomain", "SUBDOMAIN_FAILED", `脚本子域启用被拒（HTTP ${r.status}）`) };
    } catch (e) { return { __fail: fail("subdomain", "SUBDOMAIN_FAILED", `脚本子域启用请求失败：${e.message}`) }; }
    return { subName };
  });
  if (s.__fail) return s.__fail;
  const workerUrl = `wss://${WIZARD_SCRIPT_NAME}.${s.subName}.workers.dev`;
  const pairing = {
    workerUrl, keyId: g.keyId, psk: g.psk,
    metaPath: `${g.metaSeg}/meta`, edgesPath: `${g.metaSeg}/edges`,
  };

  // Step 4 — liveness: facade + /meta + real handshake, riding
  // out the post-deploy propagation lag (measured ~3 min worst
  // case) before declaring failure; the parts are reported
  // separately so the copy can say WHAT did not come up.
  const l = await step("liveness", async () => {
    const deadline = deps.now() + (deps.livenessWindowMs ?? 180_000);
    let last = null;
    for (;;) {
      try { last = await deps.probeLiveness(pairing); } catch (e) { last = { facade: false, meta: false, handshake: false, detail: e.message }; }
      if (last.facade && last.meta && last.handshake) return { last };
      if (deps.now() >= deadline) {
        return { __fail: fail("liveness", "LIVENESS_FAILED", "部署完成但验活未通过——Worker 已在账号里，可稍后重试向导（会直接收敛到验活）", { parts: last }) };
      }
      await deps.sleep(deps.livenessPollMs ?? 15_000);
    }
  });
  if (l.__fail) return l.__fail;

  // Step 5 — persist as the current config (the caller connects).
  const f = await step("finalize", async () => {
    try { await deps.finalize(pairing, account); }
    catch (e) { return { __fail: fail("finalize", "FINALIZE_FAILED", `配置落盘失败：${e.message}——Worker 已部署且验活通过，可用手动导入接回`) }; }
    return {};
  });
  if (f.__fail) return f.__fail;

  return { ok: true, workerUrl, accountId: account.id, accountName: account.name, subdomain: s.subName };
}

// One-click cleanup offered on the failure page (never forced):
// delete the wizard's script from the user's own account.
export async function deleteDeployedWorker(deps, { accountId }) {
  try {
    const r = await deps.api("DELETE", `/accounts/${accountId}/workers/scripts/${WIZARD_SCRIPT_NAME}`);
    return { ok: !!r.ok, status: r.status };
  } catch (e) {
    return { ok: false, detail: e.message };
  }
}
