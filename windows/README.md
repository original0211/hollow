# Hollow Windows client

Implements the plan in `../../files/m2/windows-mvp-plan.md` (goal workspace).
Status: **M2-1 + M2-2 + M2-3 landed** (NP-1114-03 / NP-1114-05 /
NP-1114-07) — full bridge state machine, the hardened system proxy (iron
snapshot rule, atomic verified backups, exact-match startup self-heal),
and config & pairing (below). Electron shell, M1 core reused byte-identical
via a vendored copy (integrity proven by `tools/verify-vendor.mjs` on every
check run).

## Pairing a fresh install (≤15 minutes)

1. Deploy the Worker (repo root): `cd worker && npx wrangler deploy`
   (or, in the Cloudflare console: Workers & Pages → `newproto-hollow` →
   Settings → Variables and Secrets).
2. Start Hollow once — it generates its PSK locally
   (`%APPDATA%\Hollow\psk.bin`, ACL-locked) and shows the pairing value **V**
   on the Pairing card. The PSK itself is never displayed.
3. Put V into the Worker secret `PSK_V_HEX`, either path:
   - **wrangler**: `npx wrangler secret put PSK_V_HEX` (paste V), or
   - **console**: Worker → Settings → Variables and Secrets → Add →
     type *Secret*, name `PSK_V_HEX`, value = V.
4. Set the Worker address in Hollow if it differs from the default, then
   click **测试连接** — it runs a real handshake. Success = paired.

Moving to a second machine (any of the three forms lands on the same
in-app confirmation — nothing is applied without your click):
- **Link**: copy a `hollow://` link (or generate the config QR) on machine
  A; paste it into the import box on machine B.
- **File**: export `hollow-config.json` on A (default excludes the PSK —
  that pairs the address only; the *with-PSK* export is behind an extra
  confirmation), import the file on B.
- **QR**: scan from an image file or the clipboard on B. A QR that carries
  the PSK is behind the same extra confirmation on A.

If `psk.bin` is ever damaged, Hollow refuses to start pairing and says so —
it never silently regenerates (that would break pairing without a trace).

Layout:
- `src/main.js` — Electron main: window + tray + single instance + `--restore-proxy`.
- `src/preload.js` — whitelist IPC bridge (connect / disconnect / getState / logs).
- `src/renderer/` — status shell UI.
- `src/core-bridge.js` — HollowClient + SOCKS entry + state machine (Electron-free, used by the smoke).
- `src/sysproxy.js` — HKCU system proxy save/set/restore (Windows only).
- `src/config.js` — `%APPDATA%\Hollow` (or `~/.hollow`) config + PSK; verifier display.
- `smoke.mjs` — headless smoke: `npm run smoke` (connect → handshake → fetch through a stream).
- `tools/prepare-vendor.mjs` — copies `../shared` + `../cli/src/{ws-client,socks}.js` into `vendor/` at repo-identical depth (generated, gitignored), so vendored relative imports resolve exactly as in the repo.

Commands:
- `npm install` — dev deps (Electron, electron-builder).
- `npm run check` — vendor prep + syntax checks.
- `npm run smoke` — live smoke against the deployed Worker (PSK from config dir).
- `npm start` — run the shell.
- `npm run dist` — portable single-file exe into `dist/` (also what CI builds).

No key material lives in this repo: PSK comes from the user config dir only.
