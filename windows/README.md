# Hollow Windows client

Implements the plan in `../../files/m2/windows-mvp-plan.md` (goal workspace).
Status: **v0.2.0 — M2 complete (sandbox side)**: M2-1 bridge (NP-1114-03),
M2-2 system proxy (NP-1114-05), M2-3 config & pairing (NP-1114-07), M2-4
edge-IP + PAC (NP-1114-11), M2-5 hardening (NP-1114-14). Real-machine
acceptance is packaged separately (goal files: `m2/real-machine-acceptance-pack.md`).
Electron shell, M1 core reused byte-identical via a vendored copy
(integrity proven by `tools/verify-vendor.mjs` on every check run).

## Feature map (v0.2.0)

- **Connect**: bridge state machine with §8.4 backoff, 15-minute carrier
  rotation, fatal-error classification; local SOCKS5 entry (port 1080,
  auto-increments when taken); per-day stream/byte/queue stats.
- **System proxy** (Windows): three modes — off / global / PAC — under one
  snapshot discipline: the pre-existing registry state (all four WinINET
  values) is snapshotted atomically before any write, restored byte-exact,
  with startup self-heal (exact/written/foreign fingerprint states) and an
  automatic restore when the carrier dies fatally. Emergency CLI:
  `Hollow.exe --restore-proxy` (bypasses the single-instance lock).
- **PAC mode**: loopback endpoint serves a generated PAC — LAN/localhost
  and your editable direct-host list go DIRECT, everything else via SOCKS.
- **Edge-IP selection**: curated Cloudflare anycast candidates (refreshable
  from the Worker's `/edges.json`), 3-handshake median RTT measurement,
  per-IP landing per-IP landing identification through the deployment-specific meta endpoint (path learned via pairing or Settings, never shipped in the repo), three selection modes
  (default / auto-best / manual). Labels show the measured landing colo —
  never a promised country.
- **Pairing** (below): PSK generated locally, only its verifier V is ever
  shown; import by link / file / QR, always behind an in-app confirmation
  that names the target Worker before anything is written.

## Pairing a fresh install (≤15 minutes)

1. Deploy the Worker (repo root): `cd worker && npx wrangler deploy`
   (or, in the Cloudflare console: Workers & Pages → `hollow` →
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
