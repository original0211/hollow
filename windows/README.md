# Hollow Windows client

Implements the plan in `../../files/m2/windows-mvp-plan.md` (goal workspace).
Status: **M2-1 + M2-2 landed** (NP-1114-03 / NP-1114-05) — full bridge state
machine and the hardened system proxy (iron snapshot rule, atomic verified
backups, exact-match startup self-heal). Electron shell, M1 core reused
byte-identical via a vendored copy (integrity proven by
`tools/verify-vendor.mjs` on every check run).

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
