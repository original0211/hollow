# Hollow for Android（M3）

Kotlin shell + Go core (gomobile AAR). Plan: `files/m3/android-mvp-plan.md`
(NP-1114-28, approved 2026-11-14: D1 Kotlin+Go / D4 targetSdk 34 /
D5 arm64-v8a only / D8 applicationId below).

## Layout

| Path | What |
|---|---|
| `core/` | Go module `hollow/androidcore` — the binding seam (`Version`/`Echo`) plus, since M3-1, the full protocol core port in `core/core/` (package `core`), locked to the JS canonical implementation by `core/testvectors/vectors-v0.1.2.json` (policy: `core/VECTORS.md`) |
| `app/` | Kotlin shell: `MainActivity` (status + consent flow + pairing import/export panel) and `HollowVpnService` (specialUse foreground + the M3-2 data plane: `establish()` → fd handed to the Go session; restart gate per plan §2) |
| `app/libs/hollowcore.aar` | gomobile output — build artifact, git-ignored, produced by the bind step below |

Fixed parameters: applicationId `eu.org.brodydung.hollow`, minSdk 26,
targetSdk/compileSdk 34, single ABI `arm64-v8a`.

## Build

CI (`.github/workflows/android-build.yml`) is the reference build;
locally the same steps:

```sh
# pins: Go 1.27.4 · JDK 17 · Gradle 8.7 · AGP 8.5.2 · Kotlin 2.0.20
#       Android SDK platform 34 · build-tools 34.0.0 · NDK 27.0.12077973
#       gomobile golang.org/x/mobile v0.0.0-20261011034528-197770444867
go install golang.org/x/mobile/cmd/gomobile@v0.0.0-20261011034528-197770444867
cd core && go test ./... && gomobile init
gomobile bind -target=android/arm64 -androidapi=26 -o ../app/libs/hollowcore.aar .
cd .. && gradle :app:assembleDebug
```

No Gradle wrapper is committed yet: CI pins Gradle via
`gradle/actions/setup-gradle`. Generate the wrapper locally once
(`gradle wrapper --gradle-version 8.7`) if you want `./gradlew`;
the version pins above are the contract either way.

The AAR is a hard dependency of `:app` — building the shell without
binding the core first fails loudly by design (never ship a coreless
APK silently).

## Workflow scope (who builds what)

- `android-build` — path-filtered to `android/**` + its own file;
  produces the unsigned **debug** APK. Release signing is M3-5.
- `windows-build` — path-filtered to `windows/**` + its own file.
- `ci` — unfiltered but node-only (root `npm test` + syntax checks);
  it does not see or build anything Android.

## Skeleton behavior (M3-0, honest scope)

- The activity shows the Go core's version/echo strings — if they
  render, bind → AAR → JNI works end to end.
- "开启 VPN（骨架）" runs the real consent flow (`VpnService.prepare`
  → system dialog) and starts the service, which promotes itself to
  the foreground with the `specialUse` type (see
  `files/m3/fgs-verification-record.md`).
- Since M3-2 the service establishes the TUN (10.99.0.1/24 +
  fd00::1/64, routes 0.0.0.0/0 and ::/0 — v6 enters the TUN and is
  dropped there, never bypassed — DNS 10.99.0.1, MTU 1280) and hands
  the fd to the Go session (`Hollowcore.startVPN`): pump + DNS +
  protocol core run in-process; every egress socket is protect()ed
  through the service bridge.
