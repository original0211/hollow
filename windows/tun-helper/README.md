# hollow-tun-helper (TUN helper, NP-1114-19: T-0 + T-1)

The elevated helper process for Hollow's TUN mode, built to the frozen
design in `../../files/m2/tun-implementation-notes-v2.md`. It holds the
Wintun adapter and a userspace netstack, and splices every TCP flow into
the app's existing loopback SOCKS listener. **The helper has zero
knowledge of the Hollow protocol — it moves bytes only.**

## Layout

- `cmd/hollow-tun-helper` — entry point; `--version`, `--check-dll`.
- `internal/ipc` — the fixed-verb pipe protocol (closed verb set:
  enable_tun / disable_tun / note_mode / status / restore / ping;
  newline-delimited JSON, size-capped; heartbeat frames).
- `internal/server` — portable core: mode arbitration (off/sysproxy/tun),
  pump lifecycle, heartbeat emission, and the dead-man's switch (TUN up +
  app silent beyond the freshness threshold on the sleep-excluded clock ⇒
  self-teardown; netcfg restore joins this path in T-2).
- `internal/clock` — monotonic, sleep-excluded time (Windows:
  QueryUnbiasedInterruptTime).
- `internal/pump` — gVisor netstack + TCP forwarder → SOCKS5. Flow table:
  512 max, 120 s idle reap, table-full ⇒ RST (no second queue here).
  Non-DNS UDP is dropped and counted (DNS handling is T-3).
- `internal/tun` — Wintun pin + (Windows) link endpoint over a session.
- `internal/pipe` — named-pipe listener, ACL = LocalSystem + owner SID.

## Pins and provenance (read before bumping anything)

- **Wintun 0.14.1**, amd64 DLL vendored at `third_party/wintun/wintun.dll`
  with its LICENSE.txt. Zip SHA-256 (as published on wintun.net):
  `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`;
  DLL SHA-256 `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`.
  The helper verifies the DLL next to its exe against this hash before
  loading and refuses any other bytes; a unit test pins the vendored file.
- **Netstack: gVisor via the SagerNet build fork**
  (`github.com/sagernet/gvisor`, version in `go.mod`). Upstream
  `gvisor.dev/gvisor` module zips are NOT consumable by the Go toolchain:
  they omit Bazel-generated sources (e.g. `pkg/bits` template outputs,
  `pkg/sync` template assembly) and carry a stray cross-package test file
  in `pkg/tcpip/stack`, so even a trivial import fails to build — this is
  why every serious Go consumer pins an ancient snapshot or a fork. The
  SagerNet fork is the same Apache-2.0 gVisor codebase with the generated
  files checked in, maintained for sing-box. Chosen and recorded in
  NP-1114-19; the T-2 red-team construction audit may revisit it.
- **Go 1.27** (module directive in `go.mod`); go-winio for the pipe;
  `golang.zx2c4.com/wintun` for the adapter bindings.

## Netstack integration notes (learned the hard way, NP-1114-19)

- The helper NIC must own at least one address (the adapter's own IP):
  gVisor's IPv4 layer delivers foreign-destination packets locally only
  when promiscuous acquisition can anchor them to an assigned address —
  with none, SYNs die as invalid destinations before any transport
  handler runs.
- PacketBuffers are not wire bytes: an outbound buffer re-injected into
  another stack fails parse validation (MalformedPacketsReceived). The
  test channel pair round-trips through bytes, as a real wire would.
  (The Wintun endpoint constructs fresh buffers from adapter reads and
  serializes on write, so production never had this bug — it was
  test-harness only, but it cost a full debugging cycle; the stack's own
  IP counters are what found it.)

## Build & test

```sh
go vet ./... && go test ./...          # portable core, any OS
GOOS=windows go build ./...           # windows cross-build
go build -o hollow-tun-helper.exe ./cmd/hollow-tun-helper   # on Windows
```

Windows runtime behavior that a sandbox cannot prove (DLL load, UAC,
adapter creation, pipe ACL under a second user) is listed in
`../../files/m2/real-machine-tun-t0t1-addendum.md` — do not treat the
green suites here as evidence for those.
