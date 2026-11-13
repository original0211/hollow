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

## T-2 additions (NP-1114-20)

- `internal/netcfg` — the routing takeover under the Self-Heal Discipline
  Spec (`../../files/m2/self-heal-discipline-spec.md`, the single source
  of truth shared with the JS sysproxy layer): snapshot-before-touch with
  the iron rule, add-before-delete set changes (spec R5), verified
  restore, four-state startup self-heal, and the route planner (exclusion
  /32s via the physical gateway BEFORE the /1 takeover routes; restore in
  the reverse order). The original default route is never modified.
  Address plan (spec §1.3): adapter IPv4 `10.99.0.1/24`, IPv6 `fd00::1/64`;
  the pump's in-stack anchors are the same addresses (`HelperAddr`,
  `HelperAddr6`).
- IPC verb `set_exclusions` refreshes the candidate/exclusion set while
  TUN is up; `enable_tun` takes the initial set. Every teardown path
  (disable / restore / dead-man) restores the takeover.
- `--restore-tun` is the emergency command (spec §6): run elevated, it
  unwinds per the held snapshot (or the fingerprint set when corrupt) and
  verifies by re-reading the table.
- IPv6 phase-1 fast reject: the pump's stack is dual-family; v6 TCP/UDP
  is counted (`droppedV6` in status) and silently dropped — never proxied,
  never answered. v6 takeover routes are in the netcfg plan.
- The Windows System adapter (route.exe/netsh) is compile-verified only;
  its real-machine behavior list lives in
  `../../files/m2/real-machine-tun-t2-addendum.md`.

## T-3 additions (NP-1114-22)

- `internal/dns` — the tunnelled resolver (notes v2 §4, mandatory change
  E): queries arriving at the adapter's resolver address (10.99.0.1:53)
  are forwarded as DNS-over-TCP to `ResolverAddr` (default 1.1.1.1:53)
  through the app's SOCKS — i.e. inside the Hollow tunnel, resolved at
  the exit. ONE persistent upstream connection, multiplexed by message
  ID (collisions rewritten and mapped back); per-query timeout 5s →
  SERVFAIL, no retries; every failure path ends in SERVFAIL — the
  resolver's only dialer is SOCKS, so falling back to a physical DNS is
  impossible by construction. Carrier rotation breaks the stream;
  in-flight queries SERVFAIL and the next query redials. Query contents
  are never logged; the status surface carries dnsQueries / dnsResolved /
  dnsServfail / dnsConns counters (dnsConns is the reuse proof).
- netcfg's Written adapter config now carries the DNS field
  (`10.99.0.1`); the netsh assignment itself is T-4 adapter wiring, with
  the real-machine checks in `../../files/m2/real-machine-tun-t3-addendum.md`.

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
