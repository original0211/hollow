# gVisor license (vendored)

`LICENSE.txt` is the Apache License 2.0 text of the gVisor netstack this
helper links against — vendored verbatim from the pinned fork module
`github.com/sagernet/gvisor v0.0.0-20260727.0-sing-box-mod.1`
(sha256 of this file at vendoring time: 0fbab5c58efbdf6d31e8…).

It ships in dist as `GVISOR-LICENSE.txt` next to `WINTUN-LICENSE.txt`
(red-team condition on the NP-1114-21 fork ruling; NP-1114-25 item 7).
The windows-build workflow asserts both license files exist in dist —
a build missing either one goes red.
