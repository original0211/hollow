Hollow Android vX.Y.Z — M3 MVP 签名版（arm64 单 ABI，Android 8.0+）。

变更：
- （逐条写本版变更）

校验：
- APK SHA-256 见随附 .sha256 文件；签名证书以 apksigner verify 输出为准（见发版运行记录）。

已知边界（如实）：
- UDP 流量不经过 Hollow 加密通道；IPv6 已阻断。
- 蜂窝 IPv6-only + NAT64 环境未实测（见真机清单 D 段）。
- 本版为自用侧载分发，不经应用商店。
