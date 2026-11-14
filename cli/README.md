# cli/

Hollow 命令行客户端（M1 最小原型），实现冻结 spec v0.1 的客户端：本地生成 PSK、X25519+Finished 握手、记录层加解密、流多路复用、OPEN_QUEUED 排队等待、承载监督（§8.4 退避重连、§5.6 15 分钟轮换）。

```bash
node cli/src/cli.js --version     # hollow-cli 0.1.0
node cli/src/cli.js --health      # {"name":"hollow-cli","version":"0.1.0","status":"ok"}
node cli/src/cli.js psk init      # 在 ~/.hollow/psk.bin 生成 PSK（0600），并打印校验值 V
node cli/src/cli.js psk verifier  # 打印现有 PSK 的校验值 V（供所有者设置 Worker secret）
HOLLOW_WORKER_URL="wss://hollow.example.workers.dev/" \
  node cli/src/cli.js serve --listen 127.0.0.1:1080   # SOCKS5 本地入口（loopback、仅 CONNECT）
```

- PSK 只存本地文件（默认 `~/.hollow/psk.bin`，权限 0600），永不入仓、永不出现在日志。
- 本地入口选定 **SOCKS5**（`src/socks.js`）；错误映射：OPEN 被拒按错误码回 REP（禁区类 → 2、不可达 → 5、其余 → 1），非 CONNECT 命令回 REP 7。
- WebSocket 承载为手写客户端（`src/ws-client.js`）：自定义 UA `HollowClient/0.1`、客户端掩码、75–150 秒随机应用层 ping。
