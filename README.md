# Hollow

从零设计的代理协议与配套客户端（Windows / Android），服务端运行在 Cloudflare 免费额度上。

> 正式名：Hollow（2026-11-13 定名，原代号 NEWPROTO 退役；仓库已由 newproto 改名为 hollow）。
> 本仓库开发期私有。协议规格已冻结于 `spec/protocol-spec-v0.1.md`（NP-1113-03/05 审查通过）。
> **M1 最小原型已实现并部署**（NP-1113-06）：CLI ↔ Worker 按冻结 spec 完成握手与逐帧加密的 TCP 代理，端到端跑通；实现说明见 `docs/IMPLEMENTATION.md`。

## 目录

- `worker/` — 服务端 Worker（已部署为新账号脚本 `newproto-hollow`，仅 workers.dev）。
- `cli/` — 命令行客户端：PSK 管理 + SOCKS5 本地入口（`serve`）。
- `shared/` — 双端共享协议核心（握手、记录层、流帧层、选门）。
- `spec/` — 冻结的协议规格 v0.1 及冻结记录。
- `docs/` — 项目文档（实现说明）。
- `tests/` — 本地测试（Node 内置 test runner）与线上验收脚本（`tests/acceptance/`）。
- `tools/` — Worker 单文件打包（`build-worker.mjs`）。

## 本地开发入口

环境：Node.js ≥ 20，无第三方依赖。

```bash
node cli/src/cli.js --version
node cli/src/cli.js --health
npm test                        # 本地全套（16 项）
node tools/build-worker.mjs     # 改 shared/ 或 worker/src/entry.js 后重打包
```

## 安全纪律

- 仓库内禁止存放任何密钥、令牌、账号凭据；PSK 在用户本地生成（0600 文件），服务端只存校验值 V（secret 注入），代码零硬编码。
- 本地密钥文件（`*.key`、`key*.json`、`.env*` 等）已由 `.gitignore` 排除。
