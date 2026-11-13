# newproto（代号）

从零设计的代理协议与配套客户端（Windows / Android），服务端运行在 Cloudflare 免费额度上。

> 代号说明：`newproto` 为开发期代号，正式名未定，定后仓库可改名。
> 本仓库开发期私有。协议规格见 `spec/`（v0.1 制定中），本仓库目前只有工程脚手架与最小空壳，不含协议实现。

## 目录

- `worker/` — 服务端 Worker（Cloudflare Workers），当前为最小空壳（版本与健康状态端点）。
- `cli/` — 最小原型 CLI，当前为最小空壳（`--version` / `--health`）。
- `spec/` — 协议规格文档存放处。
- `docs/` — 项目文档。
- `tests/` — 冒烟测试（Node 内置 test runner，无外部依赖）。

## 本地开发入口

环境：Node.js ≥ 20，无第三方依赖。

```bash
# CLI 空壳
node cli/src/cli.js --version
node cli/src/cli.js --health

# 测试
node --test
```

## 部署与使用说明

占位：部署与使用说明留到 M1 原型跑通后补全。

## 安全纪律

- 仓库内禁止存放任何密钥、令牌、账号凭据；密钥一律在用户本地生成，代码零硬编码。
- 本地密钥文件（`*.key`、`key*.json`、`.env*` 等）已由 `.gitignore` 排除。
