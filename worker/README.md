# worker/

服务端 Worker（Cloudflare Workers），实现冻结 spec v0.1 的服务端：握手（§5）、记录层与流帧层（§6）、出站选门（§7）、错误与队列（§7.5/§8）。

- 部署形态：脚本名 `hollow`，部署在专用免费账号、仅 workers.dev 子域。非 Upgrade 的 HTTP 请求只回固定极简静态页（见 `src/entry.js` 注释）。
- 元数据端点（NP-1114-11 增设、NP-1114-15 总审收紧定版）：两个只读端点（落地 colo/国家回显、策展候选 IP 名单下发）位于带部署随机段的不可猜路径上，随机段存 Worker secret（不入仓），客户端经配对载荷或设置页获知路径；名单载荷只含 IP。其余非 Upgrade 路径仍只回固定静态页。
- 源码：`src/entry.js`（入口：静态页、secret 读取、传输注入）+ 仓根 `shared/`（协议核心，与 CLI 共用）。`src/index.js` 是 `tools/build-worker.mjs` 的打包产物，**部署的是它**；改 shared 或 entry 后必须重跑打包。
- 配置：`wrangler.toml`（`nodejs_compat`，原因见 `docs/IMPLEMENTATION.md` §2）。
- 密钥：PSK 本身不进服务端；只存校验值 V，经 secret `PSK_V_HEX`（key_id 1）与可选 `PSK_V_HEX_2`（key_id 2）注入，代码零硬编码。
