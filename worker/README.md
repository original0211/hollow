# worker/

服务端 Worker（Cloudflare Workers）。当前为最小空壳：

- `GET /health` → `{ name, version, status: "ok" }`
- `GET /` 与 `GET /version` → `{ name, version }`
- 其余路径 → 404

不含协议逻辑；协议实现等 spec v0.1 过审后另行派工。`wrangler.toml` 仅为配置占位，本目录未部署。
