# docs/IMPLEMENTATION.md — M1 最小原型实现说明（NP-1113-06）

实现对象：冻结件 `spec/protocol-spec-v0.1.md`（54,329 B，md5 `aebf671e633551b7ebad744770d85b98`）。
本文只记录实现选择与实测事实，不改动 spec 任何口径；与 spec 冲突时以 spec 为准并停报队长。

## 1. 架构

双端共享同一核心，单仓三处代码：

- `shared/protocol.js` — 常量、帧编解码、记录层 seal/open、HKDF/HMAC 派生、OPEN 编解码、禁区判定、错误码。
- `shared/client-core.js` — `HollowClient`：握手状态机、流多路复用、双向流控、OPEN_QUEUED 处理。传输层注入（`send/onMessage/onClose/closeCarrier`），本地测试用内存传输、线上用 `cli/src/ws-client.js`。
  - **应用契约（NP-1116-01/02）**：流的 `onEnd`（对端 CLOSE）到达后，应用层**必须**履行关流义务——调用该流的 `closeWrite()`（或在异常时 `reset()`）。core 按 §6.3 半关语义不代答 CLOSE（应用可能仍有数据要发），而服务端要等到双方均 CLOSE 或任一方 RESET 才释放 §7.5 占用名额；应用漏关会把整条承载的并发名额无限期占死（M4 soak 实证：6 流整点被 OPEN_REJECT 0x01 拒绝）。各应用层泵（SOCKS、Go pump、测试 harness）均须遵守，回归用例见 `tests/protocol.test.mjs` 的 occupancy wedge 用例。
- `shared/server-core.js` — `HollowServer`：握手、§7.2 禁区校验、§7.3 选门、§7.4 fetch 事务、§7.5 占用/队列、socket 泵送与背压。出站注入（`connectFn/fetchFn`），Worker 入口传平台实现、本地测试传 node:net 实现。
- `worker/src/entry.js` + `tools/build-worker.mjs` — 把 shared 三件与入口打包为单文件 `worker/src/index.js` 部署（脚本名 `hollow`，新账号 newproto）。
- `cli/src/cli.js` — 命令面：`--version` / `--health` / `psk init` / `psk verifier` / `serve`。本地入口为 **SOCKS5**（`cli/src/socks.js`，loopback、仅 CONNECT）。

## 2. 平台决策：ChaCha20-Poly1305 走 node:crypto（非偏离）

能力微探针实测：Workers WebCrypto **不支持** `CHACHA20-POLY1305` 的 importKey（报 `Unrecognized key import algorithm`）；同一运行时在 `nodejs_compat` 下的 `node:crypto` 原生支持 `chacha20-poly1305`（往返验证通过）。Worker 因此启用 `nodejs_compat` 并用 node:crypto 执行 AEAD；CLI 端（Node）同一路径。属平台成熟实现、非自造加密，算法/密钥长度/nonce 构造/AAD 均按 spec §6 不变。

X25519、HMAC-SHA256、SHA-256 双端均走 WebCrypto subtle；HKDF 按 RFC 5869 用 HMAC 手工 Extract/Expand（双端同一实现，保证语义一致）。

## 3. 红队注记 R-1113-05-01 落地（fail-closed 两条）

`shared/protocol.js` 的 `parseFrames` 是唯一分流点，代码与语义一一对应：

- 单帧 `payload_len` 超 16,373 B 硬上限、但帧能恰好装入 `frames_len` → 返回 `oversize` 标记，调用方按 §8.2 发**流级 RESET**（`protocol_error`），不计记录级失败。
- 帧序列未恰好耗尽 `frames_len`（含截断、越界、残留）→ 抛记录级错误，`RecordReceiver` 按 §6.1 计**记录级失败**（连续计数、成功清零、连续 3 次关承载）。

本地测试 `tests/protocol.test.mjs` 对两条分别有正反用例。

## 4. 其余实现选择（spec 留白处）

- §2 非 Upgrade HTTP 响应固定静态页，字节已固定为：
  `<!doctype html><html><head><title>ok</title></head><body><p>ok</p></body></html>\n`
  （见 `worker/src/entry.js`；变更须在此登记。）
- PSK 只以校验值 V 存在于服务端：Worker secret `PSK_V_HEX`（key_id 1）/ `PSK_V_HEX_2`（key_id 2，可选轮换位）。代码零硬编码，secret 经 API 注入后回读仅见名与类型。
- 客户端 UA 固定 `HollowClient/0.1`（不含 proxy/vpn/tunnel 词，§2）。
- 服务端 zone 后缀由请求 Host 首段推导（`ownHost` 去首段），用于 §7.2「连回自身」判定。
- §7.4 fetch 槽位：fetch 事务占用与 connect 流同一占用池（上限 6）；fetch body 上限 4 MiB，超限 RESET `response_too_large`(0x09)。
- §6.5 窗口信用（connect 门）：服务端仅在出站 `writer.write` 完成（resolve）后补充窗口信用，避免把「已排队未落 socket」的字节误报为已消费——早期版本曾因此误判超窗，已修并有本地回归。
- 服务端出站泵送用单一有序字节队列（`outBuf`）：字节严格按 socket 读序成帧。早期版本「余量暂存 + 继续读」会造成字节重排，已修并有回归测试（`closeWrite does not overtake queued DATA` 配套的 300 KiB 乱序检出用例）。

## 5. 线上验收形态登记（与本地机制验收的关系）

- **F-5（fetch 门）**：本地 harness 已验证全机制（connect 抛 spec 专属错误原文 → fetch 兜底 → 合成 HTTP 响应回送；gate_policy=1 时拒为 0x04）。线上对 13 个 CF 相关靶实测，connect() 在边缘直接终结 TCP 全部成功，专属错误原文不出现、fetch 兜底在线上无从触发。登记为：**机制验证通过；线上形态为 connect 直达**，F-5 记部分完成。
- **F-6（背压）**：本地慢消费滴灌（256 KiB）与 1 MiB 快速消费均字节全等、零窗口违规。线上经 tcpbin.com 回显时尾部丢 1–4 KiB——已用**无任何 Hollow 代码的裸 connect() 对照**证明为靶侧行为：裸连接同样丢尾（tcpbin 连接约 15 秒被关、关前缓冲尾字节不达）。Hollow 层口径为「对端实际返回的字节 100% 送达应用、零丢失零重排」，线上实测 consumed == received 精确成立。此项记部分完成（线上整程受第三方回显服务行为所限）。

## 6. SOCKS5 读取器（已修缺陷）

初版用 `sock.unshift()` 回退多读字节，在 flowing 模式下会静默丢字节，表现为问候+请求同包到达时挂死。已改为单连接缓冲读取器（`makeReader`）：全部头部读取走同一缓冲，请求后剩余字节作 pipelined payload 直交流层；回归测试覆盖「问候+请求+首字节同包」场景。

## 7. 验收与证据

- 本地：`npm test`（16 项，含 spec 常量、帧分流、记录往返、内存传输 E2E、禁区全矩阵、队列、fetch 机制、超窗、CLOSE 顺序、SOCKS 回归）。
- 线上：`tests/acceptance/online.mjs`（F-1/F-2 子集/F-3/F-4 子集/F-6/F-8）、`tests/acceptance/demo-capture.mjs`（端到端演示+抓帧：握手后报文长度只在 {528, 4112, 16400}、明文令牌零出现）、`tests/acceptance/cpu-gates.mjs`（CPU 门，Tail 逐调用 cpuTime）。
- CPU 门方法：Tail API（脚本 `hollow`）逐调用事件；G1=仅握手会话、G2=每会话恰好一帧 16,373 B DATA 双向（整调用 cpuTime < 10 ms 蕴含记录处理 < 10 ms）、G4=错 PSK 未认证握手。Tail 消费端需经出口代理 CONNECT 且带 `Sec-WebSocket-Protocol: trace-v1`，否则 406。
- F-9（1 小时混合负载 soak）：`tests/acceptance/soak.mjs`，逐动作 JSONL 账本与 GraphQL 用量对账闭合。
