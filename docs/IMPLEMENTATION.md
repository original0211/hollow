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

**NP-1117-04 补记（AEAD 运行时回退）**：Electron 34 的 BoringSSL 版 node:crypto 不提供 chacha20-poly1305（`ERR_CRYPTO_UNKNOWN_CIPHER`），Windows 应用曾因此不可能握手成功且被误报为记录损坏。现 `shared/crypto.js` 在加载时探测原生算法：缺失时回退到 vendored 的纯 JS 实现（@noble/ciphers 2.4.0 的 chacha20poly1305，`shared/vendor/`，LICENSE 与 SHA-256 钉记在册），有原生时仍走原生、不得误走 JS；协议字节零变化（RFC 8439 A.5 黄金向量＋双后端逐字节一致，`tests/aead.test.mjs`）。错误分类：能力缺失抛具名 `AeadUnavailableError`（客户端文案明示运行时缺 AEAD），认证失败维持返回 null 的 fail-closed 语义。CI 的 windows-build 增设 Electron 运行时握手冒烟（`windows/tools/electron-aead-smoke.mjs`，本地 server-core 全握手＋回显），此类运行时缺失在 CI 即红、不再带病出厂。 **NP-1117-06 续记**：同型吞错 x25519Derive 已同批修——运行时能力缺失（WebCrypto 无 X25519）抛具名 `X25519UnavailableError`、客户端文案明示运行时缺 X25519；低阶点与畸形对端公钥维持返回 null、语义未动（`tests/x25519.test.mjs`，含桩掉 WebCrypto 的能力缺失用例）。 **NP-1117-07 补记**：全局模式协议不自洽修复——`sysproxy.writtenFor` 的 ProxyServer 改为 WinINET SOCKS 形态 `socks=127.0.0.1:<port>`（裸值被 WinINET 当 HTTP 代理、与只懂 SOCKS5 的监听对不上，全局模式曾全灭；旧单测预期把裸串钉成规范值、已作废改正）；本地监听改双协议（`cli/src/socks.js` 按首字节分流：0x05→SOCKS5、'C'→HTTP CONNECT，其余销毁；两路共用同一 openStream 与泵、含 §6.3 半关纪律）；`tests/socks.test.mjs` 新增双协议活测（真实监听＋真实 Hollow 对＋本地回显靶）；main.js 的 startSocks 失败改 fail-closed（不连接、不启用系统代理、UI 进 error 态并明示原因）。 **NP-1117-07 增补（第二轮审计）**：(d2) saveSettings 保存后若已连接立即重跑代理应用分支（applyProxyMode 与连接时共用一条路径；切「关闭」当即 teardown 还原注册表；global↔pac 在持有快照下换写入形态、用户原始态不动；涉 TUN 的切换因承载锁须先于拨号、仍下次连接生效并记日志）；renderer 的模式下拉未保存值不再被 refresh 静默弹回——保留选择并显示「未保存」徽标。(d3) 桥承载连续失败 3 次且 edgeIp 非空（非 TUN 承载锁）时自动回退域名直连、记日志「edge ip unreachable, fell back to domain」、本会话不再试该 IP（`EDGE_FALLBACK_THRESHOLD`）。(d4) TUN 助手管道连不上时 UI 进 error 态明示「TUN 助手未运行，本模式尚未启用」（仅明示；helper 自动拉起另立项）。 **NP-1117-08 补记（服务端）**：§7.5 占用账落 spec v0.2.0 口径——`shared/server-core.js` 的 occupancy 只计在途建立：OPEN 受理 ++、出站建立结论（connect opened／fetch 门选中／拒绝／会话中途死亡）经唯一 `_releaseInFlight()` --，已建立流不再占槽、`_freeStream` 不再扣账；上限 6 提为具名本地参数 `maxInFlightOpens`。FIFO 队列（32/5,000 ms）与 OPEN_QUEUED 语义不变。回归：`tests/occupancy.test.mjs`（突发 24 条全开、6 条保活占死后新流仍可建、配平探针）＋ protocol 队列/楔子用例按新口径改写；旧实现上 occupancy 三格全红（突发格 5,065 ms 后 0x01 拒绝，与生产形态同签名）。 **NP-1117-10 续修（红队 NP-1117-09 必改三项）**：A——connect 成功后取 writer/OPEN_OK/起泵整段加防护，窗口内 socket 死亡抛错时清流＋关 socket＋回 OPEN_REJECT＋释放名额，不再漏扣；B——建立中途死亡检查改对象同一性（`streams.get(id) !== s`），防 id 复用时旧建立跨接；C——fetch 门按冻结字面持有占用至响应头到达或事务失败（`holdsInFlightSlot` 标志＋`_releaseFetchSlot` 唯一翻转，`_freeStream` 兜底），connect 门 opened 即释放不变、§7.4 fetchActive 并行不悖。补三格：writer 窗口异常注入、同 id 复用、慢响应头 fetch 占槽。 **NP-1117-12 横幅滞留修复**：根因——`HollowClient._die()` 只结算流的 Promise、不改 `s.state`，桥的 50 ms 状态轮询对滞留在 "queued" 的死流永不回收计数，横幅闩锁至会话结束。`core-bridge._instrument` 改事件驱动：链 `s.onQueued` 计数（重复 OPEN_QUEUED 更新只计一次）、`s.opened` 结算（resolve/reject 双路）回收、本地 `reset()` 包装同回收；renderer 显示即时、消退带约 1 s 防抖。随 v0.2.4 与 NP-1117-07 六项合并发布（0.2.3 两构建作废）。 **NP-1117-14 准入调参＋0x01 有界重试**：服务端 `server-core` 具名参数默认改为 maxInFlightOpens 16／queueDepth 64（等待上限 5,000 ms 不动；protocol.js 的 MAX_OCCUPANCY 6／QUEUE_DEPTH 32 留作 spec 期原始值——准入只在服务端执行、客户端不预判，故默认值只改服务端构造参数）；`cli/src/socks.js` 新增 `openWithRetry`：OPEN 遇 0x01 时在 SOCKS 挂起状态下以新流 id 重发（250 ms 起指数退避＋±25% 抖动、retry_after 作下限、总预算约 10 s），仅 0x01 适用、其余错误码即时失败；被拒流由 client-core 在 OPEN_REJECT 时 forget，流表无残留。startSocks 增 `openRetry` 注入（测试用小值）。回归：服务端 48 齐开格、SOCKS 重试三格（数拒后成功且只剩一条活流／持续 0x01 近上限才失败／0x05 即时不重试）。红队 NP-1117-15 轻审零必改通过；服务端已部署生产（NP-1117-14 部署轮），48 齐开生产实证 48/48 零拒、总时长 1,744 ms、首字节 p50 1,719 ms／p95 1,744 ms；客户端随 **v0.2.5** 发布。 **NP-1117-16 会话 50 条顶·方案 A（只改客户端）**：平台每会话出站建立约 50 条硬顶（真机实测第 51 条起全 0x06、会话假活）——`client-core` 计已发 OPEN 数（常量 SESSION_OPEN_HARD_CAP 50／SESSION_ROTATE_THRESHOLD 40），新增 `shared/session-manager.js` 为 CLI 与 Windows 桥共用的唯一轮换机器：15 分钟定时与 40 条预算共用 rotateNow（先建替代会话、原子换指、旧会话排空——在飞流原地走完、流表空或 10 分钟宽限到才关）；`socks.js` 的 openWithRetry 改为逐次经 getClient 取当前会话（轮换窗口新流挂起衔接）并合流 0x06 反应式兜底（会话达阈值或已标记耗尽才轮换＋每流至多重试一次，阈值下 0x06 即时失败）。桥的 _runLoop 与 CLI serve 均改为「首会话自建＋adopt 交管线」形态，桥状态机/退避/边缘回退政策不变。回归四格（150 流跨轮换全成／长流跨轮换存活＋排空自关／阈值下 0x06 即时无轮换／阈值上 0x06 轮换重试一次成功且双侧各恰一次尝试）。Worker bundle 与在产逐字一致（md5 8c56ae72…），服务端零改动。红队 NP-1117-17 轻审零必改通过，客户端随 **v0.2.6** 发布。精度口径（按代码实情）：排空宽限 10 分钟到期时直接关会话、不复查流表——届时仍存活的超长流会随会话关闭终结，此为有界兜底的本意。 **NP-1117-19 PAC／系统代理五修**（只改客户端配置层）：① 端口校验收口——`config.js` 新增 validPort／assertPort，buildPac 与 writtenFor 入口强校验（非法抛错）、loadConfig 对 socksPort／pacPort 强转回默认，堵「SOCKS5 127.0.0.1:null」类污染；② getPac 去猜测——pac.js 新增 makePacProvider（lastGood 缓存＋DIRECT_ONLY_PAC 安全回退、状态迁移才记日志），main 的 startPac 改走 provider、端口只认桥的实绑值；③ isInNet 加 IPv4 字面量守卫——PAC 内五段网段检查只对 IP 字面量执行，主机名永不触发 PAC 内 DNS 解析决定直连（直连名单纯字符串判定不动）；④ 切换顺序——sysproxy.applyProxyModeCore 固化 pac→global 先 enableGlobal 写注册表后 stopPac（global→pac 先启端点后写 URL)，main 改为委托该序；⑤ 运行期复查——createSysProxy 导出 verifyAgainst，main 在桥 connected／reconnecting 状态事件上顺带核四键，外部改动即记日志并按当前模式重申（断开／error 态不碰注册表）。回归七格落 config／edges-pac／sysproxy 三套件。

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
