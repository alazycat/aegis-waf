# aegis-waf v0.1 设计文档

- 日期：2026-10-23
- 状态：已确认
- 项目目录：`D:\rust_code\aegis-waf`

## 1. 背景与目标

用 Rust 开发一款可独立部署的 Web 应用防火墙（WAF），以反向代理形态接入 HTTP 流量，兼容 ModSecurity `SecRule` 规则语法的核心子集，并逐步向 OWASP Core Rule Set（CRS）靠拢。后续版本在不影响转发链路的前提下引入 AI 异步研判与告警能力。

v0.1 的首要目标是**正确性和可测试性**，而不是极限吞吐。性能优化点在设计上预留，但不作为验收项。

## 2. 范围

### 2.1 v0.1 目标

1. 反向代理：HTTP/1.1，请求转发、超时、请求大小限制、基础转发头处理。
2. 规则引擎：解析并执行 ModSecurity 指令子集，覆盖 Phase 1（请求头/URI/参数/Cookie）与 Phase 2（请求体），支持 `chain`、`setvar`、`TX` 变量和宏展开。
3. 决策闭环：放行 / 拦截 / 显式允许，拦截返回可配置状态码。
4. 规则热重载：管理 API 与 Unix `SIGHUP` 触发，原子替换，失败保留旧规则。
5. 管理 API：健康检查、就绪检查、运行状态、规则元数据、规则重载。
6. 审计：结构化 JSON Lines 事件，有界队列，队列满时丢弃并计数，不阻塞请求。
7. AI 接缝：版本化审计事件结构 + 独立 sink；后续 `aegis-ai` 作为独立进程消费事件，不进入请求路径。

### 2.2 v0.1 非目标

- 响应体检测（Phase 3/4）
- TLS 终止、HTTP/2、HTTP/3
- 完整 OWASP CRS 兼容
- `@detectSQLi` / `@detectXSS`（libinjection）、Lua、`ctl`、`skipAfter`、持久化集合（`initcol` / `setuid`）、`capture`
- WASM 插件、集群、管理 UI、GeoIP、IP 信誉、速率限制
- HTTPS 上游
- AI 在线判定

## 3. 总体架构

```
                    ┌──────────────── aegis-proxy 进程 ───────────────┐
Client ──HTTP/1.1──▶│ hyper Server                                   │
                    │   ↓                                            │
                    │ 请求预处理（大小/超时/头数量限制）              │
                    │   ↓                                            │
                    │ aegis-engine.evaluate(Phase 1, Phase 2)        │──放行──▶ hyper Client ──▶ Backend
                    │   ↓ 决策 Block/Pass/Allow                       │
                    │ 审计事件 ──▶ 有界 channel ──▶ JSONL sink         │
                    │                                                │
                    │ 管理监听器（默认 127.0.0.1:9001）                │
                    │   /healthz /readyz /status /rules /rules/reload │
                    │        │                                       │
                    │        └─ 规则加载器原子替换 ArcSwap<CompiledRules>│
                    └────────────────────────────────────────────────┘
                                     ▲
                          后续：aegis-ai 进程消费审计事件流
```

### 3.1 Crate 划分

**`aegis-engine`（纯库，无 IO、无异步）**

- 职责：规则解析、校验与编译；请求变量提取；算子/变换匹配；动作执行；决策生成；审计事件类型定义。
- 不依赖：`tokio`、`hyper`。
- 测试：完全可在内存中构造请求并断言结果。

**`aegis-proxy`（二进制）**

- 职责：HTTP 服务与上游转发、请求限制、规则加载与热重载、管理 API、审计 sink、信号与优雅退出。
- 依赖 `aegis-engine`。

后续新增 **`aegis-ai`（独立 crate/二进制）**，只依赖审计事件 schema，不依赖 proxy。

### 3.2 并发模型

- `tokio` 多线程运行时。
- `CompiledRules` 不可变，存放于 `ArcSwap<CompiledRules>`。每个请求开始时取一份 `Arc` 快照，整个请求生命周期内使用同一版本；重载只影响后续请求。
- 引擎求值在异步任务内同步执行；v0.1 规则规模下开销可控，不引入 `spawn_blocking`。
- 同一时刻只允许一个重载任务，重载流程由 `tokio::sync::Mutex` 串行化。

## 4. 请求生命周期

1. 接受连接，读取请求头（受 `header_read_timeout_ms`、`max_header_bytes` 约束）。
2. 生成 `request_id`（UUID v4）。
3. 检查 URI 长度（`max_uri_bytes`）。
4. 执行 Phase 1：对方法、URI、查询串、请求头、Cookie、来源地址求值。
5. 若 Phase 1 已产生 `Block` 决策，跳过请求体读取，直接返回；若产生 `Allow` 决策，跳过 Phase 2 检测，请求体以流式转发（仍受 `max_body_bytes` 约束）。
6. 读取请求体，最多 `max_body_bytes`：
   - `Content-Length` 超限：不读取正文，返回 413。
   - `Transfer-Encoding: chunked`：边读边累计，超限即停止并返回 413。
7. 执行 Phase 2：对 `REQUEST_BODY`、`ARGS_POST` 求值。
8. 决策：
   - `Block`：返回规则指定状态码（默认 403），不访问上游。
   - `Pass` / `Allow`：转发到上游。
9. 上游响应以流式方式回传给客户端（v0.1 不检测响应体）。
10. 按审计配置写入事件。
11. 请求结束，释放规则快照。

## 5. 规则引擎

### 5.1 处理流水线

```
.conf 文件 → 词法/语法解析 → AST → 校验 → 编译（预编译正则、按 phase 分组）
           → CompiledRules（不可变）→ 按请求逐 phase 求值 → Evaluation
```

解析器为手写、面向行的解析器，不引入解析器组合子库。这样可以精确报告文件名、行号和列号，并支持 ModSecurity 的引号、转义、注释与续行规则。

### 5.2 支持的指令

| 指令 | 语义 |
|---|---|
| `SecRule` | 定义规则：变量列表、算子、动作列表 |
| `SecAction` | 无变量/算子的无条件动作规则 |
| `SecDefaultAction` | 为后续规则提供默认动作，按 ModSecurity 合并语义实现子集 |
| `SecMarker` | 解析并记录，v0.1 不实现 `skipAfter`，因此仅作占位 |
| `Include` | 引入其他规则文件，支持 glob、相对路径、嵌套；最大深度 8，检测循环引用 |

注释以 `#` 开始；支持反斜杠续行；支持单引号、双引号与反斜杠转义；引号内的逗号不作为动作分隔符。

`SecDefaultAction` 的作用域为当前文件中该指令之后的所有规则；可继承的类别为 `phase`、`deny`/`pass`/`allow`、`status`、`log`/`nolog` 与 `t`。规则显式声明的同类动作覆盖默认值；默认的 `t:` 变换排在规则自身变换之前；不支持跨文件继承。

### 5.3 规则模型

```rust
pub struct Rule {
    pub id: u32,
    pub phase: Phase,                 // Phase1 | Phase2
    pub variables: Vec<VariableSpec>, // 含取反项
    pub operator: OperatorSpec,       // 支持取反
    pub actions: RuleActions,
    pub transformations: Vec<Transform>,
    pub chain: ChainPosition,         // Standalone | Start | Middle | End
    pub metadata: RuleMetadata,       // msg/severity/tag/rev/ver/log
}

pub struct CompiledRules {
    pub version: u64,
    pub rule_count: usize,
    pub files: Vec<PathBuf>,
    // 内部：按 phase 分组、保持文件顺序、预编译正则
}
```

编译期校验：

- `id` 必填，重复 `id` 报错。
- `phase` 只接受 1 和 2；缺省为 2。
- 每个规则必须能完整解析变量、算子、动作与变换。
- 未知动作/算子/变换/指令在严格模式（默认）下报错；宽松模式下记录警告并忽略该未知项。
- `phase` 为 3/4/5 的规则在严格模式下报错；宽松模式下跳过该规则并记录警告。
- 正则采用 Rust `regex` 库；依赖 PCRE 回溯特性（lookaround、backreference 等）的表达式会编译失败并给出明确错误。

### 5.4 求值语义

- 同一 phase 内按规则在文件中的出现顺序执行（`Include` 展开后的顺序）。
- 一条规则：
  1. 提取变量列表中的全部值；取反变量表示排除对应值/集合项。
  2. 对每个值按声明顺序执行 `t:` 变换。
  3. 对每个变换后的值执行算子匹配；任一值命中即视为该规则命中。算子取反时，对每个值取反后再按“任一命中”聚合。
  4. 规则命中后执行动作。
- `chain`：
  - `chain` 动作把下一条规则串联进来，链上所有规则都命中才视为整体命中。
  - 链中间规则的元数据动作（`setvar`、`msg` 等）在各自匹配时执行；破坏性动作只在链尾执行。
  - 链中间规则声明破坏性动作视为编译错误。
- 破坏性动作优先级：`deny`/`block` 立即产生 `Block` 决策并结束当前 phase 及后续 phase；`allow` 立即产生 `Allow` 决策，跳过后续所有 phase 的规则处理并直接放行；`pass` 不改变决策，继续执行后续规则。Phase 1 中产生 `Allow` 时，请求体不做检测、以流式转发，但仍受 `max_body_bytes` 约束。
- 无任何规则命中时默认为 `Pass`。

### 5.5 变量

| 变量 | 取值 |
|---|---|
| `REQUEST_URI` | 原始请求目标中的路径 + 查询串 |
| `REQUEST_METHOD` | HTTP 方法 |
| `QUERY_STRING` | 原始查询串 |
| `REQUEST_FILENAME` | 请求路径（不含查询串） |
| `REQUEST_HEADERS` | 所有请求头的值 |
| `REQUEST_HEADERS:name` | 指定请求头的所有值（大小写不敏感） |
| `ARGS` | 查询参数 + `application/x-www-form-urlencoded` 请求体参数 |
| `ARGS_GET` | 查询参数 |
| `ARGS_POST` | `application/x-www-form-urlencoded` 请求体参数 |
| `ARGS_NAMES` | `ARGS` 的参数名 |
| `REQUEST_COOKIES` | 所有 Cookie 值 |
| `REQUEST_COOKIES:name` | 指定 Cookie 的值 |
| `REQUEST_BODY` | 请求体内容，按 UTF-8 有损转换 |
| `REMOTE_ADDR` | TCP 对端地址；不信任 `X-Forwarded-For` |
| `TX` / `TX:name` | 当前请求的事务变量存储，名称大小写不敏感 |

变量列表支持取反（`!ARGS:password`）。v0.1 不支持变量计数（`&ARGS`）和集合排除正则。

参数解析规则：

- 查询串与 urlencoded 请求体使用标准表单解析（`+` 转为空格，百分号解码）。
- Cookie 按 `;` 分隔、首个 `=` 拆分键值，不做引号处理。
- `multipart/form-data` 不解析：`ARGS_POST` 为空，规则只能通过 `REQUEST_BODY` 检测原始内容。
- 请求体超过上限时按第 4 节处理，不进入引擎。

### 5.6 算子

| 算子 | 语义 |
|---|---|
| `@rx` | 正则匹配；未写算子名时代默认算子 |
| `@eq` | 字符串完全相等 |
| `@contains` | 包含子串 |
| `@beginsWith` | 前缀匹配 |
| `@endsWith` | 后缀匹配 |
| `@pm` | 空格分隔的短语列表，任一命中 |
| `@ipMatch` | 逗号分隔的 IP 或 CIDR 列表，输入必须是合法 IP |
| `@within` | 输入字符串包含在算子参数中 |
| `@gt` / `@ge` / `@lt` / `@le` | 按十进制有符号整数比较 |

所有算子支持前缀 `!` 取反（如 `!@rx ^GET$`）。

### 5.7 变换

按声明顺序执行，输出使用 `Cow<str>` 以避免不必要分配。

| 变换 | 语义 |
|---|---|
| `lowercase` | ASCII 小写 |
| `urlDecode` | 百分号解码，`+` 转为空格 |
| `urlDecodeUni` | 在 `urlDecode` 基础上解码 `%uXXXX` |
| `htmlEntityDecode` | 解码命名与数字 HTML 实体 |
| `trim` / `trimLeft` / `trimRight` | 去除 ASCII 空白 |
| `compressWhitespace` | 连续空白折叠为单个空格 |
| `removeNulls` | 删除 NUL 字节 |
| `normalizePath` | 反斜杠转斜杠、折叠重复斜杠、解析 `.` 与 `..`（不越过根路径） |
| `base64Decode` | 标准 Base64 解码；非法输入保持原值 |

### 5.8 动作

| 动作 | 语义 |
|---|---|
| `id:n` | 规则 ID，必填且唯一 |
| `phase:n` | 1 或 2，缺省 2 |
| `deny` / `block` | 产生 Block 决策；`block` 作为 `deny` 的同义词 |
| `pass` | 非破坏性，继续处理 |
| `allow` | 产生 Allow 决策并结束规则处理 |
| `status:n` | Block 时返回的状态码，默认 403 |
| `log` / `nolog` | 控制该规则是否触发审计事件（见 7.5） |
| `msg:'...'` | 命中消息，支持 `%{...}` 宏展开 |
| `logdata:'...'` | 命中时附加数据，支持 `%{...}` 宏展开，写入审计事件 `rule_data` |
| `severity:'...'` | 严重级别字符串，支持 ModSecurity 标准级别名，也接受 0–7 数字 |
| `tag:'...'` | 标签，可重复 |
| `rev:'...'` / `ver:'...'` | 规则版本文本 |
| `t:name` | 变换，可重复 |
| `chain` | 串联下一条规则 |
| `setvar:tx.name=value` | 设置 TX 变量，支持见 5.9 |

未知动作在严格模式报错；宽松模式警告并忽略。

### 5.9 TX、setvar 与宏展开

- TX 存储按请求创建，跨 phase 保留，规则名大小写不敏感。
- `setvar` 支持：
  - 字面量赋值：`setvar:tx.foo=bar`
  - 数值增量：`setvar:tx.score=+5`、`setvar:tx.score=-3`
  - 宏展开值：`setvar:tx.score=+%{tx.critical_anomaly_score}`
  - 删除变量：`setvar:!tx.foo`
- 仅支持 `tx.` 集合；其他集合（`ip.`、`session.` 等）在严格模式报错，宽松模式忽略。
- 宏语法 `%{tx.name}`，在 `msg`、`logdata` 与 `setvar` 值中展开；未知变量展开为空串。
- 数值增量作用于非数值或缺失变量时，从 0 开始。
- 异常评分不做引擎内置逻辑：由规则通过 `setvar` 累加 `TX` 分数，再由规则比较 `TX` 阈值实现，从而保持与 CRS 一致的表达方式。

### 5.10 错误与失败策略

- 启动时规则编译失败：进程以非零状态退出，并打印文件、行号、原因。
- 热重载失败：保留旧规则，管理 API 返回 400 与错误详情。
- 请求期引擎内部错误（不应发生，如不可达的状态）：
  - `on_error: block`（默认）：返回 500，审计标记 `error`。
  - `on_error: pass`：放行到上游，审计标记 `error`。
- 规则命中产生的 Block 返回 403（或 `status` 指定值），与内部错误区分。

## 6. 反向代理

### 6.1 转发

- `hyper` 1.x server 与 client，仅 HTTP/1.1。
- 上游 URL 仅支持 `http://`；连接池由 `hyper-util` 管理。
- 请求转发：
  - 移除 hop-by-hop 头：`Connection`、`Keep-Alive`、`Proxy-Authenticate`、`Proxy-Authorization`、`TE`、`Trailers`、`Transfer-Encoding`、`Upgrade`。
  - 追加 `X-Forwarded-For`（保留已有链并追加客户端 IP）、设置 `X-Forwarded-Proto: http`、设置 `X-Forwarded-Host` 为原始 Host。
  - `Host` 头策略由 `upstream.host_header` 控制：`preserve`（默认，保留原始 Host）或 `rewrite`（改为上游 authority）。
- 响应转发：保留状态码、响应头（同样过滤 hop-by-hop 头）与响应体流。

### 6.2 限制与超时

| 配置 | 默认 | 行为 |
|---|---|---|
| `max_header_bytes` | 65536 | 超出返回 431 |
| `max_uri_bytes` | 8192 | 超出返回 414 |
| `max_body_bytes` | 1048576 | 超出返回 413 |
| `header_read_timeout_ms` | 10000 | 超出返回 408 |
| `body_read_timeout_ms` | 15000 | 超出返回 408 |
| `upstream.connect_timeout_ms` | 3000 | 失败返回 502 |
| `upstream.total_timeout_ms` | 30000 | 失败返回 504 |

### 6.3 错误映射

| 场景 | 返回 |
|---|---|
| 规则拦截 | 规则 `status`，默认 403 |
| 请求体/头/URI 超限 | 413 / 431 / 414 |
| 读取超时 | 408 |
| 上游连接失败或无效响应 | 502 |
| 上游超时 | 504 |
| 引擎内部错误且 `on_error: block` | 500 |
| 引擎内部错误且 `on_error: pass` | 正常转发 |

### 6.4 生命周期

- 收到 `SIGINT` / `SIGTERM` 后停止接受新连接，等待进行中的请求完成，最多 10 秒，然后退出。
- `SIGHUP`（Unix）触发规则重载，语义与管理 API 相同。

## 7. 管理 API、热重载与审计

### 7.1 管理 API

独立监听器，默认 `127.0.0.1:9001`。若绑定非回环地址且未配置 token，进程拒绝启动。

| 端点 | 方法 | 响应 |
|---|---|---|
| `/healthz` | GET | `200 {"status":"ok"}` |
| `/readyz` | GET | 规则已加载时 200，否则 503 |
| `/status` | GET | 版本、运行时长、规则版本/数量/文件、审计丢弃计数、上游状态 |
| `/rules` | GET | 规则版本、数量、文件列表、加载时间 |
| `/rules/reload` | POST | 成功 200 与新版本信息；失败 400 与错误详情 |

认证：配置了 `admin.token` 时要求 `Authorization: Bearer <token>`；未配置时仅允许回环地址。

`/status` 示例：

```json
{
  "version": "0.1.0",
  "uptime_seconds": 123,
  "rules": {
    "version": 4,
    "count": 87,
    "files": ["rules/base.conf"],
    "loaded_at": "2026-10-23T12:00:00Z"
  },
  "audit": { "dropped": 0 },
  "ready": true
}
```

### 7.2 热重载

1. 读取配置中 `rules.files` 列出的文件（glob 展开，按字典序）。
2. 解析并编译全部文件；任一错误则整体失败。
3. 成功后替换 `ArcSwap<CompiledRules>`，规则版本号加 1，记录加载时间。
4. 进行中的请求继续使用旧快照；新请求使用新快照。
5. 失败时保留旧规则并在响应中返回文件、行号与错误信息。

### 7.3 审计事件

事件为 JSON Lines，每行一个 JSON 对象，`event_version` 用于演进；`ts` 为 RFC3339 UTC 时间。

```json
{
  "event_version": 1,
  "ts": "2026-10-23T12:00:00.123Z",
  "request_id": "0b6f7d2e-6f0a-4e2a-9c1a-2f4b6d8e0a11",
  "client_ip": "203.0.113.10",
  "method": "GET",
  "path": "/login",
  "query": null,
  "decision": "block",
  "status": 403,
  "rule_id": 942100,
  "rule_msg": "SQL Injection Attack Detected",
  "rule_data": "Matched Data: ' UNION SELECT found within ARGS:id",
  "severity": "CRITICAL",
  "tags": ["attack-sqli"],
  "matched_rules": [
    { "id": 942100, "msg": "SQL Injection Attack Detected", "severity": "CRITICAL", "tags": ["attack-sqli"] }
  ],
  "error": null,
  "upstream": { "status": null, "latency_ms": null },
  "latency_ms": 2,
  "request_bytes": 128,
  "rules_version": 4
}
```

- `query` 默认不记录；`audit.include_query: true` 时记录原始查询串。
- 不记录请求头与请求体原文。
- `rule_data` 为最终产生破坏性动作的规则中 `logdata` 的展开结果；没有则为 `null`。
- `matched_rules` 最多记录 `audit.matched_rules_limit`（默认 16）条。
- `request_bytes` 表示从客户端读取的字节数（请求头 + 已缓冲的请求体）。
- `decision` 取值 `pass` / `block` / `allow` / `error`。

### 7.4 审计 sink

- `sink: file`：追加写入 JSON Lines；每行 flush；启动时创建父目录；不实现轮转。
- `sink: stdout`：输出到标准输出。
- `sink: none`：关闭审计。
- 事件通过有界 `tokio::mpsc` 发送，容量 `audit.queue_capacity`（默认 8192）；使用 `try_send`，队列满时丢弃并递增原子计数，计数通过 `/status` 暴露。
- 写文件失败时记录 `tracing::error!` 并继续运行，不阻塞或终止请求处理。

### 7.5 审计模式

- `blocked_only`（默认）：为 Block/Allow 决策写事件；此外，任何带 `log` 动作的规则命中也会写事件。
- `all`：每个请求写一条事件。

### 7.6 AI 接缝

- 审计事件 schema 是 AI 分析的稳定输入契约，放在 `aegis-engine::audit`，由 serde 序列化。
- 未来的 `aegis-ai` 作为独立进程读取 JSONL（或后续事件总线），进行 LLM 研判、告警降噪和报告生成。
- AI 不进入请求路径，不参与拦截决策，因此不引入请求延迟和可用性风险。
- 事件中不包含请求体原文，AI 如需更多上下文，由后续版本通过显式的采样/脱敏配置扩展。

## 8. 配置

```yaml
listen: "0.0.0.0:8080"

upstream:
  url: "http://127.0.0.1:3000"
  host_header: preserve        # preserve | rewrite
  connect_timeout_ms: 3000
  total_timeout_ms: 30000

admin:
  listen: "127.0.0.1:9001"
  token: null

rules:
  files: ["rules/*.conf"]
  lenient: false

limits:
  max_header_bytes: 65536
  max_uri_bytes: 8192
  max_body_bytes: 1048576
  header_read_timeout_ms: 10000
  body_read_timeout_ms: 15000

on_error: block                # block | pass

audit:
  sink: file                   # file | stdout | none
  path: "logs/audit.jsonl"
  mode: blocked_only           # blocked_only | all
  queue_capacity: 8192
  include_query: false
  matched_rules_limit: 16
```

- YAML 使用 `serde_yaml` 解析，`deny_unknown_fields` 拒绝未知字段。
- 启动时校验：监听地址可解析、上游 URL 合法且为 `http`、管理面暴露非回环时必须配置 token、规则文件至少存在一个。
- CLI：`aegis-proxy --config <path>`；`aegis-proxy --config <path> --check` 仅校验配置与规则并退出。
- 不做环境变量覆盖。

## 9. 工程结构

```
aegis-waf/
├── Cargo.toml                       # workspace
├── .gitignore
├── README.md                        # M3 完成
├── crates/
│   ├── aegis-engine/
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── error.rs
│   │   │   ├── parser/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── scanner.rs
│   │   │   │   └── directive.rs
│   │   │   ├── model.rs
│   │   │   ├── compile.rs
│   │   │   ├── variables/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── request.rs
│   │   │   │   └── tx.rs
│   │   │   ├── operators.rs
│   │   │   ├── transforms.rs
│   │   │   ├── eval.rs
│   │   │   └── audit.rs
│   │   └── tests/
│   └── aegis-proxy/
│       ├── Cargo.toml
│       ├── src/
│       │   ├── main.rs
│       │   ├── config.rs
│       │   ├── rules.rs
│       │   ├── admin.rs
│       │   ├── audit_sink.rs
│       │   └── proxy/
│       │       ├── mod.rs
│       │       ├── forward.rs
│       │       └── limits.rs
│       └── tests/
├── rules/
│   ├── examples/*.conf
│   └── conformance/*.conf
└── docs/
```

### 9.1 引擎公共接口

```rust
pub fn load_rules(files: &[PathBuf], options: &LoadOptions) -> Result<CompiledRules, LoadError>;

pub struct RequestView<'a> {
    pub method: &'a str,
    pub uri: &'a str,          // path + query
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub headers: &'a http::HeaderMap,
    pub body: &'a [u8],
    pub remote_addr: IpAddr,
}

pub fn evaluate(rules: &CompiledRules, request: &RequestView<'_>) -> Evaluation;

pub struct Evaluation {
    pub decision: Decision,        // Pass | Block { status, rule_id, msg } | Allow { rule_id }
    pub matched: Vec<RuleMatch>,
    pub error: Option<EngineError>,
    pub latency: Duration,
}
```

- `aegis-engine` 公开依赖 `http::HeaderMap`（`http` crate），不依赖 `hyper`。
- `#![forbid(unsafe_code)]` 同时应用于两个 crate。

### 9.2 主要依赖

| crate | 依赖 |
|---|---|
| `aegis-engine` | `serde`、`serde_json`、`thiserror`、`regex`、`ipnet`、`percent-encoding`、`form_urlencoded`、`html-escape`、`base64`、`http` |
| `aegis-proxy` | `tokio`、`hyper`、`hyper-util`、`http-body-util`、`bytes`、`http`、`serde`、`serde_yaml`、`thiserror`、`anyhow`、`arc-swap`、`glob`、`uuid`、`tracing`、`tracing-subscriber`、`futures-util`、`aegis-engine` |

`uuid` 仅用于请求 ID。所有依赖选择稳定版，Rust edition 2021。

## 10. 测试策略

### 10.1 引擎单元测试

- 解析器：每种指令、引号/转义/续行/注释的黄金测试；错误用例断言文件名与行号。
- 变量提取：查询串、urlencoded 表单、Cookie、重复头、大小写不敏感头名、`ARGS` 合并。
- 算子：每个算子的正例、反例、取反、空值、非法 IP。
- 变换：URL 编码/Unicode、HTML 实体、路径归一化、空白处理、Base64 非法输入。
- `chain`、`setvar`、`TX`、宏展开、异常评分累加的表驱动测试。

### 10.2 一致性测试

- `rules/conformance/` 下每个 `.conf` 配套 Rust 表驱动用例：构造请求、期望决策、期望命中规则 ID。
- 覆盖每条支持的动作、算子、变换以及组合场景（chain + setvar + 宏）。

### 10.3 代理集成测试

- 在随机端口启动 mock 上游与 aegis-proxy，使用真实 TCP 请求断言：
  - 放行请求被正确转发，转发头正确。
  - 命中规则返回配置状态码，上游未收到请求。
  - 请求体/头/URI 超限与超时映射。
  - 热重载成功替换；失败保留旧版本。
  - 审计文件写入内容与 `blocked_only` / `all` 模式。
  - 管理 API 认证与状态字段。

### 10.4 属性测试与模糊测试

- `proptest`：URL 解码/编码往返、`normalizePath` 幂等性、规则文本解析不 panic。
- `cargo-fuzz` 解析器目标作为 M3 可选任务；不作为 v0.1 验收阻塞项。

### 10.5 质量门禁

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test --all`
- 两个 crate 均启用 `#![forbid(unsafe_code)]`

## 11. 里程碑与验收标准

### M0：工程骨架与透传代理

- workspace、两个 crate、配置加载与校验。
- hyper 反向代理可透传 GET/POST 到 mock 上游。
- 管理面 `/healthz`、`/readyz`、`/status` 可用。
- 集成测试：透传成功、配置非法时启动失败。

### M1：引擎核心

- 解析器、规则模型、编译与校验、全部支持变量/算子/变换/动作。
- `chain`、`setvar`、`TX`、宏展开、异常评分累加。
- 解析器黄金测试与一致性测试全部通过。

### M2：拦截闭环与热重载

- Phase 1/2 接入代理，Block/Allow/Pass 生效。
- 请求体限制、超时与错误映射。
- 审计 JSONL、有界队列、丢弃计数。
- 管理 API 重载与 `SIGHUP`；失败保留旧规则。
- 代理集成测试全部通过。

### M3：文档与兼容性验证

- 示例规则、README、配置说明。
- CRS 子集兼容报告：列出已测试规则、通过项与失败原因（明确不声称完整兼容）。
- `proptest`；fuzz 目标可选。
- `cargo clippy` 零警告，全部测试通过。

### 后续候选（不承诺版本号）

- Phase 3/4 响应检测
- TLS 终止与 HTTP/2
- Prometheus 指标
- `@detectSQLi` / `@detectXSS`、`capture`、`ctl`、更长 CRS 覆盖
- `aegis-ai` 异步研判进程

## 12. 风险与缓解

| 风险 | 缓解 |
|---|---|
| ModSecurity 语义细节多，易产生“看起来兼容”的偏差 | 明确子集边界；一致性测试以行为为准；不宣称完整 CRS 兼容 |
| CRS 大量依赖 PCRE 特性，Rust `regex` 不支持 | 编译期明确报错；兼容报告列出不支持规则；后续评估 PCRE2/libinjection 绑定 |
| 请求体缓冲导致内存压力 | 硬上限 + 超限提前返回；chunked 边读边计数 |
| URL/Unicode 解码差异导致漏报或误报 | 针对已知绕过手法编写边界测试；兼容报告记录已知差异 |
| 热重载与在途请求状态不一致 | 每请求固定规则快照；重载串行化；版本号可观测 |
| 管理面暴露风险 | 默认回环绑定；非回环必须配置 token；数据面/管理面端口分离 |
| 审计写入影响请求 | 有界队列 + `try_send`；丢弃计数；写失败不阻断请求 |
| 上游响应或客户端慢连接占用资源 | 读取超时、上游总超时、优雅退出上限 |

## 13. 术语

- **SecRule**：ModSecurity 规则语法。
- **Phase**：规则执行阶段；v0.1 仅 Phase 1（请求头等）与 Phase 2（请求体）。
- **Operator**：变量值的匹配方式，如 `@rx`。
- **Transformation**：匹配前对值做的转换，如 `urlDecode`。
- **TX**：请求级事务变量存储，供规则写入和读取。
- **Anomaly Score**：CRS 风格的风险累计分数，由规则通过 `setvar` 计算。
- **Disruptive Action**：会改变请求命运的规则动作，如 `deny`、`block`、`allow`。
- **Fail-closed**：内部错误时选择拦截而非放行。
- **CRS**：OWASP Core Rule Set。
