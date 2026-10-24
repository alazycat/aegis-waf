# aegis-waf go-ftw 回归与响应检测加固设计

- 日期：2026-10-24
- 状态：已评审
- 范围：迭代 1（go-ftw 回归接入、chunked/压缩响应检测、解析器结构上限）
- 前置：`2026-10-23-aegis-waf-design.md`、`2026-10-24-aegis-waf-crs-compatibility-design.md`

## 1. 目标

在 CRS 规则 100% 可编译的基础上，解决三个影响可信度的问题：

1. 用 OWASP CRS 官方 go-ftw 回归套件验证真实拦截语义，而不只是编译覆盖。
2. 消除响应体检测的已知绕过：chunked 响应、压缩响应、超过检测上限的响应。
3. 给请求解析器加结构上限，防止参数、multipart part、XML 节点数量导致的解析型 DoS。

完成后应能持续运行回归套件、产出分类报告，并对核心规则目录形成可执行的门禁。

## 2. go-ftw 回归接入

### 2.1 验收方式

- 全量运行 `target/crs/coreruleset/tests/regression/tests` 下全部 326 个 YAML 文件，生成 JSON 报告。
- **门禁目录**（必须 100% 通过，已知差异清单除外）：
  `REQUEST-911`、`REQUEST-913`、`REQUEST-920`、`REQUEST-921`、`REQUEST-930`、
  `REQUEST-931`、`REQUEST-932`、`REQUEST-933`、`REQUEST-941`、`REQUEST-942`、
  `REQUEST-943`、`REQUEST-949`。
- **仅报告目录**：`REQUEST-901`、`REQUEST-922`、`REQUEST-934`、`REQUEST-944` 与全部
  `RESPONSE-*`。
- 门禁目录内失败但确认超出本次范围的用例，登记在
  `scripts/ftw-known-gaps.txt`，每行格式为 `<ruleId-testId> <原因>`，
  `#` 开头为注释。清单为空或滞后于现状时，门禁脚本输出提示。

### 2.2 组件

| 组件 | 职责 |
|---|---|
| `crates/aegis-proxy/examples/ftw_backend.rs` | 测试专用上游：`/reflect` 回显、`/status/{code}`、其余路径 200 |
| `scripts/ftw.sh` | 准备 CRS 与 go-ftw、生成配置、启动后端与代理、运行 ftw、清理进程 |
| `crates/aegis-proxy/examples/ftw_gate.rs` | 解析 ftw JSON 报告与已知差异清单，计算门禁结果 |
| `scripts/ftw-known-gaps.txt` | 已知差异清单（初始为空，首次基线后填写） |

### 2.3 测试后端

`ftw_backend` 监听 `127.0.0.1:${FTW_BACKEND_PORT:-18081}`，行为：

- `POST /reflect`：解析 JSON body：
  - `status`（整数）→ 响应状态码，默认 200
  - `body`（字符串）→ 响应体
  - `headers`（对象）→ 附加响应头
- `ANY /status/{code}`：返回该状态码
- 其他路径：200，空响应体
- JSON 解析失败：400

该后端不参与生产构建，仅作为 example 编译。

### 2.4 运行流程

`scripts/ftw.sh [--full|--gate]`，默认 `--gate`；两种模式都运行全量测试，
区别只在是否执行门禁判定与退出码：

1. CRS 目录复用 `target/crs/coreruleset`；不存在时 `git clone --depth 1`；记录实际 commit。
2. 解析 go-ftw 可执行文件：优先 `FTW_BIN`；否则在 `$(go env GOPATH)/bin` 下查找
   `ftw`（Unix）或 `go-ftw.exe`（Windows）；不存在时执行
   `go install github.com/coreruleset/go-ftw/v2@v2.6.1`。
3. 在 `target/ftw/` 生成：
   - `crs-test-setup.conf`：`crs-setup.conf.example` 之后、CRS 规则之前的测试 setup，
     包含 `id:900005` 的 DetectionOnly/PL4/阈值配置与 marker 规则
   - `aegis-ftw.yaml`：监听 `127.0.0.1:${FTW_PROXY_PORT:-18080}`，上游为
     `ftw_backend`；审计 JSONL `mode: all`、`matched_rules_limit: 256`
   - `.ftw.yaml`：`logfile` 指向审计文件，`logmarkerheadername: X-CRS-Test`，
     `testoverride.input.dest_addr=127.0.0.1`、`port=${FTW_PROXY_PORT:-18080}`
4. 启动 `ftw_backend` 与 `aegis-proxy`，轮询 `/healthz` 等待就绪。
5. 运行：
   `go-ftw run --config target/ftw/.ftw.yaml -d <CRS>/tests/regression/tests -o json -f target/ftw/report.json`
6. `trap` 清理两个子进程。
7. 退出码：`--gate` 由门禁检查器决定；`--full` 只产出报告，ftw 自身运行失败时仍返回非零。

### 2.5 marker 机制

go-ftw 通过前后两个 marker 行截取日志区间；marker 是请求头
`X-CRS-Test: <stage-id>`，日志行中必须同时包含头名与 stage-id。

测试 setup 中加入：

```apache
SecRule REQUEST_HEADERS:X-CRS-Test "@rx ^.*$" \
    "id:999999,phase:1,pass,log,msg:'X-CRS-Test %{MATCHED_VAR}',ctl:ruleRemoveById=1-999999"
```

- 规则位于 CRS 规则之前、`id:900005` 之后。
- `msg` 宏展开已存在，marker 值进入审计 JSON 的 `matched_rules[].msg`。
- `ctl:ruleRemoveById=1-999999` 屏蔽后续规则，保证 marker 请求不产生额外命中。
  为此 `ctl:ruleRemoveById` 扩展为接受单个 id 或 `id-id` 范围。
- 审计 JSON 无需改造：go-ftw 的 JSON 日志解析识别 `"id":<number>`，
  我们的 `matched_rules[].id` 已满足。

### 2.6 门禁检查

`ftw_gate` 读取 ftw JSON 报告（字段：`run`、`success`、`failed`、`skipped`）与已知差异清单：

- 门禁目录的判定依据是测试 ID（`ruleId-testId`）中 rule id 的百位前缀
  （例如 `920`、`921`）；
- 门禁目录内、未出现在 `failed` 中的用例通过；
- `failed` 且不在清单中 → 退出码 1；
- 清单中但已通过的用例 → 输出 `stale known gap` 警告，不影响退出码；
- 报告缺失或无法解析 → 退出码 1；
- 输出汇总：passed / failed / known-gap / skipped / stale-gap。

## 3. 响应体检测

### 3.1 检测条件

仅当 `phase4` 规则非空时执行响应体检测。`Content-Type` 以
`text/event-stream` 开头时直接透传，不缓冲、不检测。

### 3.2 流程

1. `Content-Length` 已知且大于 `max_response_body_bytes`：
   - `reject` → 502 `upstream body too large`
   - `pass` → 不读取，直接透传
2. 否则带超时读取响应体，上限 `max_response_body_bytes`：
   - **读取成功**：
     - 无 `Content-Encoding`：用原始字节检测
     - `gzip` / `x-gzip` / `deflate` / `br`：按声明顺序逆序解码，
       解码上限同为 `max_response_body_bytes`；用解码结果检测，转发原始字节
     - 解码失败或未知编码：`tracing::warn!` 后按原始字节检测，转发原始字节
   - **解码后超限**：`reject` → 502；`pass` → 转发已缓冲的原始字节
   - **原始读取超限**：
     - `reject` → 502
     - `pass` → 已读前缀 + 剩余 `Incoming` 流式转发，跳过 Phase 4
3. Phase 5 的执行时机保持不变。

### 3.3 转发与变量

- 检测通过的响应以完整缓冲发送（可能由 chunked 变为 `Content-Length`）。
- `pass` 且原始读取超限时，使用 `PrefixBody` 保持流式转发。
- `PrefixBody` 使用 `http_body_util::StreamBody` 拼接前缀与剩余帧，
  需要把 `futures-util` 提升为 workspace 直接依赖。
- 解码依赖 `flate2`（gzip/deflate）与 `brotli`。
- `RESPONSE_BODY` 与 `RESPONSE_BODY_LENGTH` 在解码成功时反映解码后内容；
  转发内容始终是原始编码字节。

### 3.4 配置

```yaml
limits:
  response_body_limit_action: reject   # reject | pass
```

默认 `reject`。该值同时约束原始与解码后大小。

## 4. 解析器结构上限

### 4.1 引擎接口

```rust
pub struct ParseLimits {
    pub max_args: usize,
    pub max_multipart_parts: usize,
    pub max_multipart_part_headers: usize,
    pub max_xml_depth: usize,
    pub max_xml_values: usize,
}

pub enum BodyParseError {
    TooManyArgs,
    TooManyMultipartParts,
    TooManyMultipartHeaders,
    XmlTooDeep,
    TooManyXmlValues,
}
```

- `EvaluationState` 增加 `set_parse_limits(ParseLimits)`；默认值由 `Default` 提供。
- `set_body(&mut self, body: &[u8]) -> Result<(), BodyParseError>`；
  失败时保留原始请求体供审计。
- 解析器行为：
  - URL-encoded：`take(max_args + 1)`，超限报 `TooManyArgs`
  - Multipart：part 数超过 `max_multipart_parts`、单个 part 头行数超过
    `max_multipart_part_headers`、非文件字段数超过 `max_args` 分别报错
  - XML：元素深度超过 `max_xml_depth`、提取值数量超过 `max_xml_values` 分别报错；
    roxmltree 保持默认不解析 DTD
  - JSON / None：不解析，不报错
- Query string 不新增上限，继续由 `max_uri_bytes` 约束。

### 4.2 配置默认值

```yaml
limits:
  max_args: 10000
  max_multipart_parts: 1000
  max_multipart_part_headers: 64
  max_xml_depth: 64
  max_xml_values: 10000
```

全部必须大于零。默认值高于 CRS 的 `tx.max_num_args=255`，不改变规则语义。

### 4.3 代理处理

- `set_body` 返回 `BodyParseError` → 413 `request body structure too large`，
  不调用上游。
- 审计 `error` 字段为 `body_parse_limit: <kind>`。
- Phase 1 已产生的命中规则照常记录。

## 5. 错误处理汇总

| 场景 | 行为 | 审计/日志 |
|---|---|---|
| 响应体原始或解码后超限，`reject` | 502 `upstream body too large` | `error: upstream_body_too_large` |
| 响应体超限，`pass` | 流式透传，不检测 | 正常审计 |
| 响应解码失败或未知编码 | 原样透传 | `tracing::warn!` |
| `text/event-stream` | 不缓冲、不检测 | 正常审计 |
| 请求体结构超限 | 413 `request body structure too large` | `error: body_parse_limit: <kind>` |
| 其他解析异常 | 保持现状：解析为空或跳过 | 无 |

## 6. 测试

### 6.1 单元与集成

- 引擎：五类结构上限的边界测试（等于上限通过、上限 + 1 报错）；
  JSON/None 不受影响；`ruleRemoveById` 单 id 与范围。
- 代理响应：
  - chunked 无 `Content-Length` 的响应体可被 Phase 4 命中
  - gzip / deflate / br 按解码文本命中
  - gzip 解码后超限的 `reject` 与 `pass`
  - 无 CL 原始 body 超限的 `reject` 与 `pass`（`pass` 字节与上游一致）
  - CL 已知且超限的 `reject` 与 `pass`
  - 损坏 gzip、未知编码、`text/event-stream` 原样透传
  - 未超限压缩响应转发字节与上游一致
- 代理请求：URL-encoded 参数超限、multipart part 超限返回 413，
  上游命中数为 0，审计错误标记正确。

### 6.2 回归与门禁

- `bash scripts/ftw.sh --full`：全量报告。
- `bash scripts/ftw.sh --gate`：门禁检查。
- `cargo test --workspace`
- `cargo fmt --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo run -p aegis-proxy -- --config config.example.yaml --check`

## 7. 文档

- `README.md`：能力与限制更新，链接 ftw 文档。
- `docs/compatibility.md`：响应检测、结构上限、go-ftw 验证结论。
- `docs/ftw.md`：运行方式、门禁目录、已知差异维护流程。
- `config.example.yaml`：新增配置项。

## 8. 不在本次范围

- 请求体压缩解码、zstd
- SSE 内容检测
- 部分响应检测（process partial）
- 解压后转发
- go-ftw cloud mode
- CI 工作流
- 门禁目录之外的语义修复
- query string 参数上限

## 9. 风险

| 风险 | 应对 |
|---|---|
| 首次基线暴露大量核心语义缺陷 | 先分类为引擎缺陷 / 近似实现 / 测试环境；只修引擎缺陷，超出范围的条目带原因进清单并在报告统计 |
| 外部依赖不可达 | go-ftw 已通过 Go module proxy 安装；CRS 已存在于 `target/crs`；脚本记录 commit |
| 端口冲突 | `FTW_PROXY_PORT`、`FTW_BACKEND_PORT` 可覆盖 |
| chunked 响应缓冲改变分帧 | 仅在 `phase4` 非空时缓冲，文档注明 |
| Windows 进程清理 | trap 统一清理；按平台解析 ftw 可执行文件名 |
