# aegis-waf

Rust 编写的反向代理 Web 应用防火墙（WAF）v0.1。

## 能力

- HTTP/1.1 反向代理
- ModSecurity `SecRule` 核心子集
- Phase 1-5：请求头/URI/参数/Cookie、请求体、响应头、响应体、日志阶段
- 扩展变量：`REQUEST_LINE`、`REQUEST_BASENAME`、`REQUEST_COOKIES_NAMES`、`XML:/*`、
  `MATCHED_VAR`、`MATCHED_VARS`、`FILES`、`MULTIPART_PART_HEADERS`、
  `REQBODY_PROCESSOR`、`UNIQUE_ID`、`ARGS_COMBINED_SIZE`、
  `IP`/`SESSION`/`USER`/`GLOBAL`、`RESPONSE_STATUS`、`RESPONSE_BODY`、`ARGS:name` 等
- 变量选择器（字面量或 `/regex/`）、按项取反、`&VAR` 计数
- `deny`/`block`/`allow`/`pass`、`status`、`msg`、`severity`、`tag`、`logdata`
- 变换、正则/字符串/IP/数值算子、`chain`、`capture`、`multiMatch`、`skipAfter`、`ctl` 子集
- `@pmFromFile`（大小写不敏感）、libinjection：`@detectSQLi`、`@detectXSS`（纯 Rust 移植）
- 校验算子：`@validateByteRange`、`@validateUtf8Encoding`、`@validateUrlEncoding`
- 数值算子宏参数（`@ge %{tx.threshold}`），可表达 CRS 的异常评分拦截
- 请求体处理器感知：URLENCODED/MULTIPART/JSON/XML，multipart 字段进入 `ARGS_POST`
- 响应体检测覆盖 chunked、gzip/deflate/br 压缩内容与超限拒绝策略
- 请求解析结构上限（参数、multipart part/头、XML 深度/值数量）
- go-ftw 回归套件门禁（核心规则目录）
- TX 变量、`setvar`、持久化集合（内存）、`MATCHED_VAR` 与宏展开，可表达 CRS 风格异常评分
- 规则热重载（管理 API 与 Unix `SIGHUP`）
- 变量提取缓存与 Aho-Corasick/RegexSet 预筛（含 regex 字面量与变换感知）
- JSON Lines 审计，有界队列，丢弃计数
- 管理 API：`/healthz` `/readyz` `/status` `/rules` `/rules/reload`

## 构建与测试

```bash
cargo build --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

性能基准：

```bash
cargo bench -p aegis-engine --bench engine
bash scripts/bench_e2e.sh
```

结果与分析见 [docs/benchmarks.md](docs/benchmarks.md)。

## 运行

```bash
cargo run -p aegis-proxy -- --config config.example.yaml
```

验证配置与规则但不启动服务：

```bash
cargo run -p aegis-proxy -- --config config.example.yaml --check
```

示例配置监听 `0.0.0.0:8080`，管理面监听 `127.0.0.1:9001`，上游为
`http://127.0.0.1:3000`。规则位于 `rules/examples/`。

## 配置

完整字段见 `config.example.yaml`。关键项：

- `rules.files`：按配置顺序加载；单个 glob 内部按字典序；重复文件只保留第一次出现。
- `rules.lenient`：宽松模式下跳过未知指令/动作/变换和 Phase 5 规则。
- `limits`：URI/头部/请求体/响应体大小与读取超时；响应体检测仅在
  `Content-Length` 存在且不超过 `max_response_body_bytes` 时执行。
- `on_error`：`block` 或 `pass`。当前引擎求值没有可恢复错误路径，该配置为后续扩展预留。
- `audit.sink`：`file`、`stdout`、`none`；`audit.mode`：`blocked_only` 或 `all`。
- 管理面绑定非回环地址时必须配置 `admin.token`。

## 管理 API

```bash
curl http://127.0.0.1:9001/status
curl http://127.0.0.1:9001/rules
curl -X POST http://127.0.0.1:9001/rules/reload
```

配置 token 后：

```bash
curl -H "Authorization: Bearer secret" http://127.0.0.1:9001/status
```

## 规则示例

```apache
SecRule ARGS "@rx (?i)(union\s+select|<script)" \
    "id:942100,phase:2,deny,status:403,msg:'attack pattern',t:urlDecodeUni,t:lowercase"
```

`SecDefaultAction` 会作用于后续规则和 `SecAction`。`block` 表示“使用默认破坏性动作”；
未定义默认动作时回退为 `deny 403`。

## 审计与 AI 接缝

审计事件为 JSON Lines，字段包含请求元数据、决策、命中规则、上游状态和延迟。
未来 `aegis-ai` 可作为独立进程消费该事件流，做 LLM 研判、告警降噪和报告生成；
AI 不进入请求路径，不影响转发延迟。

## 已知限制

- `text/event-stream` 响应不缓冲、不检测
- 请求体压缩内容不解码；未知响应编码按原始字节检测
- 响应体超过上限时默认返回 502，可用 `limits.response_body_limit_action: pass` 放行
- 不终止 TLS，不支持 HTTP/2
- CRS 规则全部可编译，但部分语义仍是近似实现，详见 `docs/compatibility.md`
- `ctl` 支持 audit/rule engine、规则移除、body processor 与 target 移除；其他 ctl 忽略
- 持久化集合仅内存实现，无 TTL/Redis 后端
- XML 变量提取所有元素文本/属性；复杂 XML 选择器未实现
- `@validateUtf8Encoding` 通过 U+FFFD 近似检测非法 UTF-8
- `multiMatch` 每条规则只记录一条审计
- 响应压缩内容不解压后检测
- go-ftw 门禁目录存在 44 条已知差异（hyper 请求解析、非 UTF-8 字节、PCRE/transform 边界）
- 头部大小限制在 hyper 解析后近似统计
- `on_error` 为未来引擎内部错误预留；当前引擎求值无可恢复错误路径

## 文档

- [设计文档](docs/superpowers/specs/2026-10-23-aegis-waf-design.md)
- [实现计划](docs/superpowers/plans/2026-10-23-aegis-waf-v0.1.md)
- [CRS 兼容性扩展设计](docs/superpowers/specs/2026-10-24-aegis-waf-crs-compatibility-design.md)
- [CRS 兼容性扩展计划](docs/superpowers/plans/2026-10-24-aegis-waf-crs-compatibility.md)
- [兼容性报告](docs/compatibility.md)
- [go-ftw 回归测试](docs/ftw.md)
- [性能基准](docs/benchmarks.md)

## 许可证

Apache License 2.0
