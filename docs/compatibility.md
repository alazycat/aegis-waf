# ModSecurity 子集兼容报告（v0.1）

- 更新：2026-10-23
- 参考：OWASP ModSecurity Reference Manual、OWASP CRS v4.31.0-dev

## 结论

aegis-waf v0.1 不声称完整兼容 OWASP CRS。引擎实现了下表列出的语法与语义子集，
并通过 `crates/aegis-engine/tests/` 与 `crates/aegis-proxy/tests/` 下的一致性测试验证。

在真实 CRS 规则上，`lenient: true` 模式可以编译 **541 / 693（78.1%）** 的
`SecRule`/`SecAction` 指令；这不代表完整语义兼容，剩余规则主要依赖 multipart/FILES、
`@pmFromFile`、持久化集合、Phase 5 等尚未实现的能力。详见
`docs/benchmarks.md` 第 13 节。

## 已支持

| 类别 | 内容 |
|---|---|
| 阶段 | Phase 1（请求头）、Phase 2（请求体）、Phase 3（响应头）、Phase 4（响应体） |
| 指令 | `SecRule`（2 或 3 参数）、`SecAction`、`SecDefaultAction`、`SecMarker`、`Include` |
| 请求变量 | `REQUEST_URI`、`REQUEST_URI_RAW`、`REQUEST_LINE`、`REQUEST_PROTOCOL`、`REQUEST_BASENAME`、`REQUEST_METHOD`、`QUERY_STRING`、`REQUEST_FILENAME`、`REQUEST_HEADERS[:name]`、`REQUEST_HEADERS_NAMES`、`ARGS[:name]`、`ARGS_GET[:name]`、`ARGS_POST[:name]`、`ARGS_NAMES`、`REQUEST_COOKIES[:name]`、`REQUEST_COOKIES_NAMES`、`REQUEST_BODY`、`REQUEST_BODY_LENGTH`、`REMOTE_ADDR`、`TX[:name]` |
| 匹配/XML 变量 | `MATCHED_VAR`、`MATCHED_VAR_NAME`、`XML` / `XML:/*` |
| 响应变量 | `RESPONSE_STATUS`、`RESPONSE_HEADERS[:name]`、`RESPONSE_HEADERS_NAMES`、`RESPONSE_BODY`、`RESPONSE_BODY_LENGTH`、`RESPONSE_CONTENT_TYPE` |
| 算子 | `@rx`、`@eq`、`@streq`、`@contains`、`@beginsWith`、`@endsWith`、`@pm`、`@ipMatch`、`@within`、`@gt`、`@ge`、`@lt`、`@le`、`@detectSQLi`、`@detectXSS`、`@unconditionalMatch`、`@validateByteRange`，支持 `!` 取反 |
| 变换 | `lowercase`、`urlDecode`、`urlDecodeUni`、`htmlEntityDecode`、`trim`、`trimLeft`、`trimRight`、`compressWhitespace`、`removeNulls`、`normalizePath`、`base64Decode` |
| 动作 | `id`、`phase`、`deny`、`block`、`pass`、`allow`、`status`、`log`/`nolog`、`msg`、`severity`、`tag`、`rev`、`ver`、`logdata`、`t`、`chain`、`setvar`、`capture`、`ctl` 子集 |
| TX/宏 | `tx.` 集合、`setvar` 赋值/增减/删除、`TX:0..9`、`%{tx.name}`、`%{MATCHED_VAR}`、`%{MATCHED_VAR_NAME}` |

### `ctl` 子集

- `ctl:auditEngine=Off|On|RelevantOnly`
- `ctl:ruleEngine=Off|On|DetectionOnly`（DetectionOnly 当前不拦截）
- `ctl:ruleRemoveById=<id>`
- `ctl:ruleRemoveByTag=<tag>`

其他 `ctl`（`requestBodyProcessor`、`forceRequestBodyVariable`、`ruleRemoveTargetByTag` 等）
在宽松模式下会被忽略。

## 语义说明

- `block` 使用 `SecDefaultAction` 中的默认破坏性动作；没有默认动作时回退为 `deny 403`。
  `SecDefaultAction` 中不允许使用 `block`。
- `SecDefaultAction` 作用于同文件中后续的 `SecRule` 与 `SecAction`；显式 `pass` 可阻止继承默认 `deny`。
- 链式规则：
  - 链首可以声明 `block` 等破坏性动作，但只在整条链匹配后执行；
  - 链中间规则禁止破坏性动作；链尾可以声明破坏性动作；
  - 链节可以省略 `id` 与 `phase`，继承链首；
  - 非破坏性动作在单条命中时执行，链失败不回滚（与 ModSecurity `setvar` 文档一致）；
  - 宽松模式下链中规则被跳过时，整条不完整链会被丢弃。
- `capture` 把正则捕获组写入 `TX:0..9`，并设置 `MATCHED_VAR` / `MATCHED_VAR_NAME`。
- `@detectSQLi` / `@detectXSS` 使用纯 Rust 的 `barbacane-libinjection`
  （crate 名 `libinjectionrs`，对 C 版做过差分测试）。
- 响应阶段：
  - Phase 3 在收到上游响应头后执行；
  - Phase 4 仅在 `Content-Length` 存在且不超过 `max_response_body_bytes` 时执行；
  - chunked 或超大响应只做 Phase 3 并透传响应体。
- `XML` 变量使用 `roxmltree` 提取所有元素文本和属性值；复杂 XPath 选择器未实现，
  `XML:selector` 当前按全量匹配处理。
- 变量取反当前按“值”排除，而不是按集合项排除。
- `@pm` 大小写敏感；需要时配合 `t:lowercase`。
- 数值算子只接受十进制整数。
- 正则使用 Rust `regex`：不支持 lookaround、backreference 等 PCRE 特性。
- `(?i)` 等无安全 AC 字面量的 regex 使用预编译 RegexSet 预筛；同一变换变体内模式数
  ≥ 8 时启用，小集合逐条求值（性能取舍）。

## 已验证的 CRS 风格规则

- 异常评分初始化与累加（`SecAction` + `setvar` + `TX` 比较）
- 扫描器 User-Agent 检测（`@pm`）
- 请求方法限制（`!@pm`）
- SQLi/XSS 正则检测（`@rx` + `t:urlDecodeUni` + `t:lowercase`）
- libinjection SQLi/XSS 检测
- capture + `MATCHED_VAR` + `TX:1` 链式判定
- 路径遍历检测（`REQUEST_URI` + `@contains`）
- 响应状态/响应体拦截（Phase 3/4）
- `ctl` 规则移除与审计关闭

这些模式在 `rules/examples/base.conf`、`crates/aegis-engine/src/eval.rs` 的测试和
`crates/aegis-proxy/tests/proxy_response_integration.rs` 中有可执行示例。

## 已知不兼容

- 完整 OWASP CRS：未实现全部变量、算子、动作和语义
- `FILES` / `FILES_NAMES` / `FILES_SIZES`、multipart 表单解析
- `@pmFromFile`
- `MATCHED_VARS`（复数集合）
- `initcol`、`setuid`、持久化集合（`ip.`/`session.`/`user.`）
- Phase 5（日志阶段）
- 大部分 `ctl`：`requestBodyProcessor`、`forceRequestBodyVariable`、
  `ruleRemoveTargetById/Tag` 等
- `skipAfter`、`multiMatch`、`capture` 之外的捕获相关高级语义
- Lua、GeoIP
- 变量计数（`&ARGS`）、集合排除正则
- 完整 XPath/XML 选择器
- lookaround、backreference 等 PCRE 特性
- chunked/超大响应体的 Phase 4 检测
- 响应压缩内容的解压后检测
- PHP/Python 等语言特定规则中依赖上述能力的部分

## 验证方式

```bash
cargo test -p aegis-engine
cargo test -p aegis-proxy
cargo run -p aegis-proxy -- --config config.example.yaml --check
```

CRS 子集覆盖率：

```bash
bash scripts/bench_crs.sh
```

结果与分析见 `docs/benchmarks.md` 第 13 节。
