# ModSecurity 子集兼容报告（v0.1）

## 结论

aegis-waf v0.1 不声称完整兼容 OWASP CRS。引擎实现了下表列出的语法与语义子集，并通过
`crates/aegis-engine/tests/` 下的一致性测试验证。完整 CRS 需要 libinjection、`ctl`、
`capture`、持久化集合等能力，属于后续版本。

## 已支持

| 类别 | 内容 |
|---|---|
| 指令 | `SecRule`、`SecAction`、`SecDefaultAction`、`SecMarker`、`Include` |
| 变量 | `REQUEST_URI`、`REQUEST_METHOD`、`QUERY_STRING`、`REQUEST_FILENAME`、`REQUEST_HEADERS[:name]`、`ARGS`、`ARGS_GET`、`ARGS_POST`、`ARGS_NAMES`、`REQUEST_COOKIES[:name]`、`REQUEST_BODY`、`REMOTE_ADDR`、`TX[:name]` |
| 算子 | `@rx`、`@eq`、`@contains`、`@beginsWith`、`@endsWith`、`@pm`、`@ipMatch`、`@within`、`@gt`、`@ge`、`@lt`、`@le`，支持 `!` 取反 |
| 变换 | `lowercase`、`urlDecode`、`urlDecodeUni`、`htmlEntityDecode`、`trim`、`trimLeft`、`trimRight`、`compressWhitespace`、`removeNulls`、`normalizePath`、`base64Decode` |
| 动作 | `id`、`phase`、`deny`、`block`、`pass`、`allow`、`status`、`log`/`nolog`、`msg`、`severity`、`tag`、`rev`、`ver`、`logdata`、`t`、`chain`、`setvar` |
| TX/宏 | `tx.` 集合、`setvar` 赋值/增减/删除、`%{tx.name}` 宏 |

## 语义说明

- `block` 使用 `SecDefaultAction` 中的默认破坏性动作；没有默认动作时回退为 `deny 403`。
  `SecDefaultAction` 中不允许使用 `block`。
- `SecDefaultAction` 作用于同文件中后续的 `SecRule` 与 `SecAction`；显式 `pass` 可阻止继承默认 `deny`。
- 链上非破坏性动作（`setvar`、元数据）在单条规则命中时执行；链后续失败不回滚。这与
  ModSecurity 的 `setvar` 文档语义一致。破坏性动作只能在链尾。
- 变量取反当前按“值”排除，而不是按集合项排除。
- `@pm` 大小写敏感；需要时配合 `t:lowercase`。
- 数值算子只接受十进制整数。

## 已验证的 CRS 风格规则

- 异常评分初始化与累加（`SecAction` + `setvar` + `TX` 比较）
- 扫描器 User-Agent 检测（`@pm`）
- 请求方法限制（`!@pm`）
- SQLi/XSS 正则检测（`@rx` + `t:urlDecodeUni` + `t:lowercase`）
- 路径遍历检测（`REQUEST_URI` + `@contains`）

这些模式在 `rules/examples/base.conf` 和 `crates/aegis-engine/tests/engine_conformance.rs`
中有可执行示例。

## 已知不兼容

- `@detectSQLi`、`@detectXSS`：未实现 libinjection
- `capture` 与 `TX:0..9`：未实现
- `ctl`、`skipAfter`、`multiMatch`：未实现
- `initcol`、`setuid`、持久化集合：未实现
- Lua、GeoIP、响应阶段（Phase 3/4/5）：未实现
- PHP/Python 等语言特定规则中依赖上述能力的部分
- 正则使用 Rust `regex`：不支持 lookaround、backreference 等 PCRE 特性
- `ARGS:name` 选择器、变量计数（`&ARGS`）、集合排除正则未实现
- 多部分表单、文件上传变量未实现

## 验证方式

```bash
cargo test -p aegis-engine
cargo test -p aegis-proxy
cargo run -p aegis-proxy -- --config config.example.yaml --check
```

CRS 子集预筛覆盖率：

```bash
bash scripts/bench_crs.sh
```

结果与分析见 `docs/benchmarks.md` 第 13 节。
