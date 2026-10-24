# aegis-waf CRS 兼容性扩展设计

- 日期：2026-10-24
- 状态：已评审
- 范围：补齐 OWASP CRS 剩余可编译能力与关键运行时语义
- 前置：`2026-10-23-aegis-waf-design.md`、`2026-10-23-aegis-waf-v0.1.md`

## 1. 目标

在 v0.1 引擎基础上：

1. 消除当前导致 CRS `SecRule`/`SecAction` 在 `lenient: true` 下被跳过的能力缺口。
2. 修正会影响检测结果的语义偏差，而不只是“让规则编译通过”。
3. 修复 `@validateByteRange` 现有实现的反向语义。

完成后，CRS 规则应接近 100% 可编译；剩余跳过项必须来自明确不支持且已记录的特性。

## 2. 现存问题

对 CRS commit `58ff33b` 的 693 条 `SecRule`/`SecAction`：

- 599 条可编译（86.4%），102 条跳过。
- 跳过原因：变量计数、`MULTIPART_PART_HEADERS`、`REQBODY_PROCESSOR`、`UNIQUE_ID`、
  `@validateUtf8Encoding`、`@validateUrlEncoding`。

此外存在不阻塞编译但影响检测正确性的问题：

- 正则选择器（如 `REQUEST_COOKIES:/^_ga/`）被当作字面量键，永不匹配。
- 变量取反按“值”排除，而 ModSecurity 按“变量项名称”排除。
- `MATCHED_VARS` 返回变量名，而 ModSecurity 返回命中值集合。
- `multiMatch` 被忽略，异常评分只累计一次。
- 请求体总是按 urlencoded 解析，JSON/XML body 也会产生 `ARGS_POST`。
- `@validateByteRange` 语义反转：当前“全部字节合法则匹配”，而 ModSecurity
  `validate*` 算子在“校验失败”时匹配。若直接加载 CRS，920270 会拦截正常请求。

## 3. 数据模型

### 3.1 Selector

```rust
pub enum Selector {
    Literal(String),
    Regex(RegexSelector),
}

pub struct RegexSelector {
    pattern: String,
    regex: regex::Regex,
}
```

- `RegexSelector` 的 `PartialEq`/`Eq`/`Hash` 只基于 `pattern`，避免在变量缓存键中比较编译产物。
- `Selector::matches(&self, key: &str) -> bool`：
  - `Literal`：大小写不敏感相等（沿用现有行为）。
  - `Regex`：`regex.is_match(key)`，区分大小写；模式内可用 `(?i)`。
- 选择器正则以 `/.../` 形式出现在规则中，在规则编译期编译并校验；非法正则产生带
  `file:line:column` 的加载错误，`lenient` 下跳过该规则。

### 3.2 Variable

所有集合变量的选择器改为 `Option<Selector>`：

`REQUEST_HEADERS`、`ARGS`、`ARGS_GET`、`ARGS_POST`、`ARGS_NAMES`、`REQUEST_COOKIES`、
`IP`、`SESSION`、`USER`、`GLOBAL`、`XML`、`TX`、`RESPONSE_HEADERS`、
`MATCHED_VARS`。

新增：

```rust
Variable::Count(Box<Variable>),                 // &VAR
Variable::MultipartPartHeaders(Option<Selector>),
Variable::ReqbodyProcessor,                     // REQBODY_PROCESSOR
Variable::UniqueId,                             // UNIQUE_ID
Variable::ArgsGetNames,                         // ARGS_GET_NAMES
Variable::ArgsCombinedSize,                     // ARGS_COMBINED_SIZE
```

`Count` 只允许出现一次（拒绝 `&&` 或嵌套 `&`）。

### 3.3 VariableEntry

```rust
pub struct VariableEntry {
    pub name: String,        // MATCHED_VAR_NAME，如 "ARGS:foo"
    pub key: Option<String>, // 选择器匹配目标，如 "foo"；标量为 None
    pub value: String,
}
```

`RequestContext::extract(&Variable) -> Arc<Vec<VariableEntry>>`，缓存类型同步改为
`HashMap<Variable, Arc<Vec<VariableEntry>>>`。

名称约定：

| 变量 | name | key |
|---|---|---|
| `ARGS` | `ARGS:foo` | `foo` |
| `ARGS_GET` / `ARGS_POST` | `ARGS_GET:foo` / `ARGS_POST:foo` | `foo` |
| `ARGS_NAMES` | `ARGS_NAMES:foo` | `foo`，value 也是 `foo` |
| `REQUEST_HEADERS` | `REQUEST_HEADERS:user-agent` | 小写头名 |
| `REQUEST_COOKIES` | `REQUEST_COOKIES:session` | cookie 名 |
| `TX` / `IP` / `SESSION` / `USER` / `GLOBAL` | `TX:score` 等 | 集合键 |
| `FILES` / `FILES_NAMES` / `FILES_SIZES` | `FILES:upload` 等 | 表单字段名 |
| `MULTIPART_PART_HEADERS` | `MULTIPART_PART_HEADERS:upload` | part 字段名 |
| 标量变量 | `display_name()` | `None` |

## 4. 变量抽取

### 4.1 集合与选择器

- 正选 spec 在选择器匹配时只保留匹配项；无选择器返回全部项。
- 字面量选择器的匹配仍不区分大小写；正则选择器按模式执行。
- `TX(None)` 返回全部 TX 值；`TX(Some(Selector))` 按键过滤。
- `IP/SESSION/USER/GLOBAL` 无 `initcol` 键时返回空。
- `Count(inner)`：调用 `inner` 抽取并返回单条 `VariableEntry`，name 为 `&INNER`，
  value 为条目数。示例：`&TX:foo` 为 0/1，`&ARGS` 为参数个数。

### 4.2 MATCHED_VARS

- `RequestContext` 维护 `matched_entries: Vec<VariableEntry>`，事务内累积。
- 每次规则命中（含 `multiMatch` 的每次命中）追加对应 entry。
- `MATCHED_VARS(None)` 返回所有已命中值；`MATCHED_VARS(Some(selector))`
  按完整 `name` 过滤。
- `MATCHED_VAR` / `MATCHED_VAR_NAME` 保持“最近一次命中”。
- `MATCHED_VARS` 不参与缓存。

### 4.3 缓存

- 静态集合（URI、headers、args、cookies、files、multipart 头等）可缓存。
- `TX`、持久化集合、`MATCHED_VAR*`、`MATCHED_VARS` 不缓存。
- `set_body`、`set_collection_key`、collection 写入、响应设置继续清空缓存。

## 5. 匹配与动作

### 5.1 取反

`VariableSpec.negated` 的新语义：按变量项排除。

- 对每个正选 entry，若存在负选 spec：
  - 变量族相同（枚举变体一致，`Count` 先解包）；
  - 负选无选择器，或选择器匹配 entry 的 `key`；
  则该 entry 被跳过。
- 负选 spec 本身不产生命中。
- 例：`ARGS|!ARGS:foo` 评估除 `foo` 外的所有参数；
  `REQUEST_HEADERS|!REQUEST_HEADERS:Cookie` 排除 Cookie 头。

### 5.2 规则命中

`rule_hits(&self, rule) -> Vec<RuleHit>`：

- 普通规则：返回第一个命中即停止。
- `multiMatch`：收集所有正选 entry 的命中。
- `RuleHit { value, variable_name, key, captures }`，`variable_name` 取 entry.name。

### 5.3 multiMatch

- 每个命中依次：
  1. 记录 `MATCHED_VAR` / `MATCHED_VAR_NAME` / `MATCHED_VARS`；
  2. 写入 `capture` 的 `TX:0..9`；
  3. 执行非破坏性动作（`setvar` 按命中次数累计）。
- 每条规则只记录一条 `RuleMatch`（首个命中），避免审计重复膨胀。
- 破坏性动作在全部命中处理后执行一次。
- 链节使用 `multiMatch` 时，只要至少一个命中就继续链；该链节的非破坏性动作按命中次数执行。

### 5.4 ctl 扩展

- `ctl:requestBodyProcessor=URLENCODED|MULTIPART|XML|JSON`
  设置请求体处理器覆盖，影响随后 `set_body` 的解析。
- `ctl:forceRequestBodyVariable=On|Off` 接受为 no-op：本引擎始终提供 `REQUEST_BODY`。
- `ctl:ruleRemoveTargetById=<id>;<VAR>[:selector]`
  `ctl:ruleRemoveTargetByTag=<tag>;<VAR>[:selector]`
  在事务内记录排除目标；后续 id/tag 匹配的规则在匹配时跳过该变量的对应项。
- 未知 ctl 继续按现状处理：`lenient` 忽略，严格模式报错。

## 6. 请求体与 multipart

### 6.1 BodyProcessor

```rust
pub enum BodyProcessor { UrlEncoded, Multipart, Json, Xml, None }
```

- 由 `Content-Type` 推导：`application/x-www-form-urlencoded`、`multipart/form-data`、
  `application/json` 或 `+json`、`application/xml`/`text/xml` 或 `+xml`。
- 无 `Content-Type` 时默认 `UrlEncoded`（务实默认，保持现有调用方行为）。
- `ctl:requestBodyProcessor` 优先于 `Content-Type`。
- `REQBODY_PROCESSOR` 返回处理器名称；未识别时为 `None`（空值）。

### 6.2 解析规则

- `UrlEncoded`：`form_urlencoded` 解析 body → `ARGS_POST`。
- `Multipart`：解析 part；
  - 文件 part → `FILES*`；
  - 非文件 part → `ARGS_POST`（与 ModSecurity 一致）；
  - 每个 part 的原始头行 → `MULTIPART_PART_HEADERS`，键为 part 字段名。
- `Json` / `Xml` / `None`：不产生 `ARGS_POST`；`REQUEST_BODY` 仍保存原文。
- `REQUEST_BODY` 与 `REQUEST_BODY_LENGTH` 对所有处理器可用。

### 6.3 Multipart 头

- `MultipartPart.headers: Vec<String>` 保存原始头行（不含空行）。
- `MULTIPART_PART_HEADERS` 无选择器：所有 part 的所有头行。
- 带选择器：匹配 part 字段名的头行。
- `&MULTIPART_PART_HEADERS[:selector]` 返回头行条数。

## 7. 新变量与算子

### 7.1 UNIQUE_ID

- `RequestView` 新增 `unique_id: &'a str`。
- 代理使用现有每请求 `request_id`（UUID v4）。
- 引擎测试传固定字符串。
- `UNIQUE_ID` 返回该字符串。

### 7.2 校验算子

ModSecurity 的 `validate*` 算子在**校验失败**时匹配。统一按此语义实现：

- `@validateByteRange RANGES`：任一字节不在范围内 → 匹配。修正现有反向实现。
- `@validateUtf8Encoding`：输入含 U+FFFD 替换字符 → 匹配。
  - 说明：引擎内部字符串使用 lossy 转换，非法 UTF-8 会变成 U+FFFD；这是近似检测。
- `@validateUrlEncoding`：存在 `%` 未跟随两位十六进制（含结尾不完整）→ 匹配。
- `@gt/@ge/@lt/@le` 的参数支持 `%{...}` 宏：编译期保留模板，求值时用 TX 与请求上下文展开后再解析为整数。
  CRS 的异常评分拦截规则依赖这一能力。

## 8. 代理接入

- `handle` 把 `request_id` 写入 `RequestView.unique_id`。
- Phase 1 中 `ctl:requestBodyProcessor` 先于 Phase 2 的 `set_body` 生效。
- `AppState.collections` 继续跨请求共享。
- 审计与响应路径不变。

## 9. 错误处理

- 非法选择器正则：严格模式加载失败，`lenient` 跳过规则并记录警告。
- 非法 `ruleRemoveTarget` 语法或目标变量：严格模式报错，`lenient` 忽略 ctl。
- `&` 嵌套、`&` 与 `!` 组合：视为语法错误（严格模式报错，`lenient` 跳过规则）。
- 未知请求体处理器值：`lenient` 忽略，严格模式报错。
- 现有 fail-closed 与热重载失败保留旧规则的行为不变。

## 10. 测试

单元/一致性测试：

- 正则选择器命中与排除：`REQUEST_COOKIES:/^_ga/`、`!REQUEST_HEADERS:Cookie`。
- `&` 计数：`&TX:foo`、`&ARGS`、`&MULTIPART_PART_HEADERS:_charset_`。
- `MATCHED_VARS` 返回命中值，选择器按名称过滤。
- multipart：文件/非文件 part、`ARGS_POST`、`MULTIPART_PART_HEADERS` 头行。
- `REQBODY_PROCESSOR`：urlencoded、multipart、json、xml、ctl 覆盖。
- `UNIQUE_ID` 可见。
- 三个 validate 算子（含 `@validateByteRange` 反向修复）。
- `multiMatch` 对 `setvar` 的累计次数与单条审计记录。
- `ruleRemoveTargetById/Tag` 排除指定变量。

集成验证：

- 代理请求中 `UNIQUE_ID` 与集合跨请求行为。
- 全量 `cargo test --workspace`、`cargo fmt --check`、
  `cargo clippy --workspace --all-targets -- -D warnings`。
- `bash scripts/bench_crs.sh` 重新统计覆盖率，并更新
  `docs/benchmarks.md`、`docs/compatibility.md`、`README.md`。

## 11. 不在本次范围

- 持久化集合 TTL/淘汰、Redis 后端。
- 完整 XPath/XML 选择器；`XML` 仍沿用当前“返回全部 XML 值、选择器不过滤”的行为。
- chunked/超大响应体 Phase 4 检测。
- 响应压缩内容解压后检测。
- Lua、GeoIP、WASM 插件。
- PCRE lookaround/backreference。
- `MultiMatch` 每次命中都写审计记录（本设计刻意简化为每条规则一条）。
