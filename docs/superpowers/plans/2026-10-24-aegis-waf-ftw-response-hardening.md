# aegis-waf go-ftw 回归与响应检测加固实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 接入 OWASP CRS 的 go-ftw 回归套件，并实现 chunked/压缩响应检测与请求解析结构上限。

**Architecture:** 引擎侧扩展 `ctl:ruleRemoveById` 范围语法与 `ParseLimits`；代理侧重写响应体检测流程（无 `Content-Length` 也检测、超限策略、压缩解码、流式续传）；测试侧新增 go-ftw 测试后端、编排脚本与门禁检查器。

**Tech Stack:** Rust 2021、tokio、hyper 1、http-body-util、futures-util、flate2、brotli、serde、go-ftw v2.6.1、OWASP CRS。

## Global Constraints

- Rust edition 2021，不使用 nightly。
- `aegis-engine` 与 `aegis-proxy` 均保持 `#![forbid(unsafe_code)]`。
- 生产代码不得使用 `unwrap()` / `expect()`；测试与 examples 也应避免 panic 路径。
- 代码注释与标识符使用英文；文档与提交信息可使用中文。
- 每个任务结束前执行 `cargo fmt`，只提交本任务相关文件，并做一个提交。
- **提交信息不得包含任何 AI 署名或 AI 生成内容（用户明确要求），例如不得出现 `Co-Authored-By: Claude`、`Generated with Claude Code` 等。**
- go-ftw 固定使用 `v2.6.1`；CRS 使用 `target/crs/coreruleset` 现有 checkout，并在脚本输出中记录 commit。
- 下载/解压数据视为不可信；本次不编写读取外部数据的 Python 脚本。
- 所有新增配置字段必须通过 `deny_unknown_fields` 的既有校验路径，数值字段必须大于零。

---

### Task 1: `ctl:ruleRemoveById` 范围语法

**Files:**
- Modify: `crates/aegis-engine/src/model.rs:355-364`
- Modify: `crates/aegis-engine/src/compile.rs:1497-1500`
- Modify: `crates/aegis-engine/src/eval.rs:53-64,136-144,396-406`
- Test: `crates/aegis-engine/tests/compile_conformance.rs`
- Test: `crates/aegis-engine/src/eval.rs` 的 `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: 无
- Produces:
  - `pub struct RuleIdRange { pub start: u32, pub end: u32 }`
  - `RuleIdRange::contains(self, id: u32) -> bool`
  - `CtlAction::RemoveRuleById(RuleIdRange)`
  - 编译期接受 `ctl:ruleRemoveById=<id>` 与 `ctl:ruleRemoveById=<start>-<end>`

- [ ] **Step 1: 写失败的编译一致性测试**

在 `crates/aegis-engine/tests/compile_conformance.rs` 顶部导入中把 `CtlAction`、`RuleIdRange` 加进去：

```rust
use aegis_engine::model::{
    CompiledOperator, CtlAction, Phase, RuleGroup, RuleIdRange, Selector, Variable,
};
```

在文件末尾追加：

```rust
#[test]
fn compiles_rule_remove_by_id_range() {
    let rules = load(
        r#"SecRule ARGS "@contains x" "id:1,phase:1,pass,ctl:ruleRemoveById=1-999999""#,
    )
    .unwrap();
    let RuleGroup::Single(rule) = &rules.phase1[0] else {
        panic!("expected single rule");
    };
    assert_eq!(
        rule.actions.ctl,
        vec![CtlAction::RemoveRuleById(RuleIdRange {
            start: 1,
            end: 999999,
        })]
    );
}

#[test]
fn compiles_rule_remove_by_id_single_value() {
    let rules =
        load(r#"SecRule ARGS "@contains x" "id:1,phase:1,pass,ctl:ruleRemoveById=3""#).unwrap();
    let RuleGroup::Single(rule) = &rules.phase1[0] else {
        panic!("expected single rule");
    };
    assert_eq!(
        rule.actions.ctl,
        vec![CtlAction::RemoveRuleById(RuleIdRange { start: 3, end: 3 })]
    );
}

#[test]
fn rejects_reversed_rule_remove_by_id_range() {
    let error =
        load(r#"SecRule ARGS "@contains x" "id:1,phase:1,pass,ctl:ruleRemoveById=9-1""#)
            .unwrap_err();
    assert!(error.to_string().contains("invalid ruleRemoveById range"));
}
```

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
cargo test -p aegis-engine --test compile_conformance rule_remove_by_id
```

Expected: 编译失败，提示 `RuleIdRange` 不存在或 `CtlAction::RemoveRuleById` 参数类型不匹配。

- [ ] **Step 3: 实现范围类型与解析**

在 `crates/aegis-engine/src/model.rs` 的 `CtlAction` 定义之前加入：

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleIdRange {
    pub start: u32,
    pub end: u32,
}

impl RuleIdRange {
    pub fn contains(self, id: u32) -> bool {
        self.start <= id && id <= self.end
    }
}
```

把 `CtlAction::RemoveRuleById(u32)` 改为：

```rust
    RemoveRuleById(RuleIdRange),
```

在 `crates/aegis-engine/src/compile.rs` 的 `parse_ctl` 之前加入：

```rust
fn parse_rule_id_range(value: &str) -> Result<RuleIdRange, String> {
    match value.split_once('-') {
        Some((start, end)) => {
            let start = start
                .trim()
                .parse::<u32>()
                .map_err(|error| format!("invalid ruleRemoveById start: {error}"))?;
            let end = end
                .trim()
                .parse::<u32>()
                .map_err(|error| format!("invalid ruleRemoveById end: {error}"))?;
            if start > end {
                return Err(format!("invalid ruleRemoveById range {start}-{end}"));
            }
            Ok(RuleIdRange { start, end })
        }
        None => {
            let id = value
                .trim()
                .parse::<u32>()
                .map_err(|error| format!("invalid ruleRemoveById: {error}"))?;
            Ok(RuleIdRange { start: id, end: id })
        }
    }
}
```

把 `parse_ctl` 中 `"ruleremovebyid"` 分支替换为：

```rust
        "ruleremovebyid" => parse_rule_id_range(&value).map(CtlAction::RemoveRuleById),
```

- [ ] **Step 4: 更新求值侧存储与匹配**

在 `crates/aegis-engine/src/eval.rs` 的导入中加入 `RuleIdRange`：

```rust
use crate::model::{
    CompiledOperator, CompiledRule, CompiledRules, CtlAction, Disruptive, Phase, Prefilter,
    PrefilterHits, PrefilterVariant, RuleEngineMode, RuleGroup, RuleIdRange, SetVar, SetVarOp,
    SetVarScope, Variable, VariableSpec,
};
```

把 `removed_rule_ids: HashSet<u32>` 改为：

```rust
    removed_rule_ids: Vec<RuleIdRange>,
```

把构造器中的 `removed_rule_ids: HashSet::new()` 改为：

```rust
            removed_rule_ids: Vec::new(),
```

把规则跳过判断改为：

```rust
            if self
                .removed_rule_ids
                .iter()
                .any(|range| range.contains(first.id))
                || first
                    .actions
                    .tags
                    .iter()
                    .any(|tag| self.removed_tags.contains(tag))
            {
                continue;
            }
```

把 `apply_ctl` 中的分支改为：

```rust
            CtlAction::RemoveRuleById(range) => {
                self.removed_rule_ids.push(*range);
            }
```

- [ ] **Step 5: 写失败的求值测试**

在 `crates/aegis-engine/src/eval.rs` 的测试模块中、`ctl_removes_rule_by_id` 之后加入：

```rust
    #[test]
    fn ctl_removes_rule_by_id_range() {
        let rules = load(
            r#"
SecRule REQUEST_HEADERS:X-Skip "@eq 1" "id:1,phase:1,pass,ctl:ruleRemoveById=2-10"
SecRule ARGS "@contains attack" "id:3,phase:1,deny,status:403"
"#,
        );
        let skipped = eval(&rules, "GET", "/?q=attack", &[("x-skip", "1")], b"");
        assert_eq!(skipped.decision, Decision::Pass);
        let blocked = eval(&rules, "GET", "/?q=attack", &[], b"");
        assert!(matches!(
            blocked.decision,
            Decision::Block { rule_id: 3, .. }
        ));
    }
```

- [ ] **Step 6: 运行测试确认通过**

Run:

```bash
cargo test -p aegis-engine --test compile_conformance rule_remove_by_id
cargo test -p aegis-engine ctl_removes_rule_by_id_range
cargo test -p aegis-engine
```

Expected: 全部 PASS。

- [ ] **Step 7: 格式化并提交**

```bash
cargo fmt
git add crates/aegis-engine/src/model.rs crates/aegis-engine/src/compile.rs \
    crates/aegis-engine/src/eval.rs crates/aegis-engine/tests/compile_conformance.rs
git commit -m "feat(engine): support rule id ranges in ctl ruleRemoveById"
```

---

### Task 2: 引擎请求体解析结构上限

**Files:**
- Modify: `crates/aegis-engine/src/variables/request.rs:51-88,203-241,664-755`
- Modify: `crates/aegis-engine/src/eval.rs:66-100,644-653`
- Modify: `crates/aegis-engine/src/lib.rs:20`
- Test: `crates/aegis-engine/src/variables/request.rs` 的 `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: 无
- Produces:
  - `pub struct ParseLimits { pub max_args: usize, pub max_multipart_parts: usize, pub max_multipart_part_headers: usize, pub max_xml_depth: usize, pub max_xml_values: usize }`
  - `impl Default for ParseLimits`：`10000 / 1000 / 64 / 64 / 10000`
  - `pub enum BodyParseError { TooManyArgs, TooManyMultipartParts, TooManyMultipartHeaders, XmlTooDeep, TooManyXmlValues }`
  - `RequestContext::set_parse_limits(&mut self, limits: ParseLimits)`
  - `RequestContext::set_body(&mut self, body: &[u8]) -> Result<(), BodyParseError>`
  - `EvaluationState::set_parse_limits(&mut self, limits: ParseLimits)`
  - `EvaluationState::set_body(&mut self, body: &[u8]) -> Result<(), BodyParseError>`

- [ ] **Step 1: 写失败的解析上限测试**

在 `crates/aegis-engine/src/variables/request.rs` 的测试模块末尾、最后一个 `}` 之前加入：

```rust
    #[test]
    fn urlencoded_body_over_max_args_is_rejected() {
        let headers = header_map(&[("content-type", "application/x-www-form-urlencoded")]);
        let mut context = context(&headers);
        context.set_parse_limits(ParseLimits {
            max_args: 2,
            ..ParseLimits::default()
        });
        assert!(context.set_body(b"a=1&b=2").is_ok());
        assert_eq!(
            context.set_body(b"a=1&b=2&c=3"),
            Err(BodyParseError::TooManyArgs)
        );
    }

    #[test]
    fn multipart_part_count_limit_is_enforced() {
        let headers = header_map(&[("content-type", "multipart/form-data; boundary=X")]);
        let mut context = context(&headers);
        context.set_parse_limits(ParseLimits {
            max_multipart_parts: 1,
            ..ParseLimits::default()
        });
        let one_part =
            b"--X\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--X--\r\n";
        assert!(context.set_body(one_part).is_ok());
        let two_parts = b"--X\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--X\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\n2\r\n--X--\r\n";
        assert_eq!(
            context.set_body(two_parts),
            Err(BodyParseError::TooManyMultipartParts)
        );
    }

    #[test]
    fn multipart_header_count_limit_is_enforced() {
        let headers = header_map(&[("content-type", "multipart/form-data; boundary=X")]);
        let mut context = context(&headers);
        context.set_parse_limits(ParseLimits {
            max_multipart_part_headers: 2,
            ..ParseLimits::default()
        });
        let body = b"--X\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Type: text/plain\r\nX-Test: 1\r\n\r\nvalue\r\n--X--\r\n";
        assert_eq!(
            context.set_body(body),
            Err(BodyParseError::TooManyMultipartHeaders)
        );
    }

    #[test]
    fn xml_depth_limit_is_enforced() {
        let headers = header_map(&[("content-type", "application/xml")]);
        let mut context = context(&headers);
        context.set_parse_limits(ParseLimits {
            max_xml_depth: 2,
            ..ParseLimits::default()
        });
        assert_eq!(
            context.set_body(b"<a><b><c>x</c></b></a>"),
            Err(BodyParseError::XmlTooDeep)
        );
        context.set_parse_limits(ParseLimits {
            max_xml_depth: 3,
            ..ParseLimits::default()
        });
        assert!(context.set_body(b"<a><b><c>x</c></b></a>").is_ok());
    }

    #[test]
    fn xml_value_count_limit_is_enforced() {
        let headers = header_map(&[("content-type", "application/xml")]);
        let mut context = context(&headers);
        context.set_parse_limits(ParseLimits {
            max_xml_values: 1,
            ..ParseLimits::default()
        });
        assert_eq!(
            context.set_body(b"<a><b>1</b><b>2</b></a>"),
            Err(BodyParseError::TooManyXmlValues)
        );
        context.set_parse_limits(ParseLimits {
            max_xml_values: 2,
            ..ParseLimits::default()
        });
        assert!(context.set_body(b"<a><b>1</b><b>2</b></a>").is_ok());
    }

    #[test]
    fn json_body_ignores_parse_limits() {
        let headers = header_map(&[("content-type", "application/json")]);
        let mut context = context(&headers);
        context.set_parse_limits(ParseLimits {
            max_args: 1,
            ..ParseLimits::default()
        });
        assert!(context.set_body(b"{\"a\":1,\"b\":2}").is_ok());
    }
```

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
cargo test -p aegis-engine variables::request::tests::urlencoded_body_over_max_args_is_rejected
```

Expected: 编译失败，提示 `ParseLimits` / `BodyParseError` 未定义。

- [ ] **Step 3: 定义 ParseLimits 与 BodyParseError**

在 `crates/aegis-engine/src/variables/request.rs` 的 `MultipartPart` 定义之后加入：

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseLimits {
    pub max_args: usize,
    pub max_multipart_parts: usize,
    pub max_multipart_part_headers: usize,
    pub max_xml_depth: usize,
    pub max_xml_values: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_args: 10_000,
            max_multipart_parts: 1_000,
            max_multipart_part_headers: 64,
            max_xml_depth: 64,
            max_xml_values: 10_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BodyParseError {
    #[error("too many request arguments")]
    TooManyArgs,
    #[error("too many multipart parts")]
    TooManyMultipartParts,
    #[error("too many multipart part headers")]
    TooManyMultipartHeaders,
    #[error("xml nesting too deep")]
    XmlTooDeep,
    #[error("too many xml values")]
    TooManyXmlValues,
}
```

在 `RequestContext` 字段中加入：

```rust
    parse_limits: ParseLimits,
```

在构造器中加入初始化：

```rust
            parse_limits: ParseLimits::default(),
```

- [ ] **Step 4: 让 set_body 返回 Result 并执行上限检查**

把 `RequestContext::set_body` 替换为：

```rust
    pub fn set_parse_limits(&mut self, limits: ParseLimits) {
        self.parse_limits = limits;
    }

    pub fn set_body(&mut self, body: &[u8]) -> Result<(), BodyParseError> {
        self.body_len = body.len();
        self.body_text = String::from_utf8_lossy(body).into_owned();
        self.body_processor = self
            .body_processor_override
            .unwrap_or_else(|| derive_body_processor(&self.headers));
        self.body_pairs = Vec::new();
        self.multipart_parts = Vec::new();
        self.xml_values = Vec::new();
        self.cache.borrow_mut().clear();

        let result = match self.body_processor {
            BodyProcessor::UrlEncoded => {
                let mut pairs = Vec::new();
                for (name, value) in form_urlencoded::parse(body) {
                    if pairs.len() >= self.parse_limits.max_args {
                        self.cache.borrow_mut().clear();
                        return Err(BodyParseError::TooManyArgs);
                    }
                    pairs.push((name.into_owned(), value.into_owned()));
                }
                self.body_pairs = pairs;
                Ok(())
            }
            BodyProcessor::Multipart => {
                if let Some(boundary) = multipart_boundary(&self.headers) {
                    let parts = parse_multipart(body, &boundary, &self.parse_limits)?;
                    let mut body_pairs = Vec::new();
                    for part in &parts {
                        if part.filename.is_none() {
                            if body_pairs.len() >= self.parse_limits.max_args {
                                self.cache.borrow_mut().clear();
                                return Err(BodyParseError::TooManyArgs);
                            }
                            body_pairs.push((
                                part.name.clone(),
                                String::from_utf8_lossy(&part.data).into_owned(),
                            ));
                        }
                    }
                    self.multipart_parts = parts;
                    self.body_pairs = body_pairs;
                }
                Ok(())
            }
            BodyProcessor::Xml => {
                self.xml_values = extract_xml_values(&self.body_text, &self.parse_limits)?;
                Ok(())
            }
            BodyProcessor::Json | BodyProcessor::None => Ok(()),
        };
        self.cache.borrow_mut().clear();
        result
    }
```

把 `parse_multipart` 替换为：

```rust
fn parse_multipart(
    body: &[u8],
    boundary: &str,
    limits: &ParseLimits,
) -> Result<Vec<MultipartPart>, BodyParseError> {
    let delimiter = format!("--{boundary}").into_bytes();
    let next_delimiter = format!("\r\n--{boundary}").into_bytes();
    let mut parts = Vec::new();
    let mut part_count = 0usize;
    let mut position = 0usize;

    while let Some(start) = find_subslice(&body[position..], &delimiter) {
        let mut cursor = position + start + delimiter.len();
        if body.get(cursor..cursor + 2) == Some(b"--") {
            break;
        }
        part_count += 1;
        if part_count > limits.max_multipart_parts {
            return Err(BodyParseError::TooManyMultipartParts);
        }
        if body.get(cursor..cursor + 2) == Some(b"\r\n") {
            cursor += 2;
        } else if body.get(cursor..cursor + 1) == Some(b"\n") {
            cursor += 1;
        }
        let Some(header_end) = find_subslice(&body[cursor..], b"\r\n\r\n") else {
            break;
        };
        let headers_text = String::from_utf8_lossy(&body[cursor..cursor + header_end]);
        let headers: Vec<String> = headers_text
            .lines()
            .map(str::trim_end)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect();
        if headers.len() > limits.max_multipart_part_headers {
            return Err(BodyParseError::TooManyMultipartHeaders);
        }
        let data_start = cursor + header_end + 4;
        let Some(next) = find_subslice(&body[data_start..], &next_delimiter) else {
            break;
        };
        let data_end = data_start + next;
        if let Some((name, filename)) = parse_part_disposition(&headers_text) {
            parts.push(MultipartPart {
                name,
                filename,
                headers,
                data: body[data_start..data_end].to_vec(),
            });
        }
        position = data_end + 2;
    }
    Ok(parts)
}
```

把 `extract_xml_values` 替换为：

```rust
fn extract_xml_values(
    text: &str,
    limits: &ParseLimits,
) -> Result<Vec<String>, BodyParseError> {
    let Ok(document) = roxmltree::Document::parse(text) else {
        return Ok(Vec::new());
    };
    let mut values = Vec::new();
    for node in document.descendants() {
        let depth = node.ancestors().filter(|node| node.is_element()).count();
        if depth > limits.max_xml_depth {
            return Err(BodyParseError::XmlTooDeep);
        }
        for child in node.children() {
            if child.is_text() {
                if let Some(text) = child.text() {
                    let text = text.trim();
                    if !text.is_empty() {
                        if values.len() >= limits.max_xml_values {
                            return Err(BodyParseError::TooManyXmlValues);
                        }
                        values.push(text.to_string());
                    }
                }
            }
        }
        for attribute in node.attributes() {
            if values.len() >= limits.max_xml_values {
                return Err(BodyParseError::TooManyXmlValues);
            }
            values.push(attribute.value().to_string());
        }
    }
    Ok(values)
}
```

- [ ] **Step 5: 更新 EvaluationState 与 evaluate()**

在 `crates/aegis-engine/src/eval.rs` 的 `EvaluationState` 方法中替换 `set_body`：

```rust
    pub fn set_parse_limits(&mut self, limits: crate::variables::request::ParseLimits) {
        self.context.set_parse_limits(limits);
    }

    pub fn set_body(
        &mut self,
        body: &[u8],
    ) -> Result<(), crate::variables::request::BodyParseError> {
        self.context.set_body(body)
    }
```

在 `evaluate()` 中把：

```rust
        state.set_body(view.body);
```

改为：

```rust
        let _ = state.set_body(view.body);
```

在 `crates/aegis-engine/src/lib.rs` 的导出中把：

```rust
pub use variables::request::{RequestContext, RequestView};
```

改为：

```rust
pub use variables::request::{BodyParseError, ParseLimits, RequestContext, RequestView};
```

- [ ] **Step 6: 运行引擎测试并修复调用点**

Run:

```bash
cargo test -p aegis-engine
```

Expected: 所有解析上限测试 PASS。

然后处理既有测试中的 `set_body` 调用：

```bash
grep -rn "set_body(" crates/aegis-engine/src/variables/request.rs
```

把测试模块中每个裸调用改为 `.unwrap()`，例如：

```rust
context.set_body(b"x=1").unwrap();
```

仅测试代码允许使用 `unwrap()`。

- [ ] **Step 7: 格式化并提交**

```bash
cargo fmt
git add crates/aegis-engine/src/variables/request.rs crates/aegis-engine/src/eval.rs \
    crates/aegis-engine/src/lib.rs
git commit -m "feat(engine): enforce request body parse limits"
```

---

### Task 3: 代理配置扩展

**Files:**
- Modify: `crates/aegis-proxy/src/config.rs:51-64,114-152,280-302`
- Modify: `config.example.yaml:16-24`
- Modify: `crates/aegis-proxy/tests/admin_integration.rs:41`
- Modify: `crates/aegis-proxy/tests/proxy_integration.rs:75`
- Modify: `crates/aegis-proxy/tests/proxy_response_integration.rs:79`
- Modify: `crates/aegis-proxy/tests/proxy_waf_integration.rs:80`
- Test: `crates/aegis-proxy/src/config.rs` 的 `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: 无
- Produces:
  - `pub enum ResponseBodyLimitAction { Reject, Pass }`，`Default = Reject`，serde 小写
  - `LimitsConfig` 新字段：
    - `response_body_limit_action: ResponseBodyLimitAction`
    - `max_args: usize`
    - `max_multipart_parts: usize`
    - `max_multipart_part_headers: usize`
    - `max_xml_depth: usize`
    - `max_xml_values: usize`

- [ ] **Step 1: 写失败的配置测试**

在 `crates/aegis-proxy/src/config.rs` 的测试模块中加入：

```rust
    #[test]
    fn defaults_response_and_parse_limits() {
        let yaml = r#"
listen: "127.0.0.1:8080"
upstream:
  url: "http://127.0.0.1:3000"
admin:
  listen: "127.0.0.1:9001"
rules:
  files: ["rules/*.conf"]
limits: {}
audit:
  sink: none
"#;
        let (_dir, path) = write_config(yaml);
        let config = Config::load(&path).unwrap();
        assert_eq!(
            config.limits.response_body_limit_action,
            ResponseBodyLimitAction::Reject
        );
        assert_eq!(config.limits.max_args, 10000);
        assert_eq!(config.limits.max_multipart_parts, 1000);
        assert_eq!(config.limits.max_multipart_part_headers, 64);
        assert_eq!(config.limits.max_xml_depth, 64);
        assert_eq!(config.limits.max_xml_values, 10000);
    }

    #[test]
    fn rejects_unknown_response_body_limit_action() {
        let yaml = FULL_CONFIG.replace(
            "response_body_limit_action: reject",
            "response_body_limit_action: ignore",
        );
        let (_dir, path) = write_config(&yaml);
        assert!(matches!(Config::load(&path), Err(ConfigError::Parse { .. })));
    }
```

在 `FULL_CONFIG` 的 `limits` 段中加入：

```yaml
  response_body_limit_action: reject
  max_args: 10000
  max_multipart_parts: 1000
  max_multipart_part_headers: 64
  max_xml_depth: 64
  max_xml_values: 10000
```

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
cargo test -p aegis-proxy config::tests::defaults_response_and_parse_limits
```

Expected: 编译失败，提示字段或 `ResponseBodyLimitAction` 不存在。

- [ ] **Step 3: 实现枚举与字段**

在 `crates/aegis-proxy/src/config.rs` 的 `LimitsConfig` 之前加入：

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResponseBodyLimitAction {
    #[default]
    Reject,
    Pass,
}
```

把 `LimitsConfig` 替换为：

```rust
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    #[serde(default = "default_max_header_bytes")]
    pub max_header_bytes: usize,
    #[serde(default = "default_max_uri_bytes")]
    pub max_uri_bytes: usize,
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    #[serde(default = "default_max_response_body_bytes")]
    pub max_response_body_bytes: usize,
    #[serde(default)]
    pub response_body_limit_action: ResponseBodyLimitAction,
    #[serde(default = "default_max_args")]
    pub max_args: usize,
    #[serde(default = "default_max_multipart_parts")]
    pub max_multipart_parts: usize,
    #[serde(default = "default_max_multipart_part_headers")]
    pub max_multipart_part_headers: usize,
    #[serde(default = "default_max_xml_depth")]
    pub max_xml_depth: usize,
    #[serde(default = "default_max_xml_values")]
    pub max_xml_values: usize,
    #[serde(default = "default_header_read_timeout_ms")]
    pub header_read_timeout_ms: u64,
    #[serde(default = "default_body_read_timeout_ms")]
    pub body_read_timeout_ms: u64,
}
```

在默认值函数区域加入：

```rust
fn default_max_args() -> usize {
    10_000
}

fn default_max_multipart_parts() -> usize {
    1_000
}

fn default_max_multipart_part_headers() -> usize {
    64
}

fn default_max_xml_depth() -> usize {
    64
}

fn default_max_xml_values() -> usize {
    10_000
}
```

在 `validate()` 的零值检查数组中追加：

```rust
            ("limits.max_args", self.limits.max_args),
            (
                "limits.max_multipart_parts",
                self.limits.max_multipart_parts,
            ),
            (
                "limits.max_multipart_part_headers",
                self.limits.max_multipart_part_headers,
            ),
            ("limits.max_xml_depth", self.limits.max_xml_depth),
            ("limits.max_xml_values", self.limits.max_xml_values),
```

- [ ] **Step 4: 更新测试中的 LimitsConfig 字面量**

在以下四个测试文件中，为每个 `aegis_proxy::config::LimitsConfig { ... }` 字面量追加：

```rust
            response_body_limit_action:
                aegis_proxy::config::ResponseBodyLimitAction::Reject,
            max_args: 10000,
            max_multipart_parts: 1000,
            max_multipart_part_headers: 64,
            max_xml_depth: 64,
            max_xml_values: 10000,
```

文件：

- `crates/aegis-proxy/tests/admin_integration.rs`
- `crates/aegis-proxy/tests/proxy_integration.rs`
- `crates/aegis-proxy/tests/proxy_response_integration.rs`
- `crates/aegis-proxy/tests/proxy_waf_integration.rs`

- [ ] **Step 5: 更新 config.example.yaml**

把 `config.example.yaml` 的 `limits` 段替换为：

```yaml
limits:
  max_header_bytes: 65536
  max_uri_bytes: 8192
  max_body_bytes: 1048576
  max_response_body_bytes: 1048576
  response_body_limit_action: reject
  max_args: 10000
  max_multipart_parts: 1000
  max_multipart_part_headers: 64
  max_xml_depth: 64
  max_xml_values: 10000
  header_read_timeout_ms: 10000
  body_read_timeout_ms: 15000
```

- [ ] **Step 6: 运行配置与集成测试**

Run:

```bash
cargo test -p aegis-proxy config::tests
cargo test -p aegis-proxy
```

Expected: 全部 PASS。

- [ ] **Step 7: 格式化并提交**

```bash
cargo fmt
git add crates/aegis-proxy/src/config.rs config.example.yaml \
    crates/aegis-proxy/tests/admin_integration.rs \
    crates/aegis-proxy/tests/proxy_integration.rs \
    crates/aegis-proxy/tests/proxy_response_integration.rs \
    crates/aegis-proxy/tests/proxy_waf_integration.rs
git commit -m "feat(proxy): add response and parse limit configuration"
```

---

### Task 4: 代理接入解析结构上限

**Files:**
- Modify: `crates/aegis-proxy/src/proxy/mod.rs:145-216,440-497`
- Test: `crates/aegis-proxy/tests/proxy_waf_integration.rs`

**Interfaces:**
- Consumes:
  - `aegis_engine::ParseLimits`
  - `EvaluationState::set_parse_limits`
  - `EvaluationState::set_body -> Result<(), BodyParseError>`
  - `LimitsConfig.max_args` / `max_multipart_parts` / `max_multipart_part_headers` / `max_xml_depth` / `max_xml_values`
- Produces:
  - 结构超限返回 413，审计 `error = "body_parse_limit: <kind>"`
  - 测试辅助 `harness_with_limits`

- [ ] **Step 1: 写失败的结构上限集成测试**

在 `crates/aegis-proxy/tests/proxy_waf_integration.rs` 顶部导入中加入：

```rust
use aegis_proxy::config::ResponseBodyLimitAction;
```

把 `harness_with_audit` 重构为接受 limits：

```rust
fn default_limits() -> aegis_proxy::config::LimitsConfig {
    aegis_proxy::config::LimitsConfig {
        max_header_bytes: 65536,
        max_uri_bytes: 8192,
        max_body_bytes: 1024,
        max_response_body_bytes: 1048576,
        response_body_limit_action: ResponseBodyLimitAction::Reject,
        max_args: 10000,
        max_multipart_parts: 1000,
        max_multipart_part_headers: 64,
        max_xml_depth: 64,
        max_xml_values: 10000,
        header_read_timeout_ms: 10000,
        body_read_timeout_ms: 15000,
    }
}

async fn harness(rules: &str) -> Harness {
    harness_with_limits(rules, AuditSink::None, AuditMode::BlockedOnly, default_limits()).await
}

async fn harness_with_audit(rules: &str, sink: AuditSink, mode: AuditMode) -> Harness {
    harness_with_limits(rules, sink, mode, default_limits()).await
}

async fn harness_with_limits(
    rules: &str,
    sink: AuditSink,
    mode: AuditMode,
    limits: aegis_proxy::config::LimitsConfig,
) -> Harness {
```

把原 `harness_with_audit` 函数体中的 `limits: aegis_proxy::config::LimitsConfig { ... }` 整体替换为 `limits,`。函数体其余部分不变。

在文件末尾追加：

```rust
#[tokio::test]
async fn urlencoded_args_over_parse_limit_returns_413() {
    let mut limits = default_limits();
    limits.max_args = 2;
    let harness = harness_with_limits(
        r#"SecMarker START"#,
        AuditSink::File,
        AuditMode::All,
        limits,
    )
    .await;
    let request = Request::builder()
        .method("POST")
        .uri("http://example.test/submit")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Full::new(Bytes::from_static(b"a=1&b=2&c=3")))
        .unwrap();
    let (status, _) = send(harness.proxy, request).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(harness.hits.load(Ordering::SeqCst), 0);
    let text = wait_for_audit(&harness.audit_path).await;
    assert!(
        text.contains("body_parse_limit: too many request arguments"),
        "audit: {text}"
    );
    harness.handle.abort();
}

#[tokio::test]
async fn multipart_parts_over_parse_limit_returns_413() {
    let mut limits = default_limits();
    limits.max_multipart_parts = 1;
    let harness = harness_with_limits(
        r#"SecMarker START"#,
        AuditSink::None,
        AuditMode::BlockedOnly,
        limits,
    )
    .await;
    let body = b"--X\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--X\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\n2\r\n--X--\r\n";
    let request = Request::builder()
        .method("POST")
        .uri("http://example.test/upload")
        .header("content-type", "multipart/form-data; boundary=X")
        .body(Full::new(Bytes::from_static(body)))
        .unwrap();
    let (status, _) = send(harness.proxy, request).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(harness.hits.load(Ordering::SeqCst), 0);
    harness.handle.abort();
}
```

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
cargo test -p aegis-proxy --test proxy_waf_integration urlencoded_args_over_parse_limit_returns_413
```

Expected: FAIL，当前返回 200 且上游被调用。

- [ ] **Step 3: 在请求评估初始化时注入 ParseLimits**

在 `crates/aegis-proxy/src/proxy/mod.rs` 的 `use aegis_engine::{...}` 中加入 `ParseLimits`：

```rust
use aegis_engine::{
    evaluate_phase, CompiledRules, Decision, Evaluation, EvaluationState, ParseLimits, Phase,
    RequestView,
};
```

把 `handle` 中构造 `evaluation` 的代码替换为：

```rust
    let mut evaluation = {
        let view = RequestView {
            method: &method,
            uri: &uri_string,
            path: &path,
            query: query.as_deref(),
            protocol,
            headers: &parts.headers,
            body: &[],
            remote_addr: peer.ip(),
            unique_id: request_id.as_str(),
        };
        let mut evaluation = EvaluationState::new_with_store(&view, state.collections.clone());
        evaluation.set_parse_limits(ParseLimits {
            max_args: state.config.limits.max_args,
            max_multipart_parts: state.config.limits.max_multipart_parts,
            max_multipart_part_headers: state.config.limits.max_multipart_part_headers,
            max_xml_depth: state.config.limits.max_xml_depth,
            max_xml_values: state.config.limits.max_xml_values,
        });
        evaluation
    };
```

- [ ] **Step 4: 处理 set_body 错误并返回 413**

在 `crates/aegis-proxy/src/proxy/mod.rs` 的 `local_after_upstream` 之后加入：

```rust
fn local_with_error(
    status: StatusCode,
    message: &'static str,
    body_bytes: usize,
    error: Option<String>,
) -> Outcome {
    Outcome {
        response: text_response(status, message),
        status,
        upstream_status: None,
        upstream_latency_ms: None,
        error,
        request_body_bytes: body_bytes,
    }
}
```

把 `process` 中的：

```rust
    if !skip_phase_two {
        evaluation.set_body(&body);
        evaluate_phase(evaluation, rules, Phase::Phase2);
```

改为：

```rust
    if !skip_phase_two {
        if let Err(error) = evaluation.set_body(&body) {
            return local_with_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body structure too large\n",
                body_len,
                Some(format!("body_parse_limit: {error}")),
            );
        }
        evaluate_phase(evaluation, rules, Phase::Phase2);
```

- [ ] **Step 5: 运行测试确认通过**

Run:

```bash
cargo test -p aegis-proxy --test proxy_waf_integration urlencoded_args_over_parse_limit_returns_413
cargo test -p aegis-proxy --test proxy_waf_integration multipart_parts_over_parse_limit_returns_413
cargo test -p aegis-proxy
```

Expected: 两个新测试 PASS，既有测试不回归。

- [ ] **Step 6: 格式化并提交**

```bash
cargo fmt
git add crates/aegis-proxy/src/proxy/mod.rs crates/aegis-proxy/tests/proxy_waf_integration.rs
git commit -m "feat(proxy): reject request bodies over parse limits"
```

---

### Task 5: 响应体检测（chunked、超限策略、流式续传、SSE）

**Files:**
- Modify: `Cargo.toml:11-40`
- Modify: `crates/aegis-proxy/Cargo.toml:16-34`
- Modify: `crates/aegis-proxy/src/proxy/limits.rs`
- Create: `crates/aegis-proxy/src/proxy/response_body.rs`
- Modify: `crates/aegis-proxy/src/proxy/mod.rs:25-26,245-344`
- Test: `crates/aegis-proxy/tests/proxy_response_integration.rs`

**Interfaces:**
- Consumes:
  - `LimitsConfig.max_response_body_bytes`
  - `LimitsConfig.response_body_limit_action`
- Produces:
  - `limits::BodyError::TooLarge { prefix: Bytes, rest: Incoming }`
  - `limits::prefix_body(prefix: Bytes, rest: Incoming) -> ProxyBody`
  - `response_body::is_event_stream(headers: &HeaderMap) -> bool`

- [ ] **Step 1: 扩展响应测试 harness**

在 `crates/aegis-proxy/tests/proxy_response_integration.rs` 顶部导入中加入：

```rust
use http_body_util::combinators::BoxBody;
use http_body_util::StreamBody;

use aegis_proxy::config::ResponseBodyLimitAction;
```

在 `struct Harness` 之前加入：

```rust
#[derive(Clone)]
enum TestBody {
    Full(Bytes),
    Chunked(Bytes),
}
```

把 `harness` 函数替换为下面两个函数（保留原有签名供旧测试使用）：

```rust
async fn harness(
    rules: &str,
    upstream_status: StatusCode,
    upstream_body: &'static [u8],
    max_response_body_bytes: usize,
) -> Harness {
    harness_with_body(
        rules,
        upstream_status,
        vec![("content-type", "text/plain".to_string())],
        TestBody::Full(Bytes::from_static(upstream_body)),
        max_response_body_bytes,
        ResponseBodyLimitAction::Reject,
    )
    .await
}

async fn harness_with_body(
    rules: &str,
    upstream_status: StatusCode,
    upstream_headers: Vec<(&'static str, String)>,
    body: TestBody,
    max_response_body_bytes: usize,
    action: ResponseBodyLimitAction,
) -> Harness {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_for_server = hits.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let hits = hits_for_server.clone();
            let body = body.clone();
            let upstream_headers = upstream_headers.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |_request: Request<Incoming>| {
                    let hits = hits.clone();
                    let body = body.clone();
                    let upstream_headers = upstream_headers.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        let mut builder = Response::builder().status(upstream_status);
                        for (name, value) in &upstream_headers {
                            builder = builder.header(*name, value);
                        }
                        let response_body: BoxBody<Bytes, Infallible> = match body {
                            TestBody::Full(bytes) => Full::new(bytes).boxed(),
                            TestBody::Chunked(bytes) => {
                                let stream = futures_util::stream::iter(vec![Ok::<
                                    _,
                                    Infallible,
                                >(
                                    hyper::body::Frame::data(bytes)
                                )]);
                                StreamBody::new(stream).boxed()
                            }
                        };
                        Ok::<_, Infallible>(builder.body(response_body).unwrap())
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let rules_path = dir.path().join("rules.conf");
    std::fs::write(&rules_path, rules).unwrap();
    let config = aegis_proxy::Config {
        listen: "127.0.0.1:0".to_string(),
        upstream: aegis_proxy::config::UpstreamConfig {
            url: format!("http://{upstream_addr}"),
            host_header: aegis_proxy::config::HostHeader::Preserve,
            connect_timeout_ms: 3000,
            total_timeout_ms: 30000,
        },
        admin: aegis_proxy::config::AdminConfig {
            listen: "127.0.0.1:0".to_string(),
            token: None,
        },
        rules: aegis_proxy::config::RulesConfig {
            files: vec![rules_path.display().to_string()],
            lenient: false,
        },
        limits: aegis_proxy::config::LimitsConfig {
            max_header_bytes: 65536,
            max_uri_bytes: 8192,
            max_body_bytes: 1024,
            max_response_body_bytes,
            response_body_limit_action: action,
            max_args: 10000,
            max_multipart_parts: 1000,
            max_multipart_part_headers: 64,
            max_xml_depth: 64,
            max_xml_values: 10000,
            header_read_timeout_ms: 10000,
            body_read_timeout_ms: 15000,
        },
        on_error: aegis_proxy::config::OnError::Block,
        audit: aegis_proxy::config::AuditConfig {
            sink: aegis_proxy::config::AuditSink::None,
            path: None,
            mode: aegis_proxy::config::AuditMode::BlockedOnly,
            queue_capacity: 1024,
            include_query: false,
            matched_rules_limit: 16,
        },
    };
    let rules =
        Arc::new(aegis_proxy::rules::RulesManager::load_initial(&[rules_path], false).unwrap());
    let (audit, _audit_receiver) = aegis_proxy::audit_sink::AuditHandle::channel(64);
    let state = Arc::new(aegis_proxy::state::AppState::new(config, rules, audit).unwrap());
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = proxy_listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = aegis_proxy::proxy::serve_on(proxy_listener, state).await;
    });
    Harness {
        proxy,
        hits,
        _dir: dir,
        handle,
    }
}
```

把 `send` 替换为：

```rust
async fn send_bytes(addr: SocketAddr, request: Request<Full<Bytes>>) -> (StatusCode, Bytes) {
    let (mut parts, body) = request.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_string();
    let host = parts
        .uri
        .authority()
        .map(|authority| authority.to_string())
        .unwrap_or_else(|| "example.test".to_string());
    if !parts.headers.contains_key(HOST) {
        parts
            .headers
            .insert(HOST, HeaderValue::from_bytes(host.as_bytes()).unwrap());
    }
    parts.uri = format!("http://{addr}{path_and_query}").parse().unwrap();
    let request = Request::from_parts(parts, body);

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();
    let response = client.request(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, body)
}

async fn send(addr: SocketAddr, request: Request<Full<Bytes>>) -> (StatusCode, String) {
    let (status, body) = send_bytes(addr, request).await;
    (status, String::from_utf8_lossy(&body).into_owned())
}
```

在文件末尾追加：

```rust
#[tokio::test]
async fn phase_four_inspects_chunked_response() {
    let harness = harness_with_body(
        r#"SecRule RESPONSE_BODY "@contains secret" "id:2,phase:4,deny,status:403""#,
        StatusCode::OK,
        vec![("content-type", "text/plain".to_string())],
        TestBody::Chunked(Bytes::from_static(b"a secret response")),
        1048576,
        ResponseBodyLimitAction::Reject,
    )
    .await;
    let (status, _) = send(harness.proxy, get("http://example.test/")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(harness.hits.load(Ordering::SeqCst), 1);
    harness.handle.abort();
}

#[tokio::test]
async fn over_limit_chunked_response_is_rejected() {
    let harness = harness_with_body(
        r#"SecRule RESPONSE_BODY "@contains never-match" "id:2,phase:4,pass""#,
        StatusCode::OK,
        vec![("content-type", "text/plain".to_string())],
        TestBody::Chunked(Bytes::from_static(b"0123456789abcdef0123456789abcdef")),
        16,
        ResponseBodyLimitAction::Reject,
    )
    .await;
    let (status, _) = send(harness.proxy, get("http://example.test/")).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    harness.handle.abort();
}

#[tokio::test]
async fn over_limit_chunked_response_passes_through() {
    let harness = harness_with_body(
        r#"SecRule RESPONSE_BODY "@contains never-match" "id:2,phase:4,pass""#,
        StatusCode::OK,
        vec![("content-type", "text/plain".to_string())],
        TestBody::Chunked(Bytes::from_static(b"0123456789abcdef0123456789abcdef")),
        16,
        ResponseBodyLimitAction::Pass,
    )
    .await;
    let (status, body) = send_bytes(harness.proxy, get("http://example.test/")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"0123456789abcdef0123456789abcdef");
    harness.handle.abort();
}

#[tokio::test]
async fn over_limit_known_length_response_is_rejected() {
    let harness = harness_with_body(
        r#"SecRule RESPONSE_BODY "@contains never-match" "id:2,phase:4,pass""#,
        StatusCode::OK,
        vec![("content-type", "text/plain".to_string())],
        TestBody::Full(Bytes::from_static(b"0123456789abcdef0123456789abcdef")),
        16,
        ResponseBodyLimitAction::Reject,
    )
    .await;
    let (status, _) = send(harness.proxy, get("http://example.test/")).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    harness.handle.abort();
}

#[tokio::test]
async fn over_limit_known_length_response_passes_through() {
    let harness = harness_with_body(
        r#"SecRule RESPONSE_BODY "@contains never-match" "id:2,phase:4,pass""#,
        StatusCode::OK,
        vec![("content-type", "text/plain".to_string())],
        TestBody::Full(Bytes::from_static(b"0123456789abcdef0123456789abcdef")),
        16,
        ResponseBodyLimitAction::Pass,
    )
    .await;
    let (status, body) = send_bytes(harness.proxy, get("http://example.test/")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"0123456789abcdef0123456789abcdef");
    harness.handle.abort();
}

#[tokio::test]
async fn event_stream_is_not_buffered() {
    let harness = harness_with_body(
        r#"SecRule RESPONSE_BODY "@contains secret" "id:2,phase:4,deny,status:403""#,
        StatusCode::OK,
        vec![("content-type", "text/event-stream".to_string())],
        TestBody::Chunked(Bytes::from_static(b"a secret event")),
        1048576,
        ResponseBodyLimitAction::Reject,
    )
    .await;
    let (status, body) = send_bytes(harness.proxy, get("http://example.test/")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"a secret event");
    harness.handle.abort();
}
```

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
cargo test -p aegis-proxy --test proxy_response_integration phase_four_inspects_chunked_response
```

Expected: 编译失败（`harness_with_body` 不存在），或实现后 FAIL（chunked 响应未检测）。

- [ ] **Step 3: 添加 futures-util 依赖**

在根 `Cargo.toml` 的 `[workspace.dependencies]` 中加入：

```toml
futures-util = "0.3"
```

在 `crates/aegis-proxy/Cargo.toml` 的 `[dependencies]` 中加入：

```toml
futures-util.workspace = true
```

- [ ] **Step 4: 扩展 limits.rs**

把 `crates/aegis-proxy/src/proxy/limits.rs` 替换为：

```rust
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use http_body_util::{BodyExt, BodyStream, StreamBody};
use hyper::body::Incoming;

use crate::proxy::ProxyBody;

#[derive(Debug)]
pub enum BodyError {
    TooLarge { prefix: Bytes, rest: Incoming },
    Timeout,
    Hyper(hyper::Error),
}

pub async fn read_body_limited(
    mut body: Incoming,
    limit: usize,
    timeout: Duration,
) -> Result<Bytes, BodyError> {
    let read = async {
        let mut buffer = BytesMut::new();
        loop {
            let frame = match body.frame().await {
                Some(frame) => frame.map_err(BodyError::Hyper)?,
                None => break,
            };
            if let Ok(data) = frame.into_data() {
                if buffer.len() + data.len() > limit {
                    buffer.extend_from_slice(&data);
                    return Err(BodyError::TooLarge {
                        prefix: buffer.freeze(),
                        rest: body,
                    });
                }
                buffer.extend_from_slice(&data);
            }
        }
        Ok(buffer.freeze())
    };
    match tokio::time::timeout(timeout, read).await {
        Ok(result) => result,
        Err(_) => Err(BodyError::Timeout),
    }
}

pub fn prefix_body(prefix: Bytes, rest: Incoming) -> ProxyBody {
    let first =
        futures_util::stream::once(
            async move { Ok::<_, hyper::Error>(hyper::body::Frame::data(prefix)) },
        );
    let stream = first.chain(BodyStream::new(rest));
    StreamBody::new(stream).boxed()
}
```

- [ ] **Step 5: 新增 response_body.rs**

创建 `crates/aegis-proxy/src/proxy/response_body.rs`：

```rust
use hyper::header::CONTENT_TYPE;
use hyper::HeaderMap;

pub fn is_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("text/event-stream")
        })
        .unwrap_or(false)
}
```

- [ ] **Step 6: 重写响应处理流程**

在 `crates/aegis-proxy/src/proxy/mod.rs` 中加入模块声明：

```rust
pub mod response_body;
```

在导入中加入：

```rust
use crate::config::ResponseBodyLimitAction;
use crate::proxy::response_body::is_event_stream;
```

把 `process` 中从 `let upstream_status = response_parts.status.as_u16();` 到函数末尾的内容替换为：

```rust
    let upstream_status = response_parts.status.as_u16();
    let upstream_latency = Some(upstream_started.elapsed().as_millis() as u64);

    let inspect_response = !rules.phase3.is_empty() || !rules.phase4.is_empty();
    if inspect_response {
        evaluation.set_response_headers(upstream_status, &response_parts.headers);
        evaluate_phase(evaluation, rules, Phase::Phase3);
        if let Decision::Block { status, .. } = evaluation.decision() {
            return blocked_with_upstream(*status, body_len, Some(upstream_status), upstream_latency);
        }
    }

    let max_body = state.config.limits.max_response_body_bytes;
    let limit_action = state.config.limits.response_body_limit_action;
    let mut forward_body: Option<ProxyBody> = None;
    let mut buffered_body: Option<Bytes> = None;

    if rules.phase4.is_empty() || is_event_stream(&response_parts.headers) {
        forward_body = Some(response_body.boxed());
    } else if content_length(&response_parts.headers)
        .map(|length| length > max_body as u64)
        .unwrap_or(false)
    {
        match limit_action {
            ResponseBodyLimitAction::Reject => {
                return local_after_upstream(
                    StatusCode::BAD_GATEWAY,
                    "upstream body too large\n",
                    body_len,
                    upstream_status,
                    upstream_latency,
                    "upstream_body_too_large",
                );
            }
            ResponseBodyLimitAction::Pass => forward_body = Some(response_body.boxed()),
        }
    } else {
        let timeout = Duration::from_millis(state.config.limits.body_read_timeout_ms);
        match limits::read_body_limited(response_body, max_body, timeout).await {
            Ok(raw) => {
                evaluation.set_response_body(&raw);
                buffered_body = Some(raw);
            }
            Err(limits::BodyError::TooLarge { prefix, rest }) => match limit_action {
                ResponseBodyLimitAction::Reject => {
                    return local_after_upstream(
                        StatusCode::BAD_GATEWAY,
                        "upstream body too large\n",
                        body_len,
                        upstream_status,
                        upstream_latency,
                        "upstream_body_too_large",
                    );
                }
                ResponseBodyLimitAction::Pass => {
                    forward_body = Some(limits::prefix_body(prefix, rest));
                }
            },
            Err(limits::BodyError::Timeout) => {
                return local_after_upstream(
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream body timeout\n",
                    body_len,
                    upstream_status,
                    upstream_latency,
                    "upstream_body_timeout",
                );
            }
            Err(limits::BodyError::Hyper(error)) => {
                warn!(%peer, %error, "failed to read upstream body");
                return local_after_upstream(
                    StatusCode::BAD_GATEWAY,
                    "upstream body error\n",
                    body_len,
                    upstream_status,
                    upstream_latency,
                    "upstream_body_error",
                );
            }
        }
    }

    if let Some(raw) = buffered_body.take() {
        evaluate_phase(evaluation, rules, Phase::Phase4);
        if let Decision::Block { status, .. } = evaluation.decision() {
            return blocked_with_upstream(*status, body_len, Some(upstream_status), upstream_latency);
        }
        forward_body = Some(full_body(raw));
    }

    if !rules.phase5.is_empty() {
        evaluate_phase(evaluation, rules, Phase::Phase5);
    }

    let response_body = match forward_body {
        Some(body) => body,
        None => {
            return local_after_upstream(
                StatusCode::INTERNAL_SERVER_ERROR,
                "response body unavailable\n",
                body_len,
                upstream_status,
                upstream_latency,
                "response_body_unavailable",
            );
        }
    };
    let downstream_status = response_parts.status;
    Outcome {
        response: build_response(response_parts, response_body),
        status: downstream_status,
        upstream_status: Some(upstream_status),
        upstream_latency_ms: upstream_latency,
        error: None,
        request_body_bytes: body_len,
    }
}
```

- [ ] **Step 7: 运行测试确认通过**

Run:

```bash
cargo test -p aegis-proxy --test proxy_response_integration
cargo test -p aegis-proxy
```

Expected: 全部 PASS。特别确认 `over_limit_chunked_response_passes_through` 收到的字节与上游完全一致。

- [ ] **Step 8: 格式化并提交**

```bash
cargo fmt
git add Cargo.toml Cargo.lock crates/aegis-proxy/Cargo.toml \
    crates/aegis-proxy/src/proxy/limits.rs \
    crates/aegis-proxy/src/proxy/response_body.rs \
    crates/aegis-proxy/src/proxy/mod.rs \
    crates/aegis-proxy/tests/proxy_response_integration.rs
git commit -m "feat(proxy): inspect chunked and oversized responses"
```

---

### Task 6: 压缩响应解码检测

**Files:**
- Modify: `Cargo.toml:11-40`
- Modify: `crates/aegis-proxy/Cargo.toml:16-34`
- Modify: `crates/aegis-proxy/src/proxy/response_body.rs`
- Modify: `crates/aegis-proxy/src/proxy/mod.rs` 的 `Ok(raw)` 分支
- Test: `crates/aegis-proxy/tests/proxy_response_integration.rs`

**Interfaces:**
- Consumes: `Task 5` 的 `harness_with_body`、`TestBody`
- Produces:
  - `response_body::DecodedBody { Decoded(Bytes), TooLarge, Unsupported }`
  - `response_body::decode_body(body: &Bytes, headers: &HeaderMap, limit: usize) -> DecodedBody`

- [ ] **Step 1: 添加解码依赖**

在根 `Cargo.toml` 的 `[workspace.dependencies]` 中加入：

```toml
flate2 = "1"
brotli = "9"
```

在 `crates/aegis-proxy/Cargo.toml` 的 `[dependencies]` 中加入：

```toml
flate2.workspace = true
brotli.workspace = true
```

- [ ] **Step 2: 写失败的压缩响应测试**

在 `crates/aegis-proxy/tests/proxy_response_integration.rs` 末尾追加：

```rust
fn gzip_body(data: &[u8]) -> Bytes {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    Bytes::from(encoder.finish().unwrap())
}

fn deflate_body(data: &[u8]) -> Bytes {
    use std::io::Write;
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    Bytes::from(encoder.finish().unwrap())
}

fn brotli_body(data: &[u8]) -> Bytes {
    use std::io::Write;
    let mut output = Vec::new();
    {
        let mut writer = brotli::CompressorWriter::new(&mut output, 4096, 5, 22);
        writer.write_all(data).unwrap();
    }
    Bytes::from(output)
}

#[tokio::test]
async fn gzip_response_is_inspected_after_decoding() {
    let harness = harness_with_body(
        r#"SecRule RESPONSE_BODY "@contains secret" "id:2,phase:4,deny,status:403""#,
        StatusCode::OK,
        vec![
            ("content-type", "text/plain".to_string()),
            ("content-encoding", "gzip".to_string()),
        ],
        TestBody::Full(gzip_body(b"a secret response")),
        1048576,
        ResponseBodyLimitAction::Reject,
    )
    .await;
    let (status, _) = send(harness.proxy, get("http://example.test/")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    harness.handle.abort();
}

#[tokio::test]
async fn deflate_response_is_inspected_after_decoding() {
    let harness = harness_with_body(
        r#"SecRule RESPONSE_BODY "@contains secret" "id:2,phase:4,deny,status:403""#,
        StatusCode::OK,
        vec![
            ("content-type", "text/plain".to_string()),
            ("content-encoding", "deflate".to_string()),
        ],
        TestBody::Full(deflate_body(b"a secret response")),
        1048576,
        ResponseBodyLimitAction::Reject,
    )
    .await;
    let (status, _) = send(harness.proxy, get("http://example.test/")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    harness.handle.abort();
}

#[tokio::test]
async fn brotli_response_is_inspected_after_decoding() {
    let harness = harness_with_body(
        r#"SecRule RESPONSE_BODY "@contains secret" "id:2,phase:4,deny,status:403""#,
        StatusCode::OK,
        vec![
            ("content-type", "text/plain".to_string()),
            ("content-encoding", "br".to_string()),
        ],
        TestBody::Full(brotli_body(b"a secret response")),
        1048576,
        ResponseBodyLimitAction::Reject,
    )
    .await;
    let (status, _) = send(harness.proxy, get("http://example.test/")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    harness.handle.abort();
}

#[tokio::test]
async fn gzip_body_over_decoded_limit_is_rejected() {
    let plain = vec![b'a'; 4096];
    let encoded = gzip_body(&plain);
    assert!(encoded.len() < 64);
    let harness = harness_with_body(
        r#"SecRule RESPONSE_BODY "@contains never-match" "id:2,phase:4,pass""#,
        StatusCode::OK,
        vec![
            ("content-type", "text/plain".to_string()),
            ("content-encoding", "gzip".to_string()),
        ],
        TestBody::Full(encoded),
        64,
        ResponseBodyLimitAction::Reject,
    )
    .await;
    let (status, _) = send(harness.proxy, get("http://example.test/")).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    harness.handle.abort();
}

#[tokio::test]
async fn gzip_body_over_decoded_limit_passes_through_when_configured() {
    let plain = vec![b'a'; 4096];
    let encoded = gzip_body(&plain);
    assert!(encoded.len() < 64);
    let expected = encoded.clone();
    let harness = harness_with_body(
        r#"SecRule RESPONSE_BODY "@contains never-match" "id:2,phase:4,pass""#,
        StatusCode::OK,
        vec![
            ("content-type", "text/plain".to_string()),
            ("content-encoding", "gzip".to_string()),
        ],
        TestBody::Full(encoded),
        64,
        ResponseBodyLimitAction::Pass,
    )
    .await;
    let (status, body) = send_bytes(harness.proxy, get("http://example.test/")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, expected);
    harness.handle.abort();
}

#[tokio::test]
async fn corrupt_gzip_is_forwarded() {
    let harness = harness_with_body(
        r#"SecRule RESPONSE_BODY "@contains secret" "id:2,phase:4,deny,status:403""#,
        StatusCode::OK,
        vec![
            ("content-type", "text/plain".to_string()),
            ("content-encoding", "gzip".to_string()),
        ],
        TestBody::Full(Bytes::from_static(b"not gzip data")),
        1048576,
        ResponseBodyLimitAction::Reject,
    )
    .await;
    let (status, body) = send_bytes(harness.proxy, get("http://example.test/")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"not gzip data");
    harness.handle.abort();
}

#[tokio::test]
async fn unknown_content_encoding_is_forwarded() {
    let harness = harness_with_body(
        r#"SecRule RESPONSE_BODY "@contains secret" "id:2,phase:4,deny,status:403""#,
        StatusCode::OK,
        vec![
            ("content-type", "text/plain".to_string()),
            ("content-encoding", "zstd".to_string()),
        ],
        TestBody::Full(Bytes::from_static(b"a secret response")),
        1048576,
        ResponseBodyLimitAction::Reject,
    )
    .await;
    let (status, body) = send_bytes(harness.proxy, get("http://example.test/")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"a secret response");
    harness.handle.abort();
}
```

- [ ] **Step 3: 运行测试确认失败**

Run:

```bash
cargo test -p aegis-proxy --test proxy_response_integration gzip_response_is_inspected_after_decoding
```

Expected: 编译失败（`decode_body` 尚未实现），或实现后 FAIL（压缩内容未被检测）。

- [ ] **Step 4: 实现解码**

把 `crates/aegis-proxy/src/proxy/response_body.rs` 替换为：

```rust
use std::io::Read;

use bytes::Bytes;
use hyper::header::{CONTENT_ENCODING, CONTENT_TYPE};
use hyper::HeaderMap;

pub enum DecodedBody {
    Decoded(Bytes),
    TooLarge,
    Unsupported,
}

pub fn is_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("text/event-stream")
        })
        .unwrap_or(false)
}

pub fn decode_body(body: &Bytes, headers: &HeaderMap, limit: usize) -> DecodedBody {
    let mut encodings = Vec::new();
    for value in headers.get_all(CONTENT_ENCODING).iter() {
        let Ok(value) = value.to_str() else {
            return DecodedBody::Unsupported;
        };
        for part in value.split(',') {
            let part = part.trim();
            if !part.is_empty() {
                encodings.push(part.to_ascii_lowercase());
            }
        }
    }
    if encodings.is_empty()
        || encodings
            .iter()
            .all(|encoding| encoding.as_str() == "identity")
    {
        return DecodedBody::Decoded(body.clone());
    }

    let mut current = body.clone();
    for encoding in encodings.iter().rev() {
        match decode_one(&current, encoding, limit) {
            Ok(next) => current = next,
            Err(DecodeError::TooLarge) => return DecodedBody::TooLarge,
            Err(DecodeError::Unsupported | DecodeError::Malformed) => {
                return DecodedBody::Unsupported;
            }
        }
    }
    DecodedBody::Decoded(current)
}

enum DecodeError {
    TooLarge,
    Unsupported,
    Malformed,
}

fn decode_one(body: &Bytes, encoding: &str, limit: usize) -> Result<Bytes, DecodeError> {
    let reader: Box<dyn Read> = match encoding {
        "gzip" | "x-gzip" => Box::new(flate2::read::MultiGzDecoder::new(body.as_ref())),
        "deflate" => Box::new(flate2::read::ZlibDecoder::new(body.as_ref())),
        "br" => Box::new(brotli::Decompressor::new(body.as_ref(), 4096)),
        _ => return Err(DecodeError::Unsupported),
    };
    let mut output = Vec::new();
    let mut limited = reader.take(limit as u64 + 1);
    limited
        .read_to_end(&mut output)
        .map_err(|_| DecodeError::Malformed)?;
    if output.len() > limit {
        Err(DecodeError::TooLarge)
    } else {
        Ok(Bytes::from(output))
    }
}
```

- [ ] **Step 5: 在响应流程中调用解码**

在 `crates/aegis-proxy/src/proxy/mod.rs` 中把 Task 5 的导入：

```rust
use crate::proxy::response_body::is_event_stream;
```

替换为：

```rust
use crate::proxy::response_body::{decode_body, is_event_stream, DecodedBody};
```

把 Task 5 中 `Ok(raw)` 分支：

```rust
            Ok(raw) => {
                evaluation.set_response_body(&raw);
                buffered_body = Some(raw);
            }
```

替换为：

```rust
            Ok(raw) => match decode_body(&raw, &response_parts.headers, max_body) {
                DecodedBody::Decoded(decoded) => {
                    evaluation.set_response_body(&decoded);
                    buffered_body = Some(raw);
                }
                DecodedBody::Unsupported => {
                    evaluation.set_response_body(&raw);
                    buffered_body = Some(raw);
                }
                DecodedBody::TooLarge => match limit_action {
                    ResponseBodyLimitAction::Reject => {
                        return local_after_upstream(
                            StatusCode::BAD_GATEWAY,
                            "upstream body too large\n",
                            body_len,
                            upstream_status,
                            upstream_latency,
                            "upstream_body_too_large",
                        );
                    }
                    ResponseBodyLimitAction::Pass => {
                        forward_body = Some(full_body(raw));
                    }
                },
            },
```

- [ ] **Step 6: 运行测试确认通过**

Run:

```bash
cargo test -p aegis-proxy --test proxy_response_integration
cargo test -p aegis-proxy
```

Expected: 全部 PASS。

- [ ] **Step 7: 格式化并提交**

```bash
cargo fmt
git add Cargo.toml Cargo.lock crates/aegis-proxy/Cargo.toml \
    crates/aegis-proxy/src/proxy/response_body.rs \
    crates/aegis-proxy/src/proxy/mod.rs \
    crates/aegis-proxy/tests/proxy_response_integration.rs
git commit -m "feat(proxy): decode compressed response bodies for inspection"
```

---

### Task 7: go-ftw 测试后端

**Files:**
- Create: `crates/aegis-proxy/examples/ftw_backend.rs`

**Interfaces:**
- Consumes: 无
- Produces:
  - HTTP 服务监听 `127.0.0.1:${FTW_BACKEND_PORT:-18081}`
  - `POST /reflect`：JSON `status` / `body` / `headers`
  - `ANY /status/{code}`
  - 其他路径 200 空响应

- [ ] **Step 1: 创建测试后端**

创建 `crates/aegis-proxy/examples/ftw_backend.rs`：

```rust
use std::collections::HashMap;
use std::convert::Infallible;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue, CONTENT_TYPE};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::net::TcpListener;

type Body = BoxBody<Bytes, Infallible>;

#[derive(Debug, Deserialize)]
struct Reflect {
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    headers: HashMap<String, String>,
}

fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|error: Infallible| match error {})
        .boxed()
}

fn text(status: StatusCode, message: &'static str) -> Response<Body> {
    let mut response = Response::new(full(message));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

async fn handle(request: Request<Incoming>) -> Result<Response<Body>, Infallible> {
    let path = request.uri().path().to_string();
    if let Some(code) = path
        .strip_prefix("/status/")
        .and_then(|value| value.parse::<u16>().ok())
    {
        let status = StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST);
        return Ok(text(status, ""));
    }
    if path == "/reflect" {
        let Ok(collected) = request.into_body().collect().await else {
            return Ok(text(StatusCode::BAD_REQUEST, "invalid body"));
        };
        let bytes = collected.to_bytes();
        let Ok(reflect) = serde_json::from_slice::<Reflect>(&bytes) else {
            return Ok(text(StatusCode::BAD_REQUEST, "invalid json"));
        };
        let status = reflect
            .status
            .and_then(|code| StatusCode::from_u16(code).ok())
            .unwrap_or(StatusCode::OK);
        let mut response = Response::new(full(reflect.body.unwrap_or_default()));
        *response.status_mut() = status;
        for (name, value) in reflect.headers {
            let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
                continue;
            };
            let Ok(value) = HeaderValue::from_str(&value) else {
                continue;
            };
            response.headers_mut().insert(name, value);
        }
        return Ok(response);
    }
    Ok(Response::new(full(Bytes::new())))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let port = std::env::var("FTW_BACKEND_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(18081);
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("ftw backend listening on 127.0.0.1:{port}");
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(handle);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });
    }
}
```

- [ ] **Step 2: 编译并手工验证**

Run:

```bash
cargo build -p aegis-proxy --example ftw_backend
BIN=target/debug/examples/ftw_backend
if [ -x "$BIN.exe" ]; then BIN="$BIN.exe"; fi
FTW_BACKEND_PORT=18081 "$BIN" &
BACKEND_PID=$!
sleep 1
curl -s -X POST -H 'content-type: application/json' \
    -d '{"body":"hello"}' http://127.0.0.1:18081/reflect
printf '\n'
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18081/status/418
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18081/other
kill "$BACKEND_PID"
```

Expected: 输出 `hello`、`418`、`200`。

- [ ] **Step 3: 提交**

```bash
cargo fmt
git add crates/aegis-proxy/examples/ftw_backend.rs
git commit -m "test(proxy): add go-ftw test backend"
```

---

### Task 8: go-ftw 门禁工具与编排脚本

**Files:**
- Create: `crates/aegis-proxy/examples/ftw_gate.rs`
- Create: `scripts/ftw.sh`
- Create: `scripts/ftw-known-gaps.txt`

**Interfaces:**
- Consumes:
  - Task 1 的 `ruleRemoveById` 范围
  - Task 3 的配置字段
  - Task 7 的 `ftw_backend`
  - go-ftw JSON 报告字段：`run` / `success` / `failed` / `skipped`
- Produces:
  - `bash scripts/ftw.sh [--full|--gate]`
  - 环境变量：`FTW_BIN`、`FTW_PROXY_PORT`、`FTW_ADMIN_PORT`、`FTW_BACKEND_PORT`、`FTW_INCLUDE`、`FTW_EXCLUDE`
  - `target/ftw/report.json`、`target/ftw/audit.jsonl`

- [ ] **Step 1: 创建门禁检查器**

创建 `crates/aegis-proxy/examples/ftw_gate.rs`：

```rust
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::process::ExitCode;

use serde::Deserialize;

const GATE_PREFIXES: &[&str] = &[
    "911", "913", "920", "921", "930", "931", "932", "933", "941", "942", "943", "949",
];

#[derive(Debug, Deserialize)]
struct RunStats {
    #[serde(default)]
    run: usize,
    #[serde(default)]
    success: Vec<String>,
    #[serde(default)]
    failed: Vec<String>,
    #[serde(default)]
    skipped: Vec<String>,
}

fn rule_prefix(test_id: &str) -> &str {
    test_id
        .split('-')
        .next()
        .unwrap_or("")
        .get(..3)
        .unwrap_or("")
}

fn in_gate(test_id: &str) -> bool {
    GATE_PREFIXES.contains(&rule_prefix(test_id))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: ftw_gate <report.json> <known-gaps.txt>");
        return ExitCode::from(2);
    }
    let report = match fs::read_to_string(&args[1]) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("failed to read report {}: {error}", args[1]);
            return ExitCode::FAILURE;
        }
    };
    let stats: RunStats = match serde_json::from_str(&report) {
        Ok(stats) => stats,
        Err(error) => {
            eprintln!("failed to parse report {}: {error}", args[1]);
            return ExitCode::FAILURE;
        }
    };
    let gaps = match load_gaps(&args[2]) {
        Ok(gaps) => gaps,
        Err(error) => {
            eprintln!("failed to read known gaps {}: {error}", args[2]);
            return ExitCode::FAILURE;
        }
    };

    let gate_failures: Vec<&str> = stats
        .failed
        .iter()
        .map(String::as_str)
        .filter(|id| in_gate(*id))
        .collect();
    let unknown: Vec<&str> = gate_failures
        .iter()
        .copied()
        .filter(|id| !gaps.contains_key(*id))
        .collect();
    let known: Vec<&str> = gate_failures
        .iter()
        .copied()
        .filter(|id| gaps.contains_key(*id))
        .collect();
    let stale: Vec<&str> = gaps
        .keys()
        .map(String::as_str)
        .filter(|id| stats.success.iter().any(|success| success.as_str() == *id))
        .collect();
    let gate_passed = stats
        .success
        .iter()
        .map(String::as_str)
        .filter(|id| in_gate(*id))
        .count();

    let mut failed_by_prefix: BTreeMap<&str, usize> = BTreeMap::new();
    for id in &stats.failed {
        *failed_by_prefix
            .entry(rule_prefix(id.as_str()))
            .or_insert(0) += 1;
    }

    println!(
        "go-ftw: run={} success={} failed={} skipped={}",
        stats.run,
        stats.success.len(),
        stats.failed.len(),
        stats.skipped.len()
    );
    println!(
        "gate: passed={} failed={} known-gap={} stale-gap={}",
        gate_passed,
        unknown.len(),
        known.len(),
        stale.len()
    );
    println!("failed by rule prefix: {failed_by_prefix:?}");
    for id in &unknown {
        eprintln!("GATE FAILURE {id}");
    }
    for id in &known {
        println!(
            "known gap {id}: {}",
            gaps.get(*id).map(String::as_str).unwrap_or("")
        );
    }
    for id in &stale {
        println!("stale known gap {id}: now passing, remove it from the list");
    }
    if gate_passed + gate_failures.len() == 0 {
        eprintln!("no gate tests ran");
        return ExitCode::FAILURE;
    }
    if unknown.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn load_gaps(path: &str) -> Result<HashMap<String, String>, std::io::Error> {
    let text = fs::read_to_string(path)?;
    let mut gaps = HashMap::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let Some(id) = parts.next() else {
            continue;
        };
        let reason = parts.next().unwrap_or("").trim().to_string();
        if reason.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("known gap at line {} has no reason", index + 1),
            ));
        }
        gaps.insert(id.to_string(), reason);
    }
    Ok(gaps)
}
```

- [ ] **Step 2: 创建已知差异清单**

创建 `scripts/ftw-known-gaps.txt`：

```
# Known go-ftw failures that are out of scope for the current iteration.
# Format: <ruleId-testId> <reason>
```

- [ ] **Step 3: 创建编排脚本**

创建 `scripts/ftw.sh`：

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
ROOT_WIN=$(cygpath -m "$ROOT" 2>/dev/null || printf '%s' "$ROOT")
cd "$ROOT"

MODE="${1:---gate}"
case "$MODE" in
    --full|--gate) ;;
    *)
        echo "usage: $0 [--full|--gate]" >&2
        exit 2
        ;;
esac

CRS_DIR="$ROOT/target/crs/coreruleset"
if [ ! -d "$CRS_DIR/.git" ]; then
    mkdir -p "$ROOT/target/crs"
    git clone --depth 1 https://github.com/coreruleset/coreruleset.git "$CRS_DIR"
fi
echo "CRS commit: $(git -C "$CRS_DIR" rev-parse --short HEAD)"

if [ -n "${FTW_BIN:-}" ]; then
    FTW="$FTW_BIN"
else
    GOBIN="$(go env GOPATH)/bin"
    if [ -x "$GOBIN/ftw" ]; then
        FTW="$GOBIN/ftw"
    elif [ -x "$GOBIN/ftw.exe" ]; then
        FTW="$GOBIN/ftw.exe"
    elif [ -x "$GOBIN/go-ftw" ]; then
        FTW="$GOBIN/go-ftw"
    elif [ -x "$GOBIN/go-ftw.exe" ]; then
        FTW="$GOBIN/go-ftw.exe"
    else
        go install github.com/coreruleset/go-ftw/v2@v2.6.1
        if [ -x "$GOBIN/go-ftw.exe" ]; then
            FTW="$GOBIN/go-ftw.exe"
        else
            FTW="$GOBIN/go-ftw"
        fi
    fi
fi

PROXY_PORT="${FTW_PROXY_PORT:-18080}"
ADMIN_PORT="${FTW_ADMIN_PORT:-18082}"
BACKEND_PORT="${FTW_BACKEND_PORT:-18081}"
WORK="$ROOT/target/ftw"
rm -rf "$WORK"
mkdir -p "$WORK"

cat > "$WORK/crs-test-setup.conf" <<'EOF'
SecAction "id:900005,\
  phase:1,\
  nolog,\
  pass,\
  ctl:ruleEngine=DetectionOnly,\
  ctl:ruleRemoveById=910000,\
  setvar:tx.blocking_paranoia_level=4,\
  setvar:tx.crs_validate_utf8_encoding=1,\
  setvar:tx.arg_name_length=100,\
  setvar:tx.arg_length=400,\
  setvar:tx.total_arg_length=64000,\
  setvar:tx.max_num_args=255,\
  setvar:tx.max_file_size=64100,\
  setvar:tx.combined_file_sizes=65535"

SecRule REQUEST_HEADERS:X-CRS-Test "@rx ^.*$" \
    "id:999999,phase:1,pass,log,msg:'X-CRS-Test %{MATCHED_VAR}',ctl:ruleRemoveById=1-999999"
EOF

cat > "$WORK/aegis-ftw.yaml" <<EOF
listen: "127.0.0.1:${PROXY_PORT}"

upstream:
  url: "http://127.0.0.1:${BACKEND_PORT}"
  host_header: preserve
  connect_timeout_ms: 3000
  total_timeout_ms: 30000

admin:
  listen: "127.0.0.1:${ADMIN_PORT}"
  token: null

rules:
  files:
    - "${ROOT_WIN}/target/crs/coreruleset/crs-setup.conf.example"
    - "${ROOT_WIN}/target/ftw/crs-test-setup.conf"
    - "${ROOT_WIN}/target/crs/coreruleset/rules/REQUEST-*.conf"
    - "${ROOT_WIN}/target/crs/coreruleset/rules/RESPONSE-*.conf"
  lenient: false

limits:
  max_header_bytes: 1048576
  max_uri_bytes: 65536
  max_body_bytes: 1048576
  max_response_body_bytes: 1048576
  response_body_limit_action: reject
  max_args: 10000
  max_multipart_parts: 1000
  max_multipart_part_headers: 64
  max_xml_depth: 64
  max_xml_values: 10000
  header_read_timeout_ms: 10000
  body_read_timeout_ms: 15000

on_error: block

audit:
  sink: file
  path: "${ROOT_WIN}/target/ftw/audit.jsonl"
  mode: all
  queue_capacity: 8192
  include_query: false
  matched_rules_limit: 256
EOF

cat > "$WORK/.ftw.yaml" <<EOF
logfile: "${ROOT_WIN}/target/ftw/audit.jsonl"
logmarkerheadername: X-CRS-Test
testoverride:
  input:
    dest_addr: "127.0.0.1"
    port: ${PROXY_PORT}
EOF

cargo build -p aegis-proxy --bin aegis-proxy
cargo build -p aegis-proxy --example ftw_backend

exe_path() {
    if [ -x "$1.exe" ]; then
        printf '%s.exe' "$1"
    else
        printf '%s' "$1"
    fi
}
BACKEND_BIN=$(exe_path "$ROOT/target/debug/examples/ftw_backend")
PROXY_BIN=$(exe_path "$ROOT/target/debug/aegis-proxy")

BACKEND_PID=""
PROXY_PID=""
cleanup() {
    if [ -n "$PROXY_PID" ]; then kill "$PROXY_PID" 2>/dev/null || true; fi
    if [ -n "$BACKEND_PID" ]; then kill "$BACKEND_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT

FTW_BACKEND_PORT="$BACKEND_PORT" "$BACKEND_BIN" >"$WORK/backend.log" 2>&1 &
BACKEND_PID=$!
"$PROXY_BIN" --config "$WORK/aegis-ftw.yaml" >"$WORK/proxy.log" 2>&1 &
PROXY_PID=$!

ready=0
for _ in $(seq 1 100); do
    if curl -fsS "http://127.0.0.1:${ADMIN_PORT}/healthz" >/dev/null 2>&1 \
        && curl -fsS "http://127.0.0.1:${BACKEND_PORT}/status/200" >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.1
done
if [ "$ready" -ne 1 ]; then
    echo "ftw services failed to become ready" >&2
    tail -n 40 "$WORK/proxy.log" >&2 || true
    tail -n 40 "$WORK/backend.log" >&2 || true
    exit 1
fi

FILTER=()
if [ -n "${FTW_INCLUDE:-}" ]; then
    FILTER+=(-i "$FTW_INCLUDE")
fi
if [ -n "${FTW_EXCLUDE:-}" ]; then
    FILTER+=(-e "$FTW_EXCLUDE")
fi

set +e
"$FTW" --config "$ROOT_WIN/target/ftw/.ftw.yaml" run \
    "${FILTER[@]}" \
    -d "$ROOT_WIN/target/crs/coreruleset/tests/regression/tests" \
    -o json \
    -f "$ROOT_WIN/target/ftw/report.json"
FTW_STATUS=$?
set -e

if [ ! -s "$WORK/report.json" ]; then
    echo "go-ftw produced no report (exit $FTW_STATUS)" >&2
    exit 1
fi

if [ "$MODE" = "--gate" ]; then
    cargo run -q -p aegis-proxy --example ftw_gate -- \
        "$ROOT_WIN/target/ftw/report.json" \
        "$ROOT_WIN/scripts/ftw-known-gaps.txt"
else
    echo "report: $WORK/report.json"
fi
```

- [ ] **Step 4: 赋予脚本执行权限并建立基线**

Run:

```bash
chmod +x scripts/ftw.sh
bash scripts/ftw.sh --full
```

Expected:
- 输出 `CRS commit: ...`
- 输出 `go-ftw: run=<N> success=<N> failed=<N> skipped=<N>`
- 生成 `target/ftw/report.json`
- 若个别用例失败，脚本仍以 0 退出（`--full` 不门禁）

记录首次基线数字，供 Task 10 写入文档。

- [ ] **Step 5: 运行门禁（此时可能失败，失败是预期输入）**

Run:

```bash
bash scripts/ftw.sh --gate
```

Expected: 若存在门禁失败，输出 `GATE FAILURE <id>` 与 `failed by rule prefix: {...}`，退出码 1。把输出保存到 `target/ftw/gate-failures.txt` 供 Task 9 分类。

- [ ] **Step 6: 提交**

```bash
cargo fmt
git add crates/aegis-proxy/examples/ftw_gate.rs scripts/ftw.sh scripts/ftw-known-gaps.txt
git commit -m "test: add go-ftw regression harness and gate"
```

---

### Task 9: 基线分类与门禁收敛

**Files:**
- Modify: `scripts/ftw-known-gaps.txt`
- Modify: 视失败原因而定：`crates/aegis-engine/src/*.rs`、`crates/aegis-proxy/src/*.rs`、`scripts/ftw.sh`、`target/ftw/crs-test-setup.conf`（由脚本生成，改脚本模板）

**Interfaces:**
- Consumes:
  - `target/ftw/report.json`
  - `target/ftw/gate-failures.txt`
  - `bash scripts/ftw.sh` 的 `FTW_INCLUDE` / `FTW_EXCLUDE`
- Produces:
  - 门禁目录内：要么测试通过，要么在 `scripts/ftw-known-gaps.txt` 中有具体原因
  - `bash scripts/ftw.sh --gate` 退出码 0

- [ ] **Step 1: 汇总失败分布**

Run:

```bash
set -o pipefail
bash scripts/ftw.sh --gate 2>&1 | tee target/ftw/gate-failures.txt
```

Expected: 输出 `failed by rule prefix: {...}`，列出每个规则目录的失败数量。若退出码为 0，直接跳到 Step 6。

- [ ] **Step 2: 单规则复现**

对每个门禁失败，使用规则 ID 前缀复跑（示例为 920100）：

```bash
FTW_INCLUDE='^920100-' bash scripts/ftw.sh --full
```

查看 `target/ftw/report.json` 中该测试的记录，以及 `target/ftw/audit.jsonl` 中对应请求的命中规则。

- [ ] **Step 3: 分类**

对每个失败按以下三类处理：

1. **引擎语义缺陷（本次范围内）**：规则可编译但匹配/动作/变量语义错误。按 TDD 修复：先在
   `crates/aegis-engine/src/eval.rs` 或 `variables/request.rs` 增加失败用例，再实现修复。
   提交信息示例：`fix(engine): match <behavior> for <variable>`。
2. **超出本次范围**：例如 hyper 层直接拒绝的原始 HTTP 测试、未实现的 XPath、PCRE
   lookaround。把 `<ruleId-testId>` 与具体原因追加到 `scripts/ftw-known-gaps.txt`。
3. **测试环境/脚本问题**：修 `scripts/ftw.sh`、`target/ftw` 生成配置或测试后端，不在
   引擎里绕过。

- [ ] **Step 4: 处理已知差异**

追加格式示例（每行一个，原因必须非空）：

```
920290-4 empty Host header is rejected by hyper before WAF evaluation
922130-1 raw multipart request is parsed by hyper before WAF evaluation
```

每次追加后重新运行：

```bash
bash scripts/ftw.sh --gate
```

Expected: 被加入清单的失败不再显示为 `GATE FAILURE`，改为 `known gap <id>: <reason>`。

- [ ] **Step 5: 收敛到门禁通过**

重复 Step 2-4，直到：

```bash
bash scripts/ftw.sh --gate
```

Expected: 退出码 0；输出中 `gate: passed=<N> failed=0 known-gap=<M> stale-gap=0`。

若某个门禁目录的失败数量超过 20 且原因集中在未实现的大型特性（如完整原始 HTTP 解析），
暂停并向用户汇报，不要自行扩大本次范围。

- [ ] **Step 6: 提交基线结果**

```bash
git add scripts/ftw-known-gaps.txt
# 若有引擎修复：
git add crates/aegis-engine/src crates/aegis-proxy/src
git commit -m "test: converge go-ftw gate baseline"
```

若本任务产生了多个独立的引擎修复，按修复逐条提交，提交信息使用
`fix(engine): ...`，最后再提交 known-gaps 清单。

---

### Task 10: 文档与最终验证

**Files:**
- Create: `docs/ftw.md`
- Modify: `README.md:5-24,101-114,115-122`
- Modify: `docs/compatibility.md:6-14,44-93,118-133`
- Modify: `docs/benchmarks.md`（在末尾追加 go-ftw 基线小节）

**Interfaces:**
- Consumes: Task 8/9 的基线数字与门禁结果
- Produces: 文档与最终验证记录

- [ ] **Step 1: 编写 docs/ftw.md**

创建 `docs/ftw.md`：

```markdown
# go-ftw 回归测试

本仓库使用 OWASP CRS 官方 go-ftw 回归套件验证规则语义。

## 前置条件

- Go 1.21+，且 `GOPROXY` 可访问（脚本使用 `go install` 安装 go-ftw v2.6.1）
- CRS 源码位于 `target/crs/coreruleset`（不存在时脚本自动浅克隆）
- `curl` 可用

## 运行

全量基线（不门禁）：

```bash
bash scripts/ftw.sh --full
```

门禁检查（默认模式）：

```bash
bash scripts/ftw.sh --gate
```

产物：

- `target/ftw/report.json`：go-ftw JSON 报告
- `target/ftw/audit.jsonl`：WAF 审计日志（go-ftw 读取该文件）
- `target/ftw/proxy.log`、`target/ftw/backend.log`

## 门禁目录

`REQUEST-911`、`REQUEST-913`、`REQUEST-920`、`REQUEST-921`、`REQUEST-930`、
`REQUEST-931`、`REQUEST-932`、`REQUEST-933`、`REQUEST-941`、`REQUEST-942`、
`REQUEST-943`、`REQUEST-949`。

其余目录只进入基线报告，不参与门禁。

## 已知差异

`scripts/ftw-known-gaps.txt` 每行格式：

```
<ruleId-testId> <reason>
```

`#` 开头为注释。门禁通过的条件是：门禁目录内每个失败用例都在清单中。
清单中已通过的用例会输出 `stale known gap` 警告，应删除。

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `FTW_BIN` | 自动查找 | go-ftw 可执行文件路径 |
| `FTW_PROXY_PORT` | 18080 | aegis 代理端口 |
| `FTW_ADMIN_PORT` | 18082 | 管理面端口 |
| `FTW_BACKEND_PORT` | 18081 | 测试后端端口 |
| `FTW_INCLUDE` | 空 | go-ftw `-i` 正则，只跑匹配的测试 |
| `FTW_EXCLUDE` | 空 | go-ftw `-e` 正则，排除匹配的测试 |

## 限制

- marker 机制依赖 `X-CRS-Test` 头与审计日志中的 `matched_rules[].id`
- hyper 在 WAF 之前拒绝的原始 HTTP 请求无法产生审计事件，相关用例列入已知差异
- 已知差异不是通过标准；新增条目必须写明原因
```

- [ ] **Step 2: 更新 README**

把 README 的“能力”列表中加入：

```markdown
- 响应体检测覆盖 chunked、gzip/deflate/br 压缩内容与超限拒绝策略
- 请求解析结构上限（参数、multipart part/头、XML 深度/值数量）
- go-ftw 回归套件门禁（核心规则目录）
```

把“已知限制”中的：

```markdown
- 响应体检测仅限已知 `Content-Length` 且不超过上限；chunked/超大响应只做响应头检测
```

替换为：

```markdown
- `text/event-stream` 响应不缓冲、不检测
- 请求体压缩内容不解码；未知响应编码按原始字节检测
- 响应体超过上限时默认返回 502，可用 `limits.response_body_limit_action: pass` 放行
```

在“文档”列表中加入：

```markdown
- [go-ftw 回归测试](docs/ftw.md)
```

- [ ] **Step 3: 更新兼容性报告**

在 `docs/compatibility.md` 的“结论”中写入 Task 8/9 的基线数字（示例格式，使用实际结果替换）：

```markdown
go-ftw 全量基线：运行 <N> 个测试，通过 <N>，失败 <N>，跳过 <N>。
门禁目录通过率：<N>/<N>（已知差异 <M> 条，均记录在 `scripts/ftw-known-gaps.txt`）。
```

在“语义说明”中加入：

```markdown
- 响应体检测不再要求 `Content-Length`；chunked 响应会被缓冲检测。
- `gzip` / `x-gzip` / `deflate` / `br` 响应按解码后内容检测，转发保持原始编码。
- 响应体超过 `max_response_body_bytes` 时默认 502；`pass` 模式流式透传且不检测。
- URL-encoded 参数、multipart part/头、XML 深度/值数量超过结构上限时返回 413。
```

在“已知不兼容”中加入：

```markdown
- `text/event-stream` 响应不检测
- 请求体压缩内容不解码
- 未知 `Content-Encoding` 按原始字节检测
```

- [ ] **Step 4: 追加基准记录**

在 `docs/benchmarks.md` 末尾追加：

```markdown
## 18. go-ftw 回归基线（2026-10-24）

- CRS commit：`<实际 commit>`
- go-ftw：v2.6.1
- 全量：run=<N> success=<N> failed=<N> skipped=<N>
- 门禁目录：passed=<N> failed=0 known-gap=<M>
- 报告：`target/ftw/report.json`
```

使用 Task 8/9 的实际数字替换占位符。

- [ ] **Step 5: 最终验证**

Run:

```bash
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p aegis-proxy -- --config config.example.yaml --check
bash scripts/ftw.sh --gate
```

Expected:
- `cargo fmt --check` 无输出
- 所有测试 PASS
- clippy 无 warning
- `configuration OK: 2 rule file(s)`
- go-ftw 门禁退出码 0

- [ ] **Step 6: 提交文档**

```bash
cargo fmt
git add README.md docs/ftw.md docs/compatibility.md docs/benchmarks.md
git commit -m "docs: document go-ftw regression and response hardening"
```

---

## 计划自检

- [x] spec §2.1 验收方式 → Task 8 + Task 9
- [x] spec §2.2 组件 → Task 7 + Task 8
- [x] spec §2.3 测试后端 → Task 7
- [x] spec §2.4 运行流程 → Task 8
- [x] spec §2.5 marker 与 `ruleRemoveById` 范围 → Task 1 + Task 8
- [x] spec §2.6 门禁检查 → Task 8
- [x] spec §3 响应体检测 → Task 5
- [x] spec §3.2 压缩解码 → Task 6
- [x] spec §4 解析结构上限 → Task 2 + Task 3 + Task 4
- [x] spec §5 错误处理 → Task 4 + Task 5 + Task 6
- [x] spec §6 测试 → 每个任务的测试步骤
- [x] spec §7 文档 → Task 10
- [x] spec §8 不在范围 → Global Constraints 与 Task 9 Step 5
- [x] spec §9 风险 → Task 8/9 的基线与已知差异流程


