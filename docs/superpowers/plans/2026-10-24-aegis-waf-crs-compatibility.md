# aegis-waf CRS Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 补齐 OWASP CRS 剩余可编译能力与关键运行时语义，并把 `@validateByteRange` 的反向实现修正为 ModSecurity 语义。

**Architecture:** 先把变量抽取从“值数组”重构为带名称的 `VariableEntry`，引入 `Selector`（字面量/正则）、`&` 计数、完整 `MATCHED_VARS`；再扩展请求体处理器、multipart part 头、`UNIQUE_ID`、校验算子、`multiMatch` 与 `ctl`。所有新语义都在现有同步引擎内实现，不改变代理请求路径结构。

**Tech Stack:** Rust edition 2021、regex 1、tokio/hyper（已有）、http、form_urlencoded、roxmltree、tempfile（测试）。

**Spec:** `docs/superpowers/specs/2026-10-24-aegis-waf-crs-compatibility-design.md`

## Global Constraints

- 工作目录：`D:\rust_code\aegis-waf`；所有命令默认在此目录执行。
- Rust edition 2021；不使用 nightly 特性。
- 两个 crate 均保持 `#![forbid(unsafe_code)]`。
- 生产代码禁止 `unwrap()` / `expect()`（测试代码可用）。
- 每个任务结束前执行 `cargo fmt --all`、`cargo test -p aegis-engine`（涉及代理时再加 `-p aegis-proxy`），并提交一次。
- **提交信息不得包含任何 AI 署名或 AI 生成内容**（用户明确要求），例如不得出现 `Co-Authored-By: Claude`、`Generated with Claude Code` 等。
- 代码注释和标识符使用英文；文档与提交信息可使用中文。
- `validate*` 系列算子的语义固定为“校验失败时匹配”，不得再写成“全部合法时匹配”。

## File Map

| 文件 | 责任 |
|---|---|
| `crates/aegis-engine/src/model.rs` | `Selector`、`Variable`、`VariableEntry` 相关模型、`CtlAction`、`BodyProcessor` |
| `crates/aegis-engine/src/compile.rs` | 变量/选择器/`&` 解析、新算子与新动作编译、target 解析 |
| `crates/aegis-engine/src/variables/request.rs` | 命名变量抽取、体处理器、multipart 头、MATCHED_VARS |
| `crates/aegis-engine/src/variables/tx.rs` | TX 迭代（已有 `iter()`，无需改动） |
| `crates/aegis-engine/src/operators.rs` | 校验算子与 `ByteRange` 语义修正 |
| `crates/aegis-engine/src/eval.rs` | 命中列表、按项取反、`multiMatch`、target 排除、ctl |
| `crates/aegis-engine/src/lib.rs` | 导出新类型 |
| `crates/aegis-engine/tests/compile_conformance.rs` | 编译一致性测试 |
| `crates/aegis-engine/tests/engine_conformance.rs` | 端到端引擎测试 |
| `crates/aegis-proxy/src/proxy/mod.rs` | `UNIQUE_ID` 接线 |
| `crates/aegis-proxy/tests/*` | 代理回归测试（如需） |
| `docs/benchmarks.md` | CRS 覆盖率与新增能力记录 |
| `docs/compatibility.md` | 支持矩阵与语义说明 |
| `README.md` | 能力列表与限制 |

---

## Task 1: Named Variable Entries, Selector, and Item Negation

**Files:**
- Modify: `crates/aegis-engine/src/model.rs`
- Modify: `crates/aegis-engine/src/compile.rs`
- Modify: `crates/aegis-engine/src/variables/request.rs`
- Modify: `crates/aegis-engine/src/eval.rs`
- Modify: `crates/aegis-engine/src/lib.rs`
- Test: inline `#[cfg(test)]` modules in `request.rs` and `eval.rs`

**Interfaces:**
- Produces: `model::Selector::Literal(String)`、`Selector::matches(&str) -> bool`、`Variable::selector() -> Option<&Selector>`、`Variable::same_family(&Variable) -> bool`。
- Produces: `request::VariableEntry { name: String, key: Option<String>, value: String }`。
- Produces: `RequestContext::extract(&Variable) -> Arc<Vec<VariableEntry>>`。
- Produces: `EvaluationState::entry_excluded(&CompiledRule, &VariableSpec, &VariableEntry) -> bool`（私有）。
- Consumes: 现有 parser/compile 输出。

- [ ] **Step 1: Write the failing extraction tests**

在 `crates/aegis-engine/src/variables/request.rs` 的 `mod tests` 中，把现有 helper：

```rust
    fn extract(context: &RequestContext, variable: Variable) -> Vec<String> {
        context.extract(&variable).iter().cloned().collect()
    }
```

替换为：

```rust
    fn extract(context: &RequestContext, variable: Variable) -> Vec<String> {
        context
            .extract(&variable)
            .iter()
            .map(|entry| entry.value.clone())
            .collect()
    }
```

并新增测试：

```rust
    #[test]
    fn entries_carry_precise_names_and_keys() {
        let headers = header_map(&[]);
        let context = context(&headers);
        let entries = context.extract(&Variable::Args(None));
        assert_eq!(entries[0].name, "ARGS:q");
        assert_eq!(entries[0].key.as_deref(), Some("q"));
        let names = context.extract(&Variable::ArgsNames);
        assert_eq!(names[0].name, "ARGS_NAMES:q");
        assert_eq!(names[0].value, "q");
    }
```

在 `crates/aegis-engine/src/eval.rs` 的 `mod tests` 中新增：

```rust
    #[test]
    fn negated_targets_exclude_items_by_name() {
        let rules = load(r#"SecRule ARGS|!ARGS:allow "@contains attack" "id:4101,phase:1,deny""#);
        let blocked = eval(&rules, "GET", "/?allow=attack", &[], b"");
        assert_eq!(blocked.decision, Decision::Pass);
        let still_blocked = eval(&rules, "GET", "/?allow=attack&other=attack", &[], b"");
        assert!(matches!(
            still_blocked.decision,
            Decision::Block {
                rule_id: 4101,
                ..
            }
        ));
    }

    #[test]
    fn matched_var_name_uses_collection_key() {
        let rules = load(
            r#"
SecRule ARGS "@contains attack" "id:4201,phase:1,pass,setvar:tx.seen=%{MATCHED_VAR_NAME}"
SecRule TX:SEEN "@contains ARGS:q" "id:4202,phase:1,deny,status:403"
"#,
        );
        let evaluation = eval(&rules, "GET", "/?q=attack", &[], b"");
        assert!(matches!(
            evaluation.decision,
            Decision::Block {
                rule_id: 4202,
                ..
            }
        ));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aegis-engine entries_carry_precise_names negated_targets_exclude_items_by_name`

Expected: compile error because `VariableEntry` / `.name` do not exist.

- [ ] **Step 3: Add `Selector`, update `Variable`, and add helpers in `model.rs`**

在 `use` 区域之后加入：

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Selector {
    Literal(String),
}

impl Selector {
    pub fn matches(&self, key: &str) -> bool {
        match self {
            Self::Literal(value) => value.eq_ignore_ascii_case(key),
        }
    }

    pub fn as_display(&self) -> String {
        match self {
            Self::Literal(value) => value.clone(),
        }
    }
}

fn selected(prefix: &str, selector: &Option<Selector>) -> String {
    match selector {
        Some(selector) => format!("{prefix}:{}", selector.as_display()),
        None => prefix.to_string(),
    }
}
```

把 `Variable` 中所有 `Option<String>` 选择器改为 `Option<Selector>`，并把 `MatchedVars` 改为带选择器：

```rust
    RequestHeaders(Option<Selector>),
    Args(Option<Selector>),
    ArgsGet(Option<Selector>),
    ArgsPost(Option<Selector>),
    RequestCookies(Option<Selector>),
    Ip(Option<Selector>),
    Session(Option<Selector>),
    User(Option<Selector>),
    Global(Option<Selector>),
    MatchedVars(Option<Selector>),
    Xml(Option<Selector>),
    ResponseHeaders(Option<Selector>),
    Tx(Option<Selector>),
```

把 `display_name` 中的选择器分支替换为：

```rust
            Self::RequestHeaders(selector) => selected("REQUEST_HEADERS", selector),
            ...
            Self::Args(selector) => selected("ARGS", selector),
            Self::ArgsGet(selector) => selected("ARGS_GET", selector),
            Self::ArgsPost(selector) => selected("ARGS_POST", selector),
            Self::RequestCookies(selector) => selected("REQUEST_COOKIES", selector),
            Self::Ip(selector) => selected("IP", selector),
            Self::Session(selector) => selected("SESSION", selector),
            Self::User(selector) => selected("USER", selector),
            Self::Global(selector) => selected("GLOBAL", selector),
            Self::MatchedVars(selector) => selected("MATCHED_VARS", selector),
            Self::Xml(selector) => selected("XML", selector),
            Self::ResponseHeaders(selector) => selected("RESPONSE_HEADERS", selector),
            Self::Tx(selector) => selected("TX", selector),
```

在 `impl Variable` 末尾加入：

```rust
    pub fn selector(&self) -> Option<&Selector> {
        match self {
            Self::RequestHeaders(selector)
            | Self::Args(selector)
            | Self::ArgsGet(selector)
            | Self::ArgsPost(selector)
            | Self::RequestCookies(selector)
            | Self::Ip(selector)
            | Self::Session(selector)
            | Self::User(selector)
            | Self::Global(selector)
            | Self::MatchedVars(selector)
            | Self::Xml(selector)
            | Self::ResponseHeaders(selector)
            | Self::Tx(selector) => selector.as_ref(),
            _ => None,
        }
    }

    pub fn same_family(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
```

- [ ] **Step 4: Add `VariableEntry` and rewrite extraction in `variables/request.rs`**

在 `RequestView` 之后加入：

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableEntry {
    pub name: String,
    pub key: Option<String>,
    pub value: String,
}

impl VariableEntry {
    fn scalar(variable: &Variable, value: String) -> Self {
        Self {
            name: variable.display_name(),
            key: None,
            value,
        }
    }

    fn item(prefix: &str, key: &str, value: String) -> Self {
        Self {
            name: format!("{prefix}:{key}"),
            key: Some(key.to_string()),
            value,
        }
    }
}
```

把 `use crate::model::{PrefilterScope, Variable};` 改为：

```rust
use crate::model::{PrefilterScope, Selector, Variable};
```

把 `cache` 字段类型改为：

```rust
    cache: RefCell<HashMap<Variable, Arc<Vec<VariableEntry>>>>,
```

把 `extract` 与 `compute` 整体替换为：

```rust
    pub fn extract(&self, variable: &Variable) -> Arc<Vec<VariableEntry>> {
        let cacheable = !matches!(
            variable,
            Variable::Tx(_)
                | Variable::MatchedVar
                | Variable::MatchedVarName
                | Variable::MatchedVars(_)
                | Variable::Ip(_)
                | Variable::Session(_)
                | Variable::User(_)
                | Variable::Global(_)
        );
        if cacheable {
            if let Some(values) = self.cache.borrow().get(variable) {
                return values.clone();
            }
        }
        let values = Arc::new(self.compute(variable));
        if cacheable {
            self.cache
                .borrow_mut()
                .insert(variable.clone(), values.clone());
        }
        values
    }

    fn compute(&self, variable: &Variable) -> Vec<VariableEntry> {
        match variable {
            Variable::RequestUri | Variable::RequestUriRaw => {
                vec![VariableEntry::scalar(variable, self.uri.clone())]
            }
            Variable::RequestLine => vec![VariableEntry::scalar(
                variable,
                format!("{} {} {}", self.method, self.uri, self.protocol),
            )],
            Variable::RequestProtocol => {
                vec![VariableEntry::scalar(variable, self.protocol.clone())]
            }
            Variable::RequestBasename => vec![VariableEntry::scalar(
                variable,
                self.path
                    .rsplit('/')
                    .find(|segment| !segment.is_empty())
                    .unwrap_or("")
                    .to_string(),
            )],
            Variable::RequestMethod => vec![VariableEntry::scalar(variable, self.method.clone())],
            Variable::QueryString => vec![VariableEntry::scalar(
                variable,
                self.query.clone().unwrap_or_default(),
            )],
            Variable::RequestFilename => vec![VariableEntry::scalar(variable, self.path.clone())],
            Variable::RequestHeaders(selector) => self
                .headers
                .iter()
                .filter(|(name, _)| name_matches(selector, name))
                .map(|(name, value)| VariableEntry::item("REQUEST_HEADERS", name, value.clone()))
                .collect(),
            Variable::RequestHeadersNames => unique_names(&self.headers)
                .into_iter()
                .map(|name| VariableEntry::item("REQUEST_HEADERS_NAMES", &name, name.clone()))
                .collect(),
            Variable::Args(selector) => self
                .query_pairs
                .iter()
                .chain(self.body_pairs.iter())
                .filter(|(name, _)| name_matches(selector, name))
                .map(|(name, value)| VariableEntry::item("ARGS", name, value.clone()))
                .collect(),
            Variable::ArgsGet(selector) => self
                .query_pairs
                .iter()
                .filter(|(name, _)| name_matches(selector, name))
                .map(|(name, value)| VariableEntry::item("ARGS_GET", name, value.clone()))
                .collect(),
            Variable::ArgsPost(selector) => self
                .body_pairs
                .iter()
                .filter(|(name, _)| name_matches(selector, name))
                .map(|(name, value)| VariableEntry::item("ARGS_POST", name, value.clone()))
                .collect(),
            Variable::ArgsNames => self
                .query_pairs
                .iter()
                .chain(self.body_pairs.iter())
                .map(|(name, _)| VariableEntry::item("ARGS_NAMES", name, name.clone()))
                .collect(),
            Variable::RequestCookies(selector) => self
                .cookies
                .iter()
                .filter(|(name, _)| name_matches(selector, name))
                .map(|(name, value)| VariableEntry::item("REQUEST_COOKIES", name, value.clone()))
                .collect(),
            Variable::RequestCookiesNames => unique_names(&self.cookies)
                .into_iter()
                .map(|name| VariableEntry::item("REQUEST_COOKIES_NAMES", &name, name.clone()))
                .collect(),
            Variable::RequestBody => vec![VariableEntry::scalar(variable, self.body_text.clone())],
            Variable::RequestBodyLength => {
                vec![VariableEntry::scalar(variable, self.body_len.to_string())]
            }
            Variable::Files => self
                .multipart_parts
                .iter()
                .filter(|part| part.filename.is_some())
                .map(|part| {
                    VariableEntry::item(
                        "FILES",
                        &part.name,
                        String::from_utf8_lossy(&part.data).into_owned(),
                    )
                })
                .collect(),
            Variable::FilesNames => self
                .multipart_parts
                .iter()
                .filter(|part| part.filename.is_some())
                .map(|part| VariableEntry::item("FILES_NAMES", &part.name, part.name.clone()))
                .collect(),
            Variable::FilesSizes => self
                .multipart_parts
                .iter()
                .filter(|part| part.filename.is_some())
                .map(|part| {
                    VariableEntry::item("FILES_SIZES", &part.name, part.data.len().to_string())
                })
                .collect(),
            Variable::FilesCombinedSize => vec![VariableEntry::scalar(
                variable,
                self.multipart_parts
                    .iter()
                    .filter(|part| part.filename.is_some())
                    .map(|part| part.data.len())
                    .sum::<usize>()
                    .to_string(),
            )],
            Variable::FilesTmpnames => Vec::new(),
            Variable::Ip(selector) => collection_entries(self, "ip", "IP", selector),
            Variable::Session(selector) => collection_entries(self, "session", "SESSION", selector),
            Variable::User(selector) => collection_entries(self, "user", "USER", selector),
            Variable::Global(selector) => collection_entries(self, "global", "GLOBAL", selector),
            Variable::RemoteAddr => {
                vec![VariableEntry::scalar(variable, self.remote_addr.to_string())]
            }
            Variable::MatchedVar => self
                .tx
                .get("matched_var")
                .map(|value| vec![VariableEntry::scalar(variable, value.to_string())])
                .unwrap_or_default(),
            Variable::MatchedVarName => self
                .tx
                .get("matched_var_name")
                .map(|value| vec![VariableEntry::scalar(variable, value.to_string())])
                .unwrap_or_default(),
            Variable::MatchedVars(_) => self
                .tx
                .get("matched_var_name")
                .map(|value| vec![VariableEntry::scalar(variable, value.to_string())])
                .unwrap_or_default(),
            Variable::Xml(_) => self
                .xml_values
                .iter()
                .map(|value| VariableEntry::scalar(variable, value.clone()))
                .collect(),
            Variable::ResponseStatus => self
                .response_status
                .map(|status| vec![VariableEntry::scalar(variable, status.to_string())])
                .unwrap_or_default(),
            Variable::ResponseHeaders(selector) => self
                .response_headers
                .iter()
                .filter(|(name, _)| name_matches(selector, name))
                .map(|(name, value)| VariableEntry::item("RESPONSE_HEADERS", name, value.clone()))
                .collect(),
            Variable::ResponseHeadersNames => unique_names(&self.response_headers)
                .into_iter()
                .map(|name| VariableEntry::item("RESPONSE_HEADERS_NAMES", &name, name.clone()))
                .collect(),
            Variable::ResponseBody => vec![VariableEntry::scalar(
                variable,
                self.response_body_text.clone(),
            )],
            Variable::ResponseBodyLength => vec![VariableEntry::scalar(
                variable,
                self.response_body_len.to_string(),
            )],
            Variable::ResponseContentType => self
                .response_content_type
                .clone()
                .map(|value| vec![VariableEntry::scalar(variable, value)])
                .unwrap_or_default(),
            Variable::Tx(selector) => self
                .tx
                .iter()
                .filter(|(name, _)| name_matches(selector, name))
                .map(|(name, value)| VariableEntry::item("TX", name, value.to_string()))
                .collect(),
        }
    }
```

把 `collection_values` 替换为：

```rust
fn collection_entries(
    context: &RequestContext,
    collection: &str,
    prefix: &str,
    selector: &Option<Selector>,
) -> Vec<VariableEntry> {
    context
        .collection_entries(collection)
        .into_iter()
        .filter(|(name, _)| name_matches(selector, name))
        .map(|(name, value)| VariableEntry::item(prefix, &name, value))
        .collect()
}

fn name_matches(selector: &Option<Selector>, name: &str) -> bool {
    selector
        .as_ref()
        .map(|selector| selector.matches(name))
        .unwrap_or(true)
}
```

- [ ] **Step 5: Update eval matching**

在 `eval.rs` 顶部 `use crate::model::{...}` 中加入 `VariableEntry, VariableSpec`：

```rust
use crate::model::{
    CompiledOperator, CompiledRule, CompiledRules, CtlAction, Disruptive, Phase, Prefilter,
    PrefilterHits, PrefilterVariant, RuleEngineMode, RuleGroup, SetVar, SetVarOp, SetVarScope,
    VariableEntry, VariableSpec,
};
```

把 `rule_matches` 替换为：

```rust
    fn rule_matches(&self, rule: &CompiledRule) -> Option<RuleHit> {
        if rule.unconditional {
            return Some(RuleHit {
                value: String::new(),
                variable_name: String::new(),
                captures: Vec::new(),
            });
        }
        for spec in rule.variables.iter().filter(|spec| !spec.negated) {
            let entries = self.context.extract(&spec.variable);
            for entry in entries.iter() {
                if self.entry_excluded(rule, spec, entry) {
                    continue;
                }
                let matched_value;
                let matched = if rule.transformations.is_empty() {
                    matched_value = entry.value.clone();
                    rule.operator.matches(&entry.value)
                } else {
                    let mut current = entry.value.clone();
                    let mut next = String::new();
                    for transform in &rule.transformations {
                        let result = transform.apply(&current);
                        next.clear();
                        next.push_str(&result);
                        std::mem::swap(&mut current, &mut next);
                    }
                    matched_value = current.clone();
                    rule.operator.matches(&current)
                };
                let matched = if rule.operator_negated {
                    !matched
                } else {
                    matched
                };
                if matched {
                    let captures = if rule.actions.capture {
                        capture_values(&rule.operator, &matched_value, rule.operator_negated)
                    } else {
                        Vec::new()
                    };
                    return Some(RuleHit {
                        value: matched_value,
                        variable_name: entry.name.clone(),
                        captures,
                    });
                }
            }
        }
        None
    }

    fn entry_excluded(
        &self,
        rule: &CompiledRule,
        spec: &VariableSpec,
        entry: &VariableEntry,
    ) -> bool {
        rule.variables.iter().filter(|spec| spec.negated).any(|negated| {
            negated.variable.same_family(&spec.variable)
                && match negated.variable.selector() {
                    None => true,
                    Some(selector) => entry
                        .key
                        .as_deref()
                        .map(|key| selector.matches(key))
                        .unwrap_or(false),
                }
        })
    }
```

- [ ] **Step 6: Fix compile-time construction of selectors**

在 `compile.rs` 的 `use crate::model::{...}` 中加入 `Selector`。

在 `parse_variables` 中，把：

```rust
        let (name, selector) = match item.split_once(':') {
            Some((name, selector)) => (name, Some(selector.to_string())),
            None => (item, None),
        };
```

改为：

```rust
        let (name, selector) = match item.split_once(':') {
            Some((name, selector)) => (name, Some(Selector::Literal(selector.to_string()))),
            None => (item, None),
        };
```

把 `IP`/`SESSION`/`USER`/`GLOBAL`/`TX` 分支改为：

```rust
            "IP" => Variable::Ip(selector.map(lower_selector)),
            "SESSION" => Variable::Session(selector.map(lower_selector)),
            "USER" => Variable::User(selector.map(lower_selector)),
            "GLOBAL" => Variable::Global(selector.map(lower_selector)),
            ...
            "MATCHED_VARS" => Variable::MatchedVars(selector),
            ...
            "TX" => Variable::Tx(selector.map(lower_selector)),
```

并加入 helper：

```rust
fn lower_selector(selector: Selector) -> Selector {
    match selector {
        Selector::Literal(value) => Selector::Literal(value.to_ascii_lowercase()),
    }
}
```

- [ ] **Step 7: Export `Selector` from `lib.rs`**

把 `pub use` 行扩展为：

```rust
pub use model::Selector;
```

- [ ] **Step 8: Run the tests**

Run: `cargo test -p aegis-engine`

Expected: 所有测试通过；新增 2 个测试通过。

把 `request.rs` 内联测试中所有直接构造字符串选择器的 `Variable` 改为 `Selector::Literal`。需要修改的调用点（逐一替换）：

```rust
Variable::RequestHeaders(Some(Selector::Literal("X-TEST".into())))
Variable::RequestCookies(Some(Selector::Literal("session".into())))
Variable::ArgsGet(Some(Selector::Literal("q".into())))
Variable::ArgsPost(Some(Selector::Literal("x".into())))
Variable::Args(Some(Selector::Literal("x".into())))
Variable::Xml(Some(Selector::Literal("/*".into())))
```

- [ ] **Step 9: Format and commit**

```bash
cargo fmt --all
cargo test -p aegis-engine
git add crates/aegis-engine
git commit -m "refactor: extract named variable entries and exclude items by name"
```

---

## Task 2: Regular-Expression Selectors

**Files:**
- Modify: `crates/aegis-engine/src/model.rs`
- Modify: `crates/aegis-engine/src/compile.rs`
- Modify: `crates/aegis-engine/src/variables/request.rs`（仅新增内联测试）
- Test: `crates/aegis-engine/tests/compile_conformance.rs`

**Interfaces:**
- Produces: `Selector::Regex(RegexSelector)`、`RegexSelector::new(&str) -> Result<RegexSelector, regex::Error>`、`RegexSelector::is_match(&str) -> bool`。
- Consumes: Task 1 的 `Selector`/`VariableEntry`。

- [ ] **Step 1: Write the failing selector tests**

在 `crates/aegis-engine/tests/compile_conformance.rs` 新增：

```rust
#[test]
fn compiles_regex_selectors() {
    let rules = load(
        r#"SecRule REQUEST_COOKIES:/^_ga/ "@contains x" "id:1,phase:1,pass""#,
    )
    .unwrap();
    let RuleGroup::Single(rule) = &rules.phase1[0] else {
        panic!("expected single rule");
    };
    assert!(matches!(
        rule.variables[0].variable,
        Variable::RequestCookies(Some(Selector::Regex(_)))
    ));
}

#[test]
fn rejects_invalid_selector_regex() {
    let error =
        load(r#"SecRule REQUEST_COOKIES:/(/ "@contains x" "id:1,phase:1,deny""#).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("rules.conf:1:1"), "unexpected message: {message}");
    assert!(
        message.contains("invalid selector regex"),
        "unexpected message: {message}"
    );
}
```

在 `request.rs` 的 `mod tests` 新增（并在该测试模块的 `use` 中加入 `use crate::model::RegexSelector;`）：

```rust
    #[test]
    fn regex_selector_filters_cookie_names() {
        let headers = header_map(&[("cookie", "_ga=1; session=abc; _gid=2")]);
        let context = context(&headers);
        let selector = Selector::Regex(RegexSelector::new("^_ga").unwrap());
        let entries = context.extract(&Variable::RequestCookies(Some(selector)));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key.as_deref(), Some("_ga"));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aegis-engine --test compile_conformance compiles_regex_selectors`

Expected: compile error because `Selector::Regex` / `RegexSelector` do not exist.

- [ ] **Step 3: Extend `Selector` in `model.rs`**

把 Task 1 的 `Selector` 定义替换为：

```rust
#[derive(Debug, Clone)]
pub struct RegexSelector {
    pattern: String,
    regex: regex::Regex,
}

impl RegexSelector {
    pub fn new(pattern: &str) -> Result<Self, regex::Error> {
        Ok(Self {
            pattern: pattern.to_string(),
            regex: regex::Regex::new(pattern)?,
        })
    }

    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    pub fn is_match(&self, key: &str) -> bool {
        self.regex.is_match(key)
    }
}

impl PartialEq for RegexSelector {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for RegexSelector {}

impl std::hash::Hash for RegexSelector {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.pattern.hash(state);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Selector {
    Literal(String),
    Regex(RegexSelector),
}

impl Selector {
    pub fn matches(&self, key: &str) -> bool {
        match self {
            Self::Literal(value) => value.eq_ignore_ascii_case(key),
            Self::Regex(regex) => regex.is_match(key),
        }
    }

    pub fn as_display(&self) -> String {
        match self {
            Self::Literal(value) => value.clone(),
            Self::Regex(regex) => format!("/{}/", regex.pattern()),
        }
    }
}
```

- [ ] **Step 4: Parse regex selectors in `compile.rs`**

把 Task 1 中直接构造 `Selector::Literal` 的代码改为：

```rust
        let (name, selector) = match item.split_once(':') {
            Some((name, selector)) => {
                let selector = parse_selector(selector)
                    .map_err(|message| compile_error(file, line, column, message))?;
                (name, Some(selector))
            }
            None => (item, None),
        };
```

加入：

```rust
fn parse_selector(raw: &str) -> Result<Selector, String> {
    if raw.len() >= 2 && raw.starts_with('/') && raw.ends_with('/') {
        let pattern = &raw[1..raw.len() - 1];
        crate::model::RegexSelector::new(pattern)
            .map(Selector::Regex)
            .map_err(|error| format!("invalid selector regex: {error}"))
    } else {
        Ok(Selector::Literal(raw.to_string()))
    }
}
```

把 `lower_selector` 扩展为保留正则：

```rust
fn lower_selector(selector: Selector) -> Selector {
    match selector {
        Selector::Literal(value) => Selector::Literal(value.to_ascii_lowercase()),
        Selector::Regex(regex) => Selector::Regex(regex),
    }
}
```

- [ ] **Step 5: Disable prefilter for regex selectors**

在 `compile.rs` 的 `variable_prefilter_scope` 开头加入：

```rust
    if matches!(variable.selector(), Some(Selector::Regex(_))) {
        return None;
    }
```

- [ ] **Step 6: Update the compile test imports**

在 `crates/aegis-engine/tests/compile_conformance.rs` 顶部加入：

```rust
use aegis_engine::model::Selector;
```

- [ ] **Step 7: Run the tests**

Run: `cargo test -p aegis-engine`

Expected: 全部通过，新增 3 个测试通过。

- [ ] **Step 8: Format and commit**

```bash
cargo fmt --all
cargo test -p aegis-engine
git add crates/aegis-engine
git commit -m "feat: support regex variable selectors"
```

---

## Task 3: Count Variables and Full MATCHED_VARS

**Files:**
- Modify: `crates/aegis-engine/src/model.rs`
- Modify: `crates/aegis-engine/src/compile.rs`
- Modify: `crates/aegis-engine/src/variables/request.rs`
- Modify: `crates/aegis-engine/src/eval.rs`
- Test: inline tests + `crates/aegis-engine/tests/compile_conformance.rs`

**Interfaces:**
- Produces: `Variable::Count(Box<Variable>)`；`&VAR[:selector]` 编译为计数变量。
- Produces: `RequestContext::record_match(&mut self, name: &str, key: Option<&str>, value: &str)`。
- Produces: `RuleHit` 新增 `key: Option<String>`（`eval.rs` 私有）。
- Consumes: Task 1/2 的 `VariableEntry`/`Selector`。

- [ ] **Step 1: Write the failing count and MATCHED_VARS tests**

在 `eval.rs` 的 `mod tests` 中，把现有 `matched_vars_is_available_to_later_rules` 替换为：

```rust
    #[test]
    fn matched_vars_contains_matched_values() {
        let rules = load(
            r#"
SecRule ARGS "@contains secret" "id:9501,phase:1,pass"
SecRule MATCHED_VARS "@contains secret" "id:9502,phase:1,deny,status:403"
"#,
        );
        let evaluation = eval(&rules, "GET", "/?q=secret", &[], b"");
        assert!(matches!(
            evaluation.decision,
            Decision::Block {
                rule_id: 9502,
                ..
            }
        ));
        let names = eval(
            &load(r#"
SecRule ARGS "@contains secret" "id:9501,phase:1,pass"
SecRule MATCHED_VARS "@contains ARGS" "id:9502,phase:1,deny,status:403"
"#),
            "GET",
            "/?q=secret",
            &[],
            b"",
        );
        assert_eq!(names.decision, Decision::Pass);
    }

    #[test]
    fn count_variables_report_collection_sizes() {
        let rules = load(
            r#"
SecRule &ARGS "@eq 2" "id:4301,phase:1,deny,status:403"
"#,
        );
        let evaluation = eval(&rules, "GET", "/?a=1&b=2", &[], b"");
        assert!(matches!(
            evaluation.decision,
            Decision::Block {
                rule_id: 4301,
                ..
            }
        ));
    }

    #[test]
    fn count_tx_reports_presence() {
        let rules = load(
            r#"
SecAction "id:4311,phase:1,pass,setvar:tx.flag=1"
SecRule &TX:FLAG "@eq 1" "id:4312,phase:1,deny,status:403"
"#,
        );
        let evaluation = eval(&rules, "GET", "/", &[], b"");
        assert!(matches!(
            evaluation.decision,
            Decision::Block {
                rule_id: 4312,
                ..
            }
        ));
    }
```

在 `compile_conformance.rs` 新增：

```rust
#[test]
fn rejects_count_of_count_and_negated_count() {
    let error = load(r#"SecRule &&ARGS "@gt 0" "id:1,pass""#).unwrap_err();
    assert!(error.to_string().contains("count"));
    let error = load(r#"SecRule !&ARGS "@gt 0" "id:1,pass""#).unwrap_err();
    assert!(error.to_string().contains("count"));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aegis-engine count_variables_report_collection_sizes`

Expected: 加载失败，提示 `variable counts (&VAR) are not supported`。

- [ ] **Step 3: Add `Variable::Count` in `model.rs`**

在 `Variable` 枚举末尾加入：

```rust
    Count(Box<Variable>),
```

在 `display_name` 中加入：

```rust
            Self::Count(inner) => format!("&{}", inner.display_name()),
```

把 `selector()` 与 `same_family()` 替换为：

```rust
    pub fn selector(&self) -> Option<&Selector> {
        match self {
            Self::RequestHeaders(selector)
            | Self::Args(selector)
            | Self::ArgsGet(selector)
            | Self::ArgsPost(selector)
            | Self::RequestCookies(selector)
            | Self::Ip(selector)
            | Self::Session(selector)
            | Self::User(selector)
            | Self::Global(selector)
            | Self::MatchedVars(selector)
            | Self::Xml(selector)
            | Self::ResponseHeaders(selector)
            | Self::Tx(selector) => selector.as_ref(),
            Self::Count(inner) => inner.selector(),
            _ => None,
        }
    }

    pub fn same_family(&self, other: &Self) -> bool {
        let left = self.unwrap_count();
        let right = other.unwrap_count();
        std::mem::discriminant(left) == std::mem::discriminant(right)
    }

    fn unwrap_count(&self) -> &Self {
        let mut current = self;
        while let Self::Count(inner) = current {
            current = inner;
        }
        current
    }
```

- [ ] **Step 4: Parse `&` in `compile.rs`**

把 `parse_variables` 中拒绝 `&` 的整段代码：

```rust
        if item.starts_with('&') {
            if options.lenient {
                tracing::warn!(
                    file = %file.display(),
                    line,
                    "skipping rule: variable counts are unsupported"
                );
                return Ok(None);
            }
            return Err(compile_error(
                file,
                line,
                column,
                "variable counts (&VAR) are not supported".to_string(),
            ));
        }
```

替换为：

```rust
        let (count, item) = match item.strip_prefix('&') {
            Some(rest) => (true, rest),
            None => (false, item),
        };
        if count && negated {
            return Err(compile_error(
                file,
                line,
                column,
                "variable counts cannot be negated".to_string(),
            ));
        }
        if item.is_empty() || item.starts_with('&') {
            return Err(compile_error(
                file,
                line,
                column,
                "invalid variable count".to_string(),
            ));
        }
```

在构造 `VariableSpec` 之前加入：

```rust
        let variable = if count {
            Variable::Count(Box::new(variable))
        } else {
            variable
        };
        specs.push(VariableSpec { variable, negated });
```

并把原本的 `specs.push(VariableSpec { variable, negated });` 删除。

在 `variable_prefilter_scope` 开头加入：

```rust
    if matches!(variable, Variable::Count(_)) {
        return None;
    }
```

- [ ] **Step 5: Implement Count extraction in `request.rs`**

在 `compute` 的 `match variable` 末尾加入：

```rust
            Variable::Count(inner) => {
                let count = self.extract(inner).len();
                vec![VariableEntry {
                    name: variable.display_name(),
                    key: None,
                    value: count.to_string(),
                }]
            }
```

把 `extract` 的 `cacheable` 判断中加入 `Variable::Count(_)`：

```rust
            Variable::Tx(_)
                | Variable::MatchedVar
                | Variable::MatchedVarName
                | Variable::MatchedVars(_)
                | Variable::Count(_)
                | Variable::Ip(_)
                ...
```

- [ ] **Step 6: Accumulate MATCHED_VARS**

在 `RequestContext` 字段中加入：

```rust
    matched_entries: Vec<VariableEntry>,
```

在 `new_with_store` 的初始化中加入：

```rust
            matched_entries: Vec::new(),
```

加入方法：

```rust
    pub fn record_match(&mut self, name: &str, key: Option<&str>, value: &str) {
        self.matched_entries.push(VariableEntry {
            name: name.to_string(),
            key: key.map(str::to_string),
            value: value.to_string(),
        });
    }
```

把 `compute` 中的：

```rust
            Variable::MatchedVars(_) => self
                .tx
                .get("matched_var_name")
                .map(|value| vec![VariableEntry::scalar(variable, value.to_string())])
                .unwrap_or_default(),
```

替换为：

```rust
            Variable::MatchedVars(selector) => self
                .matched_entries
                .iter()
                .filter(|entry| name_matches(selector, &entry.name))
                .cloned()
                .collect(),
```

- [ ] **Step 7: Record hits and carry keys in eval**

把 `RuleHit` 改为：

```rust
struct RuleHit {
    value: String,
    variable_name: String,
    key: Option<String>,
    captures: Vec<String>,
}
```

在 `rule_matches` 的无条件分支中加入 `key: None`：

```rust
            return Some(RuleHit {
                value: String::new(),
                variable_name: String::new(),
                key: None,
                captures: Vec::new(),
            });
```

在普通命中分支中加入：

```rust
                    return Some(RuleHit {
                        value: matched_value,
                        variable_name: entry.name.clone(),
                        key: entry.key.clone(),
                        captures,
                    });
```

在 `apply_hit_context` 开头加入：

```rust
        self.context
            .record_match(&hit.variable_name, hit.key.as_deref(), &hit.value);
```

- [ ] **Step 8: Run the tests**

Run: `cargo test -p aegis-engine`

Expected: 全部通过；新增 5 个测试通过。

- [ ] **Step 9: Format and commit**

```bash
cargo fmt --all
cargo test -p aegis-engine
git add crates/aegis-engine
git commit -m "feat: add variable counts and full MATCHED_VARS values"
```

---

## Task 4: Body Processors, Multipart Headers, and ARGS_POST

**Files:**
- Modify: `crates/aegis-engine/src/model.rs`
- Modify: `crates/aegis-engine/src/compile.rs`
- Modify: `crates/aegis-engine/src/variables/request.rs`
- Test: inline tests in `request.rs` + `crates/aegis-engine/tests/compile_conformance.rs`

**Interfaces:**
- Produces: `model::BodyProcessor { UrlEncoded, Multipart, Json, Xml, None }` 与 `BodyProcessor::parse_name(&str) -> Option<BodyProcessor>`、`BodyProcessor::name(self) -> &'static str`。
- Produces: `Variable::MultipartPartHeaders(Option<Selector>)`、`Variable::ReqbodyProcessor`。
- Produces: `RequestContext::set_body_processor_override(&mut self, BodyProcessor)`、`RequestContext::body_processor(&self) -> BodyProcessor`（Task 8 使用）。
- Produces: `MultipartPart.headers: Vec<String>`。

- [ ] **Step 1: Write the failing body/multipart tests**

在 `request.rs` 的 `extracts_multipart_files` 测试后追加：

```rust
    #[test]
    fn extracts_multipart_part_headers_and_form_fields() {
        let headers = header_map(&[("content-type", "multipart/form-data; boundary=X")]);
        let mut context = context(&headers);
        let body = b"--X\r\nContent-Disposition: form-data; name=\"_charset_\"\r\nContent-Type: text/plain\r\n\r\nUTF-8\r\n--X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\nfile-content\r\n--X--\r\n";
        context.set_body(body);
        let headers = context.extract(&Variable::MultipartPartHeaders(None));
        assert!(headers
            .iter()
            .any(|entry| entry.value.eq_ignore_ascii_case("content-type: text/plain")));
        assert_eq!(headers[0].key.as_deref(), Some("_charset_"));
        let charset = context.extract(&Variable::MultipartPartHeaders(Some(
            Selector::Literal("_charset_".to_string()),
        )));
        assert_eq!(charset.len(), 2);
        assert_eq!(
            extract(&context, Variable::ArgsPost(None)),
            vec!["UTF-8"]
        );
        assert_eq!(extract(&context, Variable::Files), vec!["file-content"]);
    }

    #[test]
    fn derives_request_body_processor() {
        let headers = header_map(&[("content-type", "application/json")]);
        let mut context = context(&headers);
        context.set_body(b"{\"a\":1}");
        assert_eq!(context.body_processor(), BodyProcessor::Json);
        assert!(extract(&context, Variable::ArgsPost(None)).is_empty());
        assert_eq!(
            extract(&context, Variable::ReqbodyProcessor),
            vec!["JSON"]
        );
    }

    #[test]
    fn missing_content_type_defaults_to_urlencoded() {
        let headers = header_map(&[]);
        let mut context = context(&headers);
        context.set_body(b"a=1&b=2");
        assert_eq!(context.body_processor(), BodyProcessor::UrlEncoded);
        assert_eq!(
            extract(&context, Variable::ArgsPost(None)),
            vec!["1", "2"]
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aegis-engine extracts_multipart_part_headers_and_form_fields`

Expected: compile error because `MultipartPartHeaders` / `BodyProcessor` do not exist.

- [ ] **Step 3: Add `BodyProcessor` and new variables in `model.rs`**

在 `Phase` 之后加入：

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyProcessor {
    UrlEncoded,
    Multipart,
    Json,
    Xml,
    None,
}

impl BodyProcessor {
    pub fn parse_name(raw: &str) -> Option<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "urlencoded" => Some(Self::UrlEncoded),
            "multipart" => Some(Self::Multipart),
            "json" => Some(Self::Json),
            "xml" => Some(Self::Xml),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::UrlEncoded => "URLENCODED",
            Self::Multipart => "MULTIPART",
            Self::Json => "JSON",
            Self::Xml => "XML",
            Self::None => "",
        }
    }
}
```

在 `Variable` 中加入：

```rust
    MultipartPartHeaders(Option<Selector>),
    ReqbodyProcessor,
```

在 `display_name` 中加入：

```rust
            Self::MultipartPartHeaders(selector) => {
                selected("MULTIPART_PART_HEADERS", selector)
            }
            Self::ReqbodyProcessor => "REQBODY_PROCESSOR".to_string(),
```

在 `selector()` 的匹配分支中加入：

```rust
            | Self::MultipartPartHeaders(selector) => selector.as_ref(),
```

- [ ] **Step 4: Parse the new variables in `compile.rs`**

在变量 match 中加入：

```rust
            "MULTIPART_PART_HEADERS" => Variable::MultipartPartHeaders(selector),
            "REQBODY_PROCESSOR" if selector.is_none() => Variable::ReqbodyProcessor,
```

在 `variable_prefilter_scope` 的 `None` 分支列表中加入：

```rust
        | Variable::MultipartPartHeaders(_)
        | Variable::ReqbodyProcessor
```

- [ ] **Step 5: Extend multipart parsing and body handling in `request.rs`**

把 `MultipartPart` 改为：

```rust
#[derive(Debug, Clone)]
struct MultipartPart {
    name: String,
    filename: Option<String>,
    headers: Vec<String>,
    data: Vec<u8>,
}
```

在 `RequestContext` 字段中加入：

```rust
    body_processor: BodyProcessor,
    body_processor_override: Option<BodyProcessor>,
```

在 `new_with_store` 初始化中加入：

```rust
            body_processor: BodyProcessor::None,
            body_processor_override: None,
```

在 `use crate::model::{...}` 中加入 `BodyProcessor`。

把 `set_body` 整体替换为：

```rust
    pub fn set_body(&mut self, body: &[u8]) {
        self.body_len = body.len();
        self.body_text = String::from_utf8_lossy(body).into_owned();
        self.body_processor = self
            .body_processor_override
            .unwrap_or_else(|| derive_body_processor(&self.headers));
        self.body_pairs = Vec::new();
        self.multipart_parts = Vec::new();
        self.xml_values = Vec::new();

        match self.body_processor {
            BodyProcessor::UrlEncoded => {
                self.body_pairs = form_urlencoded::parse(body)
                    .map(|(name, value)| (name.into_owned(), value.into_owned()))
                    .collect();
            }
            BodyProcessor::Multipart => {
                if let Some(boundary) = multipart_boundary(&self.headers) {
                    self.multipart_parts = parse_multipart(body, &boundary);
                    self.body_pairs = self
                        .multipart_parts
                        .iter()
                        .filter(|part| part.filename.is_none())
                        .map(|part| {
                            (
                                part.name.clone(),
                                String::from_utf8_lossy(&part.data).into_owned(),
                            )
                        })
                        .collect();
                }
            }
            BodyProcessor::Xml => {
                self.xml_values = extract_xml_values(&self.body_text);
            }
            BodyProcessor::Json | BodyProcessor::None => {}
        }
        self.cache.borrow_mut().clear();
    }

    pub fn set_body_processor_override(&mut self, processor: BodyProcessor) {
        self.body_processor_override = Some(processor);
    }

    pub fn body_processor(&self) -> BodyProcessor {
        self.body_processor
    }
```

加入 helper：

```rust
fn derive_body_processor(headers: &[(String, String)]) -> BodyProcessor {
    let Some(content_type) = headers
        .iter()
        .find(|(name, _)| name == "content-type")
        .map(|(_, value)| value.to_ascii_lowercase())
    else {
        return BodyProcessor::UrlEncoded;
    };
    if content_type.starts_with("application/x-www-form-urlencoded") {
        BodyProcessor::UrlEncoded
    } else if content_type.starts_with("multipart/form-data") {
        BodyProcessor::Multipart
    } else if content_type.starts_with("application/json") || content_type.contains("+json") {
        BodyProcessor::Json
    } else if content_type.starts_with("application/xml")
        || content_type.starts_with("text/xml")
        || content_type.contains("+xml")
    {
        BodyProcessor::Xml
    } else {
        BodyProcessor::None
    }
}
```

在 `parse_multipart` 中构造 `MultipartPart` 的地方加入 `headers`：

```rust
        if let Some((name, filename)) = parse_part_disposition(&headers_text) {
            parts.push(MultipartPart {
                name,
                filename,
                headers: headers_text
                    .lines()
                    .map(str::trim_end)
                    .filter(|line| !line.is_empty())
                    .map(str::to_string)
                    .collect(),
                data: body[data_start..data_end].to_vec(),
            });
        }
```

在 `compute` 中加入两个分支（`Count` 分支之前）：

```rust
            Variable::MultipartPartHeaders(selector) => self
                .multipart_parts
                .iter()
                .filter(|part| name_matches(selector, &part.name))
                .flat_map(|part| {
                    part.headers.iter().map(move |header| {
                        VariableEntry::item(
                            "MULTIPART_PART_HEADERS",
                            &part.name,
                            header.clone(),
                        )
                    })
                })
                .collect(),
            Variable::ReqbodyProcessor => {
                let name = self.body_processor.name();
                if name.is_empty() {
                    Vec::new()
                } else {
                    vec![VariableEntry::scalar(variable, name.to_string())]
                }
            }
```

- [ ] **Step 6: Run the tests**

Run: `cargo test -p aegis-engine`

Expected: 全部通过；新增 4 个测试通过（含既有 multipart 测试）。

- [ ] **Step 7: Format and commit**

```bash
cargo fmt --all
cargo test -p aegis-engine
git add crates/aegis-engine
git commit -m "feat: add body processors, multipart part headers, and ARGS_POST"
```

---

## Task 5: UNIQUE_ID

**Files:**
- Modify: `crates/aegis-engine/src/model.rs`
- Modify: `crates/aegis-engine/src/compile.rs`
- Modify: `crates/aegis-engine/src/variables/request.rs`
- Modify: `crates/aegis-engine/src/eval.rs`（测试中的 `RequestView` 字面量）
- Modify: `crates/aegis-engine/benches/engine.rs`
- Modify: `crates/aegis-engine/tests/engine_conformance.rs`
- Modify: `crates/aegis-proxy/src/proxy/mod.rs`
- Test: inline `request.rs` 测试

**Interfaces:**
- Produces: `RequestView.unique_id: &'a str`；`Variable::UniqueId`。
- Consumes: 代理现有 `request_id: String`。

- [ ] **Step 1: Write the failing test**

在 `request.rs` 的 `mod tests` 的 `context` helper 中加入 `unique_id: "test-unique-id",`，并新增：

```rust
    #[test]
    fn extracts_unique_id() {
        let headers = header_map(&[]);
        let context = context(&headers);
        assert_eq!(
            extract(&context, Variable::UniqueId),
            vec!["test-unique-id"]
        );
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p aegis-engine extracts_unique_id`

Expected: compile error because `unique_id` / `Variable::UniqueId` do not exist.

- [ ] **Step 3: Add the field and variable**

在 `variables/request.rs` 的 `RequestView` 中加入：

```rust
    pub unique_id: &'a str,
```

在 `RequestContext` 字段中加入：

```rust
    unique_id: String,
```

在 `new_with_store` 初始化中加入：

```rust
            unique_id: view.unique_id.to_string(),
```

在 `compute` 中加入：

```rust
            Variable::UniqueId => vec![VariableEntry::scalar(variable, self.unique_id.clone())],
```

在 `model.rs` 的 `Variable` 中加入 `UniqueId`，并在 `display_name` 中加入：

```rust
            Self::UniqueId => "UNIQUE_ID".to_string(),
```

在 `compile.rs` 的变量 match 中加入：

```rust
            "UNIQUE_ID" if selector.is_none() => Variable::UniqueId,
```

在 `variable_prefilter_scope` 的 `None` 列表中加入 `| Variable::UniqueId`。

- [ ] **Step 4: Update every `RequestView` literal**

在这些位置的 `RequestView { ... }` 中，`remote_addr` 行之后加入：

```rust
            unique_id: "test-unique-id",
```

文件与位置：

- `crates/aegis-engine/src/eval.rs`：`eval` helper（约 619 行）与 5 个直接构造（约 1048、1117、1149、1214、1259 行）
- `crates/aegis-engine/src/variables/request.rs`：`context` helper（约 633 行）
- `crates/aegis-engine/tests/engine_conformance.rs`：`request` helper（约 28 行）
- `crates/aegis-engine/benches/engine.rs`：9 个 `RequestView` 字面量（约 98–190 行）

- [ ] **Step 5: Wire the proxy request id**

在 `crates/aegis-proxy/src/proxy/mod.rs` 的 `handle` 中，把：

```rust
            remote_addr: peer.ip(),
        };
```

改为：

```rust
            remote_addr: peer.ip(),
            unique_id: request_id.as_str(),
        };
```

- [ ] **Step 6: Run the tests**

Run:

```bash
cargo test -p aegis-engine
cargo test -p aegis-proxy
```

Expected: 全部通过；新增 1 个测试通过。

- [ ] **Step 7: Format and commit**

```bash
cargo fmt --all
git add crates/aegis-engine crates/aegis-proxy
git commit -m "feat: expose request UNIQUE_ID to rules"
```

---

## Task 6: Validate Operators and ByteRange Fix

**Files:**
- Modify: `crates/aegis-engine/src/operators.rs`
- Modify: `crates/aegis-engine/src/compile.rs`
- Test: inline `operators.rs` 测试 + `crates/aegis-engine/tests/engine_conformance.rs`

**Interfaces:**
- Produces: `CompiledOperator::ValidateUtf8Encoding`、`ValidateUrlEncoding`。
- Changes: `CompiledOperator::ByteRange` 改为“任一字节越界即匹配”。

- [ ] **Step 1: Write the failing operator tests**

在 `operators.rs` 的 `mod tests` 中，把 `byte_range_and_unconditional_operators` 替换为：

```rust
    #[test]
    fn byte_range_matches_invalid_bytes() {
        let printable = CompiledOperator::ByteRange(vec![(32, 126)]);
        assert!(!printable.matches("hello"));
        assert!(printable.matches("hel\0lo"));
        assert!(CompiledOperator::Unconditional.matches(""));
        assert!(CompiledOperator::Unconditional.matches("anything"));
    }

    #[test]
    fn validation_operators_match_invalid_input() {
        assert!(!CompiledOperator::ValidateUtf8Encoding.matches("hello"));
        assert!(CompiledOperator::ValidateUtf8Encoding.matches("hel\u{FFFD}lo"));
        assert!(!CompiledOperator::ValidateUrlEncoding.matches("a%20b"));
        assert!(CompiledOperator::ValidateUrlEncoding.matches("a%2"));
        assert!(CompiledOperator::ValidateUrlEncoding.matches("a%zz"));
    }
```

在 `crates/aegis-engine/tests/engine_conformance.rs` 新增：

```rust
#[test]
fn validate_byte_range_flags_invalid_bytes() {
    let rules = load(r#"SecRule ARGS "@validateByteRange 32-126" "id:1,phase:1,deny""#);
    let headers = headers(&[]);
    let view = request(&headers, "GET", "/?q=hello", b"");
    assert_eq!(evaluate(&rules, &view).decision, Decision::Pass);
    let view = request(&headers, "GET", "/?q=hel%00lo", b"");
    assert!(matches!(
        evaluate(&rules, &view).decision,
        Decision::Block { rule_id: 1, .. }
    ));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aegis-engine byte_range_matches_invalid_bytes`

Expected: 第一个断言失败（当前实现返回 true）。

- [ ] **Step 3: Implement the operators**

在 `CompiledOperator` 枚举中加入：

```rust
    ValidateUtf8Encoding,
    ValidateUrlEncoding,
```

把 `ByteRange` 分支改为：

```rust
            Self::ByteRange(ranges) => !input.as_bytes().iter().all(|byte| {
                ranges
                    .iter()
                    .any(|(start, end)| *start <= *byte && *byte <= *end)
            }),
            Self::ValidateUtf8Encoding => input.contains('\u{FFFD}'),
            Self::ValidateUrlEncoding => invalid_url_encoding(input),
```

加入：

```rust
fn invalid_url_encoding(input: &str) -> bool {
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return true;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    false
}
```

在 `compile.rs` 的 `parse_operator` 中加入：

```rust
        "validateutf8encoding" => CompiledOperator::ValidateUtf8Encoding,
        "validateurlencoding" => CompiledOperator::ValidateUrlEncoding,
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p aegis-engine`

Expected: 全部通过；新增 2 个测试通过。若其他测试因 `ByteRange` 语义变化失败，按新语义修正期望值。

- [ ] **Step 5: Format and commit**

```bash
cargo fmt --all
cargo test -p aegis-engine
git add crates/aegis-engine
git commit -m "fix: match validate operators on validation failure"
```

---

## Task 7: multiMatch

**Files:**
- Modify: `crates/aegis-engine/src/model.rs`
- Modify: `crates/aegis-engine/src/compile.rs`
- Modify: `crates/aegis-engine/src/eval.rs`
- Test: inline `eval.rs` 测试

**Interfaces:**
- Produces: `CompiledActions.multi_match: bool`。
- Produces: `EvaluationState::rule_hits(&self, &CompiledRule) -> Vec<RuleHit>`（替换 `rule_matches`）。
- Produces: `apply_non_disruptive_actions` 与 `record_rule_match`（从 `apply_non_disruptive` 拆分）。

- [ ] **Step 1: Write the failing multiMatch test**

在 `eval.rs` 的 `mod tests` 中新增：

```rust
    #[test]
    fn multi_match_accumulates_actions_per_hit() {
        let rules = load(
            r#"
SecAction "id:4401,phase:1,pass,setvar:tx.score=0"
SecRule ARGS "@contains attack" "id:4402,phase:1,pass,multiMatch,setvar:tx.score=+1"
SecRule TX:SCORE "@eq 2" "id:4403,phase:1,deny,status:403"
"#,
        );
        let evaluation = eval(&rules, "GET", "/?a=attack&b=attack", &[], b"");
        assert!(matches!(
            evaluation.decision,
            Decision::Block {
                rule_id: 4403,
                ..
            }
        ));
        assert_eq!(
            evaluation
                .matched
                .iter()
                .filter(|matched| matched.id == 4402)
                .count(),
            1
        );
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p aegis-engine multi_match_accumulates_actions_per_hit`

Expected: 决策为 `Pass`（`multiMatch` 被当作未知动作忽略，评分只加一次）。

- [ ] **Step 3: Add the action flag**

在 `model.rs` 的 `CompiledActions` 中加入：

```rust
    pub multi_match: bool,
```

在 `compile.rs` 的 `ParsedActions` 中加入：

```rust
    multi_match: bool,
```

在 `parse_actions` 的 match 中加入：

```rust
            "multimatch" => {
                parsed.multi_match = true;
            }
```

在 `compile_rule` 与 `compile_action` 构造 `CompiledActions` 的地方加入：

```rust
            multi_match: parsed.multi_match,
```

- [ ] **Step 4: Refactor match collection and action application in `eval.rs`**

把 `rule_matches` 重命名为 `rule_hits` 并返回 `Vec<RuleHit>`：

```rust
    fn rule_hits(&self, rule: &CompiledRule) -> Vec<RuleHit> {
        if rule.unconditional {
            return vec![RuleHit {
                value: String::new(),
                variable_name: String::new(),
                key: None,
                captures: Vec::new(),
            }];
        }
        let mut hits = Vec::new();
        for spec in rule.variables.iter().filter(|spec| !spec.negated) {
            let entries = self.context.extract(&spec.variable);
            for entry in entries.iter() {
                if self.entry_excluded(rule, spec, entry) {
                    continue;
                }
                let matched_value;
                let matched = if rule.transformations.is_empty() {
                    matched_value = entry.value.clone();
                    rule.operator.matches(&entry.value)
                } else {
                    let mut current = entry.value.clone();
                    let mut next = String::new();
                    for transform in &rule.transformations {
                        let result = transform.apply(&current);
                        next.clear();
                        next.push_str(&result);
                        std::mem::swap(&mut current, &mut next);
                    }
                    matched_value = current.clone();
                    rule.operator.matches(&current)
                };
                let matched = if rule.operator_negated {
                    !matched
                } else {
                    matched
                };
                if matched {
                    let captures = if rule.actions.capture {
                        capture_values(&rule.operator, &matched_value, rule.operator_negated)
                    } else {
                        Vec::new()
                    };
                    hits.push(RuleHit {
                        value: matched_value,
                        variable_name: entry.name.clone(),
                        key: entry.key.clone(),
                        captures,
                    });
                    if !rule.actions.multi_match {
                        return hits;
                    }
                }
            }
        }
        hits
    }
```

把 `apply_non_disruptive` 拆分为：

```rust
    fn apply_non_disruptive(&mut self, rule: &CompiledRule) {
        self.apply_non_disruptive_actions(rule);
        self.record_rule_match(rule);
    }

    fn apply_non_disruptive_actions(&mut self, rule: &CompiledRule) {
        for (collection, template) in &rule.actions.init_collections {
            let key = self.expand_template(template);
            self.context.set_collection_key(collection, key);
        }
        for setvar in &rule.actions.setvars {
            self.apply_setvar(setvar);
        }
        for ctl in &rule.actions.ctl {
            self.apply_ctl(ctl);
        }
    }

    fn record_rule_match(&mut self, rule: &CompiledRule) {
        let msg = rule
            .actions
            .msg
            .as_ref()
            .map(|template| self.expand_template(template));
        let logdata = rule
            .actions
            .logdata
            .as_ref()
            .map(|template| self.expand_template(template));
        self.matched.push(RuleMatch {
            id: rule.id,
            msg,
            severity: rule.actions.severity.clone(),
            tags: rule.actions.tags.clone(),
            logdata,
            log: rule.actions.log,
        });
    }
```

把 `evaluate_phase` 中的 `RuleGroup::Single` 分支替换为：

```rust
                RuleGroup::Single(rule) => {
                    let hits = self.rule_hits(rule);
                    if !hits.is_empty() {
                        if rule.actions.multi_match {
                            for hit in &hits {
                                self.apply_hit_context(rule, hit);
                                self.apply_non_disruptive_actions(rule);
                            }
                        } else {
                            self.apply_hit_context(rule, &hits[0]);
                            self.apply_non_disruptive(rule);
                        }
                        if rule.actions.multi_match {
                            self.record_rule_match(rule);
                        }
                        self.apply_disruptive(rule);
                        self.apply_skip_after(rules, rule);
                    }
                }
```

把 `RuleGroup::Chain` 分支替换为：

```rust
                RuleGroup::Chain(chain) => {
                    let mut all_match = true;
                    for rule in chain {
                        let hits = self.rule_hits(rule);
                        if hits.is_empty() {
                            all_match = false;
                            break;
                        }
                        if rule.actions.multi_match {
                            for hit in &hits {
                                self.apply_hit_context(rule, hit);
                                self.apply_non_disruptive_actions(rule);
                            }
                            self.record_rule_match(rule);
                        } else {
                            self.apply_hit_context(rule, &hits[0]);
                            self.apply_non_disruptive(rule);
                        }
                    }
                    if all_match {
                        for rule in chain {
                            self.apply_disruptive(rule);
                            if self.decision.is_decisive() {
                                break;
                            }
                        }
                        if let Some(rule) =
                            chain.iter().find(|rule| rule.actions.skip_after.is_some())
                        {
                            self.apply_skip_after(rules, rule);
                        }
                    }
                }
```

- [ ] **Step 5: Run the tests**

Run: `cargo test -p aegis-engine`

Expected: 全部通过；`multi_match_accumulates_actions_per_hit` 通过。

- [ ] **Step 6: Format and commit**

```bash
cargo fmt --all
cargo test -p aegis-engine
git add crates/aegis-engine
git commit -m "feat: apply multiMatch actions for every matching value"
```

---

## Task 8: ctl Extensions

**Files:**
- Modify: `crates/aegis-engine/src/model.rs`
- Modify: `crates/aegis-engine/src/compile.rs`
- Modify: `crates/aegis-engine/src/variables/request.rs`
- Modify: `crates/aegis-engine/src/eval.rs`
- Test: inline `eval.rs` 测试 + `crates/aegis-engine/tests/compile_conformance.rs`

**Interfaces:**
- Produces: `CtlAction::{RequestBodyProcessor(BodyProcessor), ForceRequestBodyVariable(bool), RemoveTargetById { id, target }, RemoveTargetByTag { tag, target }}`。
- Consumes: Task 4 的 `BodyProcessor` 与 `set_body_processor_override`；Task 1/2 的 `Variable`/`Selector`。

- [ ] **Step 1: Write the failing ctl tests**

在 `eval.rs` 的 `mod tests` 中新增：

```rust
    #[test]
    fn rule_remove_target_by_tag_skips_matching_variable() {
        let rules = load(
            r#"
SecRule REQUEST_FILENAME "@contains admin" "id:4501,phase:1,pass,ctl:ruleRemoveTargetByTag=skip-target;REQUEST_FILENAME"
SecRule REQUEST_FILENAME "@contains admin" "id:4502,phase:1,deny,status:403,tag:'skip-target'"
"#,
        );
        let evaluation = eval(&rules, "GET", "/admin", &[], b"");
        assert_eq!(evaluation.decision, Decision::Pass);
    }

    #[test]
    fn rule_remove_target_by_id_skips_matching_variable() {
        let rules = load(
            r#"
SecRule REQUEST_FILENAME "@contains admin" "id:4511,phase:1,pass,ctl:ruleRemoveTargetById=4512;REQUEST_FILENAME"
SecRule REQUEST_FILENAME "@contains admin" "id:4512,phase:1,deny,status:403"
"#,
        );
        let evaluation = eval(&rules, "GET", "/admin", &[], b"");
        assert_eq!(evaluation.decision, Decision::Pass);
    }

    #[test]
    fn request_body_processor_ctl_overrides_content_type() {
        let rules = load(
            r#"
SecRule REQUEST_HEADERS:Content-Type "@contains text/plain" "id:4521,phase:1,pass,ctl:requestBodyProcessor=URLENCODED"
SecRule ARGS_POST:a "@eq 1" "id:4522,phase:2,deny,status:403"
"#,
        );
        let evaluation = eval(
            &rules,
            "POST",
            "/submit",
            &[("content-type", "text/plain")],
            b"a=1",
        );
        assert!(matches!(
            evaluation.decision,
            Decision::Block {
                rule_id: 4522,
                ..
            }
        ));
    }
```

在 `compile_conformance.rs` 新增：

```rust
#[test]
fn compiles_ctl_extensions() {
    let rules = load(
        r#"
SecRule ARGS "@contains x" "id:1,phase:1,pass,ctl:requestBodyProcessor=JSON"
SecRule ARGS "@contains x" "id:2,phase:1,pass,ctl:forceRequestBodyVariable=On"
SecRule ARGS "@contains x" "id:3,phase:1,pass,ctl:ruleRemoveTargetByTag=t;ARGS:foo"
"#,
    )
    .unwrap();
    assert_eq!(rules.rule_count, 3);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aegis-engine rule_remove_target_by_tag_skips_matching_variable`

Expected: `Pass` 断言失败（第二规则仍然命中）。

- [ ] **Step 3: Extend `CtlAction` in `model.rs`**

把 `CtlAction` 替换为：

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtlAction {
    AuditEngine(bool),
    RuleEngine(RuleEngineMode),
    RemoveRuleById(u32),
    RemoveRuleByTag(String),
    RequestBodyProcessor(BodyProcessor),
    ForceRequestBodyVariable(bool),
    RemoveTargetById { id: u32, target: Variable },
    RemoveTargetByTag { tag: String, target: Variable },
}
```

- [ ] **Step 4: Parse the new ctl values in `compile.rs`**

把 `parse_ctl` 替换为：

```rust
fn parse_ctl(
    raw: &str,
    file: &Path,
    line: usize,
    column: usize,
    options: &LoadOptions,
) -> Result<CtlAction, String> {
    let (name, value) = raw
        .split_once('=')
        .ok_or_else(|| "ctl requires name=value".to_string())?;
    let value = value.trim();
    match name.trim().to_ascii_lowercase().as_str() {
        "auditengine" => match value.to_ascii_lowercase().as_str() {
            "off" => Ok(CtlAction::AuditEngine(false)),
            "on" | "relevantonly" => Ok(CtlAction::AuditEngine(true)),
            other => Err(format!("unsupported auditEngine value {other}")),
        },
        "ruleengine" => match value.to_ascii_lowercase().as_str() {
            "on" => Ok(CtlAction::RuleEngine(RuleEngineMode::On)),
            "off" => Ok(CtlAction::RuleEngine(RuleEngineMode::Off)),
            "detectiononly" => Ok(CtlAction::RuleEngine(RuleEngineMode::DetectionOnly)),
            other => Err(format!("unsupported ruleEngine value {other}")),
        },
        "ruleremovebyid" => value
            .parse::<u32>()
            .map(CtlAction::RemoveRuleById)
            .map_err(|error| format!("invalid rule id in ctl: {error}")),
        "ruleremovebytag" => Ok(CtlAction::RemoveRuleByTag(value.to_string())),
        "requestbodyprocessor" => BodyProcessor::parse_name(value)
            .map(CtlAction::RequestBodyProcessor)
            .ok_or_else(|| format!("unsupported requestBodyProcessor value {value}")),
        "forcerequestbodyvariable" => match value.to_ascii_lowercase().as_str() {
            "on" => Ok(CtlAction::ForceRequestBodyVariable(true)),
            "off" => Ok(CtlAction::ForceRequestBodyVariable(false)),
            other => Err(format!("unsupported forceRequestBodyVariable value {other}")),
        },
        "ruleremovetargetbyid" => {
            let (id, target) = split_target(value)?;
            let id = id
                .parse::<u32>()
                .map_err(|error| format!("invalid rule id in ctl: {error}"))?;
            let target = parse_target_variable(file, line, column, &target, options)?;
            Ok(CtlAction::RemoveTargetById { id, target })
        }
        "ruleremovetargetbytag" => {
            let (tag, target) = split_target(value)?;
            let target = parse_target_variable(file, line, column, &target, options)?;
            Ok(CtlAction::RemoveTargetByTag {
                tag: tag.to_string(),
                target,
            })
        }
        other => Err(format!("unsupported ctl {other}")),
    }
}

fn split_target(value: &str) -> Result<(&str, String), String> {
    let (selector, target) = value
        .split_once(';')
        .ok_or_else(|| "target ctl requires id|tag;VARIABLE".to_string())?;
    Ok((selector.trim(), target.trim().to_string()))
}

fn parse_target_variable(
    file: &Path,
    line: usize,
    column: usize,
    raw: &str,
    options: &LoadOptions,
) -> Result<Variable, String> {
    match parse_variables(file, line, column, raw, options) {
        Ok(Some(mut specs)) if specs.len() == 1 => Ok(specs.remove(0).variable),
        Ok(_) => Err(format!("invalid target variable {raw}")),
        Err(error) => Err(error.to_string()),
    }
}
```

**注意**：`parse_ctl` 的签名原本是 `fn parse_ctl(raw: &str) -> Result<CtlAction, String>`；本任务改为带 `file/line/column/options` 的版本，并同时修改 `parse_actions` 中的调用处。`compile.rs` 顶部的 `use crate::model::{...}` 需加入 `BodyProcessor`：

```rust
                match parse_ctl(value, file, line, column, options) {
```

`parse_target_variable` 复用 `parse_variables`，因此支持 `VARIABLE`、`VARIABLE:literal` 与 `VARIABLE:/regex/`，无需额外解析逻辑。

- [ ] **Step 5: Apply ctl and target filtering in `eval.rs`**

在 `EvaluationState` 字段中加入：

```rust
    removed_targets_by_id: Vec<(u32, Variable)>,
    removed_targets_by_tag: Vec<(String, Variable)>,
```

在 `new_with_store` 初始化中加入：

```rust
            removed_targets_by_id: Vec::new(),
            removed_targets_by_tag: Vec::new(),
```

在 `apply_ctl` 的 match 中追加：

```rust
            CtlAction::RequestBodyProcessor(processor) => {
                self.context.set_body_processor_override(*processor);
            }
            CtlAction::ForceRequestBodyVariable(_) => {}
            CtlAction::RemoveTargetById { id, target } => {
                self.removed_targets_by_id.push((*id, target.clone()));
            }
            CtlAction::RemoveTargetByTag { tag, target } => {
                self.removed_targets_by_tag.push((tag.clone(), target.clone()));
            }
```

在 `entry_excluded` 的返回值中追加 target 检查：

```rust
        let negated = rule.variables.iter().filter(|spec| spec.negated).any(|negated| {
            negated.variable.same_family(&spec.variable)
                && match negated.variable.selector() {
                    None => true,
                    Some(selector) => entry
                        .key
                        .as_deref()
                        .map(|key| selector.matches(key))
                        .unwrap_or(false),
                }
        });
        if negated {
            return true;
        }
        self.removed_targets_by_id
            .iter()
            .filter(|(id, _)| *id == rule.id)
            .map(|(_, target)| target)
            .chain(
                self.removed_targets_by_tag
                    .iter()
                    .filter(|(tag, _)| rule.actions.tags.contains(tag))
                    .map(|(_, target)| target),
            )
            .any(|target| {
                target.same_family(&spec.variable)
                    && match target.selector() {
                        None => true,
                        Some(selector) => entry
                            .key
                            .as_deref()
                            .map(|key| selector.matches(key))
                            .unwrap_or(false),
                    }
            })
```

- [ ] **Step 6: Run the tests**

Run: `cargo test -p aegis-engine`

Expected: 全部通过；新增 4 个测试通过。若 `parse_target_variable` 触发了 `parse_variable` 的 lenient 警告，严格模式测试不受影响。

- [ ] **Step 7: Format and commit**

```bash
cargo fmt --all
cargo test -p aegis-engine
git add crates/aegis-engine
git commit -m "feat: support body processor and target-removal ctl actions"
```

---

## Task 9: Documentation, CRS Benchmark, and Final Gate

**Files:**
- Modify: `README.md`
- Modify: `docs/compatibility.md`
- Modify: `docs/benchmarks.md`
- Test: full workspace + CRS benchmark

**Interfaces:**
- Consumes: 前 8 个任务的全部能力。

- [ ] **Step 1: Run the CRS benchmark**

Run:

```bash
cd /d/rust_code/aegis-waf
bash scripts/bench_crs.sh
```

Expected output includes:

```text
compiled_rules=<N> skipped_rule_directives=<M> (…%)
```

记录 `N`、`M` 与 `groups`、`prefiltered` 数字。目标：`M` 仅来自明确不支持的特性（理想为 0）。

- [ ] **Step 2: Update `docs/benchmarks.md`**

在文件末尾新增一节：

```markdown
## 16. 剩余 CRS 兼容项（2026-10-24）

本轮补齐：

- 变量计数（`&VAR`）、正则选择器（`VAR:/regex/`）与按变量项取反。
- 完整 `MATCHED_VARS`（命中值集合）与精确 `MATCHED_VAR_NAME`（如 `ARGS:foo`）。
- `MULTIPART_PART_HEADERS`、`REQBODY_PROCESSOR`、`UNIQUE_ID`。
- 请求体处理器感知的 `ARGS_POST`（URLENCODED/MULTIPART）与 multipart 头解析。
- `@validateUtf8Encoding`、`@validateUrlEncoding`；修正 `@validateByteRange` 的反向语义。
- `multiMatch` 按命中次数执行非破坏性动作。
- `ctl:requestBodyProcessor`、`forceRequestBodyVariable`、`ruleRemoveTargetById/Tag`。

CRS 覆盖率：<按实际输出填写>。

## 17. 验证

- `cargo test --workspace`：<实际数量> 个测试通过。
- `cargo fmt --check` 与 `cargo clippy --workspace --all-targets -- -D warnings` 通过。
- `bash scripts/bench_crs.sh` 可复现第 16 节数字。
```

把第 13 节的覆盖率数字更新为本次实测值（编译成功数、百分比、跳过数、分组数、预筛数）。

- [ ] **Step 3: Update `docs/compatibility.md`**

- “已支持”表：
  - 请求变量加入 `MULTIPART_PART_HEADERS`、`REQBODY_PROCESSOR`、`UNIQUE_ID`、`MATCHED_VARS`（完整语义）。
  - 算子加入 `@validateUtf8Encoding`、`@validateUrlEncoding`。
  - 动作加入 `multiMatch`、`ctl` 扩展。
  - 变量选择器说明加入 `/regex/` 与 `&` 计数。
- “语义说明”：
  - 明确 `validate*` 算子在“校验失败时匹配”。
  - 明确取反按变量项名称排除。
  - 明确 `MATCHED_VARS` 返回命中值，`MATCHED_VAR_NAME` 带集合键。
  - 明确无 `Content-Type` 时按 URLENCODED 解析。
  - 明确 `multiMatch` 每条规则只记一条审计。
- “已知不兼容”删除已实现项，只保留：
  - 持久化集合 TTL/Redis、完整 XPath、chunked/超大响应 Phase 4、响应压缩解压、Lua/GeoIP/WASM、PCRE lookaround/backreference。
  - `validateUtf8Encoding` 使用 U+FFFD 近似检测非法 UTF-8。

- [ ] **Step 4: Update `README.md`**

能力列表加入：变量计数、正则选择器、`MULTIPART_PART_HEADERS`、`REQBODY_PROCESSOR`、`UNIQUE_ID`、`multiMatch`、`ruleRemoveTarget` ctl、两个新校验算子。

限制列表删除已实现项，并加入：

```markdown
- `@validateUtf8Encoding` 通过 U+FFFD 近似检测非法 UTF-8
- `multiMatch` 每条规则只记录一条审计
```

- [ ] **Step 5: Run the full quality gate**

Run:

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: 全部通过。

- [ ] **Step 6: Commit**

```bash
git add README.md docs/benchmarks.md docs/compatibility.md
git commit -m "docs: record remaining CRS compatibility support"
```

---

## Self-Review

- Spec 覆盖：数据模型（Task 1–3）、请求体/multipart（Task 4）、UNIQUE_ID（Task 5）、校验算子与 ByteRange 修复（Task 6）、multiMatch（Task 7）、ctl（Task 8）、文档与基准（Task 9）。
- 占位符：无 TBD/TODO；Task 9 的基准数字要求在运行时填写，属于文档更新步骤，不是实现占位。
- 类型一致性：`VariableEntry`、`Selector`、`RegexSelector`、`BodyProcessor`、`CtlAction`、`RuleHit` 的字段与各任务引用一致。
- 已知顺序依赖：Task 8 依赖 Task 2 的 `parse_selector` 与 Task 4 的 `BodyProcessor`；Task 7 依赖 Task 2 的 `variable.selector()`；Task 6 的算子测试依赖 Task 1 的 entry 抽取。`parse_target_variable` 复用 `parse_variables`，不要求额外重构。
