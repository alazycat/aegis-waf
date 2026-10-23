# aegis-waf v0.1 性能基准

- 日期：2026-10-23
- 版本：v0.1（master）
- 环境：Windows 11，AMD Ryzen 7 7840H（8 核 / 16 线程），15.3 GB RAM
- 工具链：rustc 1.99.0，release 构建
- 网络：本机 loopback；客户端、代理、上游在同一台机器上运行

> 本基准的目标是建立 v0.1 的基线和瓶颈认识，不是对外性能承诺。客户端、代理和上游共享
> CPU，客户端本身可能成为瓶颈；绝对数字会随机器、负载生成器和内核调度变化。

> **2026-10-23 更新**：已完成“变量提取缓存 + 规则预筛”，优化后结果见第 8-10 节。
> 第 2-4 节保留为优化前基线，便于对比。

## 1. 测试方法

### 引擎微基准（Criterion）

- 直接调用 `aegis_engine::evaluate`，单线程、无网络、无 IO。
- 规则集：`rules/examples/` 中的 8 条示例规则；另测空规则和动态生成的 100 条简单规则。
- 50 个样本，500 ms 预热，3 s 测量。
- 编译基准：对示例规则文件执行 `load_rules`（包含文件读取、解析、正则编译）。
- 运行方式：`cargo bench -p aegis-engine --bench engine`
- HTML 报告：`target/criterion/report/index.html`

### 端到端压测（独立进程）

- 三个独立进程：mock upstream、release 版 `aegis-proxy`、`loadtest` 客户端。
- 客户端每个并发任务使用独立的 hyper keep-alive 连接，单请求串行发送。
- 1 s 预热，5 s 测量；记录 HTTP 状态、RPS 和延迟分位数。
- 场景：
  1. **block**：`GET /search?q=%3Cscript%3E`，命中 XSS 规则，返回 403，不访问上游。
  2. **safe**：`GET /search?q=hello`，通过 8 条示例规则，转发到上游，返回 200。
  3. **empty baseline**：空规则文件，同 safe 路径，用于衡量代理/HTTP 栈的固定成本。
- 审计 sink 设为 `none`，避免磁盘 IO 干扰；block 路径仍会构造审计事件。
- 运行方式：`bash scripts/bench_e2e.sh`（Windows 上使用 Git Bash）。

## 2. 引擎结果

单位：每请求耗时（均值），吞吐为单线程理论值。

| 场景 | 耗时 | 单线程吞吐 |
|---|---:|---:|
| 空规则 | 0.562 µs | 1.78 M eval/s |
| 8 条示例规则，safe | 2.245 µs | 445 K eval/s |
| 8 条示例规则，XSS 拦截 | 2.292 µs | 436 K eval/s |
| 8 条示例规则，请求体 SQLi 拦截 | 2.197 µs | 455 K eval/s |
| 100 条简单 `@contains` 规则，safe | 16.684 µs | 60 K eval/s |
| 编译 8 条示例规则 | 637.6 µs | — |

派生数据：

- 固定开销（空规则）：约 **0.56 µs/请求**。
- 8 条规则增量：约 **210 ns/规则**。
- 100 条规则增量：约 **161 ns/规则**。
- 规则数量线性影响耗时；100 条规则时引擎单线程上限约 **60 K req/s**。

## 3. 端到端结果

### 3.1 8 条示例规则

| 场景 | 并发 | RPS | mean (ms) | p95 (ms) | p99 (ms) |
|---|---:|---:|---:|---:|---:|
| block | 1 | 22,372 | 0.044 | 0.061 | 0.099 |
| block | 8 | 84,724 | 0.094 | 0.141 | 0.182 |
| block | 32 | 103,796 | 0.308 | 0.461 | 0.590 |
| block | 64 | 110,563 | 0.578 | 0.901 | 1.173 |
| block | 128 | 113,988 | 1.122 | 1.788 | 2.266 |
| safe | 1 | 10,416 | 0.095 | 0.130 | 0.189 |
| safe | 8 | 43,105 | 0.185 | 0.253 | 0.320 |
| safe | 32 | 57,347 | 0.557 | 0.797 | 1.004 |
| safe | 64 | 55,175 | 1.159 | 1.789 | 2.279 |
| safe | 128 | 52,691 | 2.428 | 3.763 | 4.515 |

### 3.2 空规则基线（safe）

| 并发 | RPS | mean (ms) | p95 (ms) | p99 (ms) |
|---:|---:|---:|---:|---:|
| 1 | 11,155 | 0.089 | 0.121 | 0.175 |
| 8 | 43,849 | 0.182 | 0.252 | 0.321 |
| 32 | 59,131 | 0.540 | 0.775 | 0.967 |
| 64 | 58,345 | 1.096 | 1.670 | 2.131 |
| 128 | 54,295 | 2.357 | 3.640 | 4.329 |

### 3.3 对比

- **block vs safe**：block 约为 safe 的 **1.8–2.2 倍** RPS。主要差异是 block 不访问上游，
  不是引擎更快。
- **safe（8 规则）vs empty（0 规则）**：
  - 并发 32：57,347 vs 59,131（约 **-3.0%**）
  - 并发 64：55,175 vs 58,345（约 **-5.4%**）
  - 并发 128：52,691 vs 54,295（约 **-3.0%**）
  - 8 条规则的引擎成本被 HTTP 栈和上游往返掩盖。
- **safe 在并发 32 左右饱和**（约 57 K RPS）；继续增加并发吞吐下降、延迟上升，
  说明客户端/代理/上游在同一台机器上已经出现 CPU 竞争和排队。
- **block 在并发 128 时仍在上升**（约 114 K RPS），说明拒绝路径主要受 HTTP/代理栈限制。

## 4. 分析

1. **引擎不是当前端到端瓶颈**。8 条规则约 2.2 µs/请求，而 block 路径单请求实际耗时
   约 44 µs（1 并发），safe 路径约 95 µs。网络、HTTP 解析、任务调度占主导。
2. **规则扩展性需要关注**。引擎每增加一条规则约增加 160–210 ns；100 条规则时单线程
   上限约 60 K req/s。完整 CRS（数百条规则）会显著压缩引擎余量，需要优化后再谈高吞吐。
3. **空规则仍有 0.56 µs 固定成本**。主要来自请求上下文规范化：header 复制、query
   解析、Cookie 解析和变量存储初始化。即使没有任何规则，这部分成本也会发生。
4. **safe 高并发退化**。并发 64/128 时 RPS 下降而 p99 上升，说明同一台机器上的
   客户端、代理、上游三方竞争 CPU；不能据此判断代理本身的极限。
5. **block 路径的审计成本存在但未主导**。block 会构造一个审计事件并 `try_send`；
   sink 为 none，未做 JSON 序列化和磁盘写入。真实启用文件审计时，吞吐会受 sink 影响。

## 5. 优化建议（按收益排序）

> 第 8 节已实现第 1-2 项和“Aho-Corasick 字面量预筛”；按变量分组的规则索引与延迟解析仍未实现。

1. **按请求/阶段缓存变量提取结果**
   - 当前每条规则都会重新 `extract` 并克隆字符串，这是 160–210 ns/规则的主要来源。
   - 建议在 `RequestContext` 中按变量名/selector 缓存 `Vec<String>` 或 `Vec<&str>`，
     或改为借用式提取，避免重复分配。

2. **避免变换链的重复分配**
   - `rule_matches` 对每个变换调用 `into_owned()`；多变换规则会多次分配。
   - 建议保持 `Cow` 链或复用 `String` 缓冲区，仅在需要时分配。

3. **规则索引与预筛**
   - 按变量分组，避免每条规则都遍历所有变量。
   - 对 `@rx` 规则提取必要字面量，用 Aho-Corasick 做前置过滤；完整 CRS 场景收益明显。
   - 对 `@contains`/`@pm` 也可用多模式匹配。

4. **延迟解析**
   - 没有规则引用 `ARGS` 时，不解析 query/form；没有规则引用 Cookie 时，不解析 Cookie。
   - 这可以直接降低空规则/低规则数场景的 0.56 µs 固定成本。

5. **代理层热点**
   - 每请求的 `request_id`（Uuid）、header 克隆、URI 字符串分配、审计事件构造。
   - 若要追求 >100 K RPS，需要 profile 代理层的分配与 hyper 任务调度；
     block 路径目前约 114 K RPS，safe 路径受上游往返限制。

6. **完整 CRS 之前先做规则规模基准**
   - 建议增加 200/500 条规则的基准，观察线性成本是否可接受；
   - 如果目标是单机 50 K RPS + CRS，引擎优化是前置条件。

## 6. 复现

```bash
# 引擎基准（Criterion）
cargo bench -p aegis-engine --bench engine

# 端到端基准（独立进程，默认 1/8/32/64/128 并发）
bash scripts/bench_e2e.sh
```

结果文件：

- `target/bench/e2e.txt`
- `target/criterion/report/index.html`

## 7. 局限

- 客户端、代理、上游共享同一台 8C/16T 机器，客户端可能先饱和。
- 只有 HTTP/1.1 loopback，没有 TLS、跨机网络和真实上游延迟。
- 每轮 5 s 测量，p99 受短窗口和 Windows 调度影响。
- block 路径未启用审计文件写入；启用后吞吐会下降。
- 没有控制 CPU 频率/温度，绝对数字仅供同机对比。

## 8. 优化实现（变量缓存 + 规则预筛）

### 8.1 变量提取缓存

`RequestContext` 现在为每个非 TX 变量缓存 `Arc<Vec<String>>`：

- 同一请求内，多条规则引用 `ARGS`、`REQUEST_HEADERS`、`REQUEST_COOKIES` 等变量时，
  只解析/克隆一次。
- TX 变量不缓存，因为 `setvar` 会在求值过程中修改它。
- `set_body` 会清空缓存，保证 Phase 2 使用更新后的 `ARGS_POST` / `REQUEST_BODY`。
- 求值时不再为每条规则复制变量值；变换链改为复用一个 `String` 缓冲区，
  无变换规则完全避免额外分配。

### 8.2 规则预筛

编译期从可预筛规则中提取“必须出现的字面量”，用 Aho-Corasick 建立多模式匹配器：

- 支持 `@contains`、`@eq`、`@beginsWith`、`@endsWith`（单字面量）和 `@pm`（多字面量）。
- 只对满足以下条件的规则启用：
  - 无 `t:` 变换（变换可能合成字面量）；
  - 无 `TX` 或 `REMOTE_ADDR` 变量（TX 会动态变化，REMOTE_ADDR 不在扫描范围）；
  - 算子未取反（取反语义不是“必须出现”）；
  - 非 `SecAction` 无条件规则。
- 扫描范围按变量类型裁剪（请求行/头/Cookie/query/body），并且同时扫描原始值和解码后的
  query/body 键值，避免百分号编码导致漏报。
- 链式规则只用链首规则的字面量做预筛：链首不命中则整条链不可能命中。
- 预筛只在“字面量不存在”时跳过规则，属于保守过滤，不会改变命中结果；
  `eval.rs` 中增加了百分号编码、`@pm`、`REMOTE_ADDR` 等回归测试。

## 9. 优化后引擎结果

| 场景 | 优化前 | 优化后 | 变化 |
|---|---:|---:|---:|
| 8 条示例规则，safe | 2.245 µs | 1.963 µs | -12.6% |
| 8 条示例规则，XSS 拦截 | 2.292 µs | 2.233 µs | -2.1% |
| 8 条示例规则，请求体 SQLi | 2.197 µs | 2.289 µs | +3.7% |
| 空规则 | 0.562 µs | 0.572 µs | +2.5% |
| 100 条简单规则，safe | 16.684 µs | 0.894 µs | **-94.6%（约 18.7×）** |
| 200 条简单规则，safe | — | 1.108 µs | — |
| 500 条简单规则，safe | — | 1.662 µs | — |
| 200 条规则，命中最后一条 | — | 1.597 µs | — |
| 500 条规则，命中最后一条 | — | 2.171 µs | — |
| 编译 8 条示例规则 | 637.6 µs | 659.0 µs | 约 +3.4%（含 IO/噪声） |
| 编译 500 条简单规则 | — | 1.235 ms | — |

关键变化：

- 100 条“不命中”的规则从 16.7 µs 降到 0.89 µs，预筛直接跳过全部规则。
- 200/500 条规则的不命中成本主要由 Aho-Corasick 扫描决定，而不是规则数量。
- 命中一条规则时，成本约为“扫描 + 单条规则求值”，500 条规则也只有 2.17 µs。
- 8 条示例规则中，SQLi 请求体规则带多个变换且无法预筛，缓存带来的
  RefCell/HashMap 开销使其略慢 3.7%；小规则集下影响很小。
- 空规则略慢 2.5%，来自缓存结构初始化，属于可接受固定成本。

## 10. 优化后端到端结果

200/500 条规则使用固定宽度 `needle-NNNN` 字面量，规则均为可预筛的 `@contains`。

| 规则数 | 场景 | 并发 | RPS | mean (ms) | p95 (ms) | p99 (ms) |
|---:|---|---:|---:|---:|---:|---:|
| 200 | 不命中 | 32 | 57,777 | 0.553 | 0.795 | 0.992 |
| 200 | 命中 1 条 | 32 | 57,223 | 0.559 | 0.802 | 1.017 |
| 200 | 不命中 | 64 | 56,154 | 1.139 | 1.755 | 2.226 |
| 200 | 命中 1 条 | 64 | 58,666 | 1.090 | 1.675 | 2.136 |
| 500 | 不命中 | 32 | 58,123 | 0.550 | 0.785 | 0.981 |
| 500 | 命中 1 条 | 32 | 57,178 | 0.559 | 0.799 | 1.000 |
| 500 | 不命中 | 64 | 57,279 | 1.117 | 1.725 | 2.205 |
| 500 | 命中 1 条 | 64 | 57,978 | 1.103 | 1.694 | 2.152 |
| 500 | 命中并 deny | 32 | 110,889 | 0.288 | 0.430 | 0.543 |
| 500 | 命中并 deny | 64 | 121,307 | 0.527 | 0.836 | 1.103 |

同轮 empty baseline：

- 并发 32：58,090 RPS
- 并发 64：57,331 RPS

结论：

- 200/500 条可预筛规则在 safe 路径上与空规则 baseline 的差异在 **±2%** 以内，
  规则数量在端到端网络路径中已经不可测量。
- 500 条规则命中一条并 deny 时，block 路径达到 **121 K RPS（并发 64）**，
  与 8 条示例规则的 block 路径相当，说明预筛避免了规则数量带来的线性退化。
- 示例规则 safe 路径（并发 32）为 55,345 RPS，比 empty baseline 低约 4.7%；
  其中 SQLi/XSS 规则带变换，无法预筛，仍会执行。

## 11. 优化后的边界与下一步

本次优化对“字面量型、无变换、无 TX”的规则效果最大。完整 CRS 中大量规则使用：

- `t:urlDecodeUni` / `t:lowercase` 等变换；
- `@rx` 正则；
- TX/setvar 异常评分；
- `@detectSQLi` 等复杂算子。

这些规则目前仍会逐条求值（变量缓存仍能减少重复提取）。

> 第 1-2 项已在第 12 节实现；第 3-4 项仍待做。

## 12. regex 字面量与变换感知预筛

### 12.1 实现

**`@rx` 必需字面量**

- 使用 `regex-syntax` 的 `hir::literal::Extractor` 提取正则匹配必须包含的 prefix 字面量。
- 如果 prefix 序列为空/无限，则尝试 suffix 提取（匹配必须以某个字面量结尾）。
- 字面量序列必须有限、非空、无空字面量，且不超过 32 个；否则放弃该 regex 的预筛。
- 只使用“存在性”信息：任何匹配都包含至少一个提取出的字面量，因此可以在请求值中做
  Aho-Corasick 子串搜索。
- `(?i)` 或无法提取有限字面量的 regex，使用预编译的 `regex::RegexSet` 作为预筛。
  RegexSet 使用与规则相同的 regex 引擎和 Unicode case-folding 语义，因此不会漏报。
- 但 RegexSet 对少量模式反而比逐条求值更慢，因此只有同一变换变体内 regex 模式数
  **≥ 8** 时才构建 RegexSet；小集合直接逐条求值。每个变体的 RegexSet 模式上限为 512。
- 匹配空字符串的 regex（例如 `.*`）不做 RegexSet 预筛，因为它几乎命中所有值。

**变换感知变体**

- 预筛不再要求规则无变换。编译期按 `Transform` 管道分组，每组建立一个 Aho-Corasick
  变体。
- 扫描时对每个请求值应用与规则相同的变换管道，再用该变体的字面量做匹配。
  由于规则也是“先变换、后匹配”，这是等价的必要条件。
- 当前支持引擎中的全部确定性变换：`lowercase`、`urlDecode`、`urlDecodeUni`、
  `htmlEntityDecode`、`trim`、`compressWhitespace`、`normalizePath`、`base64Decode` 等。
- 变体数量上限为 16；超过上限的规则不做预筛，保持正确性。
- 变换变体在扫描时可能为每个值分配一个临时 `String`；无变换变体保持零分配。

### 12.2 引擎结果

> 以下为多次运行的代表值。测量期间测试机同时有 Chrome 等负载，绝对数字有约
> 20–40% 的波动；相对结论和 CRS 覆盖率数据不受影响。
>
> 2026-10-23 后续加入 libinjection、capture/MATCHED_VAR、ctl 和响应阶段后，匹配路径会
> 额外克隆命中值并写入 MATCHED_VAR/TX。关键场景重测：500 条 contains 不命中 2.72 µs、
> 命中 1 条 3.62 µs；500 条 regex+lowercase 不命中 3.01 µs、命中 4.04 µs；500 条 `(?i)`
> 不命中 3.40 µs、命中 4.45 µs。整体结论不变。

| 场景 | 优化后耗时 | 单线程吞吐 |
|---|---:|---:|
| 200 条 `@rx` + `t:lowercase`，不命中 | 1.57–2.16 µs | 460–638 K eval/s |
| 500 条 `@rx` + `t:lowercase`，不命中 | 2.29–3.26 µs | 307–438 K eval/s |
| 200 条 `@rx` + `t:lowercase`，命中 1 条 | 2.20–3.06 µs | 327–454 K eval/s |
| 500 条 `@rx` + `t:lowercase`，命中 1 条 | 2.90–4.13 µs | 242–344 K eval/s |
| 200 条 `(?i)` regex，不命中 | 1.82–2.06 µs | 486–550 K eval/s |
| 500 条 `(?i)` regex，不命中 | 3.11–3.65 µs | 274–321 K eval/s |
| 200 条 `(?i)` regex，命中 1 条 | 2.55–3.20 µs | 313–393 K eval/s |
| 500 条 `(?i)` regex，命中 1 条 | 3.81–4.63 µs | 216–263 K eval/s |
| 编译 500 条 regex+lowercase 规则 | 5.3–8.9 ms | — |
| 编译 500 条 `(?i)` regex 规则 | 80.8–118.7 ms | — |
| 100 条 `@contains`，不命中（变体结构后） | 1.01–1.43 µs | 700–988 K eval/s |
| 500 条 `@contains`，不命中（变体结构后） | 2.00–2.90 µs | 345–500 K eval/s |
| 8 条示例规则，safe | 2.10–2.47 µs | 405–476 K eval/s |
| 8 条示例规则，XSS | 2.31–3.25 µs | 307–433 K eval/s |
| 8 条示例规则，请求体 SQLi | 2.39–3.47 µs | 288–419 K eval/s |

说明：

- 引入“变换变体”后，无变换预筛的固定开销略有上升（100 条规则从 0.894 µs 到约 1.0 µs，
  500 条从 1.662 µs 到约 2.0 µs），但相对未优化基线仍是 90% 以上的降幅。
- regex 规则的不命中成本由 AC 扫描 + 每值变换决定；500 条时约 2–3 µs。
- `(?i)` / 无字面量 regex 使用 RegexSet；500 条时约 3–4 µs，明显低于逐条执行 500 条正则。
- RegexSet 编译成本较高：500 条 `(?i)` 规则约 80–120 ms。热重载在 `spawn_blocking`
  中执行，旧规则继续服务，不会阻塞请求。
- 示例规则只有 2 条 `(?i)` regex，低于 RegexSet 阈值，因此逐条求值；这避免了小规则集
  上 RegexSet 的固定扫描开销（实测会从约 2.4 µs 恶化到约 4.3 µs）。
- 500 条 regex 规则编译约 5–9 ms；这是启动/热重载的一次性成本。

### 12.3 端到端结果

| 规则数 | 场景 | 并发 | RPS | p99 (ms) |
|---:|---|---:|---:|---:|
| 200 | regex+lowercase，不命中 | 32 | 56,420 | 1.022 |
| 200 | regex+lowercase，命中 1 条 | 32 | 57,121 | 1.013 |
| 200 | regex+lowercase，不命中 | 64 | 59,631 | 2.103 |
| 200 | regex+lowercase，命中 1 条 | 64 | 59,417 | 2.113 |
| 500 | regex+lowercase，不命中 | 32 | 57,779 | 0.988 |
| 500 | regex+lowercase，命中 1 条 | 32 | 57,038 | 0.996 |
| 500 | regex+lowercase，不命中 | 64 | 60,065 | 2.091 |
| 500 | regex+lowercase，命中 1 条 | 64 | 59,485 | 2.068 |

同轮 baseline：并发 32 为 58,412 RPS，并发 64 为 56,968 RPS。200/500 条 regex+lowercase
规则与空规则 baseline 的差异在噪声范围内。

500 条 `(?i)` regex（RegexSet 预筛）在一轮系统负载较高时的结果：

| 规则数 | 场景 | 并发 | RPS | p99 (ms) |
|---:|---|---:|---:|---:|
| 500 | `(?i)` regex，不命中 | 32 | 48,272 | 1.181 |
| 500 | `(?i)` regex，命中 1 条 | 32 | 45,859 | 1.211 |
| 500 | `(?i)` regex，不命中 | 64 | 50,804 | 2.283 |
| 500 | `(?i)` regex，命中 1 条 | 64 | 50,389 | 2.290 |

同轮空规则 baseline 为 59,417 RPS（并发 32）和 60,384 RPS（并发 64）。
该轮整体数字受系统负载影响偏低；同一轮中 `(?i)` RegexSet 与普通 regex+lowercase
变体的吞吐接近，说明 RegexSet 的端到端开销与 AC 变体相当，主要差异在引擎微基准中。

> 以上端到端数据为请求/响应能力扩展前的测量。扩展后请求匹配路径增加少量
> `MATCHED_VAR`/TX 写入和响应阶段检查；在网络路径中占比很小，未重新完整跑矩阵。

### 12.4 仍然存在的边界

- RegexSet 只在同一变换变体内 regex 模式数 ≥ 8 时启用；小集合逐条求值，这是刻意
  的性能取舍。提高覆盖率可以降低阈值，但会增加小规则集延迟。
- RegexSet 每个变体上限 512 个模式；超出后相关规则不做预筛。
- 匹配空字符串的 regex（`.*` 等）不做预筛。
- 变换变体数量受 16 个上限约束；极端规则集可能回退到逐条求值。
- 每个变体都会对扫描范围内的值应用变换；body 很大且变体很多时，预筛成本会上升。
  后续可以按“规则是否真的需要 body”进一步缩小变体扫描范围，或对大 body 做采样策略。

## 13. 真实 CRS 子集覆盖率（含文件/集合/日志阶段）

- 日期：2026-10-24
- CRS：`coreruleset/coreruleset`，commit `58ff33b`（v4.31.0-dev）
- 规则文件：`crs-setup.conf.example` + 18 个 `REQUEST-*.conf` + 9 个 `RESPONSE-*.conf`
- 加载方式：`lenient: true`，不支持的变量/算子/动作/阶段会被跳过
- 工具：`crates/aegis-engine/examples/prefilter_report.rs`
- 复现：`bash scripts/bench_crs.sh`（CRS 下载到 `target/crs`，不提交到仓库）

### 13.1 编译结果

| 指标 | 数值 |
|---|---:|
| 请求文件 | 28 |
| 可解析文件 | 28 |
| `SecRule`/`SecAction` 指令 | 693 |
| 编译成功规则 | 599（86.4%） |
| 跳过的规则指令 | 102（14.6%） |
| `SecDefaultAction` | 5 |
| 阶段分组 | 558 |

剩余跳过的主要原因是引擎尚未支持的：

- 变量计数语法（`&TX`、`&ARGS`、`&REQUEST_HEADERS`、`&MULTIPART_PART_HEADERS`），
  主要集中在 `REQUEST-901-INITIALIZATION.conf` 的初始化检查；
- `MULTIPART_PART_HEADERS`、`REQBODY_PROCESSOR`、`UNIQUE_ID` 等变量；
- `@validateUtf8Encoding`、`@validateUrlEncoding` 算子；
- 包含上述不支持项的链会整链跳过。

未知动作与 `ctl` 在 `lenient` 模式下会被忽略，不会导致规则被跳过。

### 13.2 预筛覆盖率

| 指标 | 数值 |
|---|---:|
| 分组总数 | 558 |
| 预筛分组 | 42（7.5%） |
| 其中 AC | 33 组 / 44 规则 |
| 其中 RegexSet | 9 组 / 11 规则 |
| 规则总数（按分组统计） | 599 |
| 预筛规则 | 55（9.2%） |
| 非 `SecAction` 算子的分组 | 550 |
| 非 `SecAction` 算子的预筛分组 | 42（7.6%） |
| **非 TX 算子分组** | **321** |
| **非 TX 算子预筛分组** | **42（13.1%）** |
| **非 TX 算子规则** | **360** |
| **非 TX 算子预筛规则** | **55（15.3%）** |

分组原因分解：

| 原因 | 分组 | 规则 |
|---|---:|---:|
| AC 字面量 | 33 | 44 |
| RegexSet | 9 | 11 |
| `SecAction` 无条件规则 | 8 | 8 |
| 含 TX 变量（异常评分） | 229 | 231 |
| 响应变量规则（Phase 3/4/5） | 61 | 62 |
| 算子取反 | 10 | 10 |
| 匹配空字符串的 regex | 5 | 9 |
| 小 regex 集合（< 8 个模式） | 181 | 199 |
| `REMOTE_ADDR` 规则 | 1 | 3 |
| 其他不可预筛算子 | 21 | 22 |

### 13.3 解释

- **总体覆盖率低的主因仍是 TX 异常评分规则**：229 个分组只读写 `TX` 做数值累计/比较，
  没有可提取的请求字面量；它们是廉价的整数比较，逐条求值成本很低。
- **响应阶段规则（61 组 / 62 规则）** 使用 `RESPONSE_STATUS`、`RESPONSE_HEADERS`、
  `RESPONSE_BODY` 等变量，不在请求预筛范围内；代理在收到上游响应后执行 Phase 3/4/5。
- 去掉 TX 和响应规则后，非 TX 请求算子规则的预筛覆盖率约为 **15.3%**。
  剩余未预筛的主要是小 regex 集合（199 条，同一变换变体内 < 8 个模式），
  按第 12 节阈值逐条求值；其次是取反算子、空匹配 regex、`REMOTE_ADDR` 等。
- 如果把 RegexSet 阈值降到 1，预筛覆盖会显著上升，但小规则集会退化；
  当前阈值 8 是性能与覆盖率的折中。
- **86.4% 的 CRS 规则指令已能编译**，比上一轮（78.1%）提升 8.3 个百分点，主要来自：
  `FILES`/multipart、`@pmFromFile`、`MATCHED_VARS`、持久化集合与 `initcol`、
  Phase 5/`skipAfter`、新增变换、`t:none` 与大小写不敏感的 `@pm`。
  剩余 14.6% 主要是变量计数语法、multipart 分部头变量、`REQBODY_PROCESSOR`/
  `UNIQUE_ID` 以及两个校验算子。

### 13.4 局限

- 这是“引擎能编译的子集”的覆盖率，不代表对完整 CRS 的检测效果。
- `lenient: true` 会跳过不支持的特性，可能导致部分规则语义不完整。
- 响应体检测仅在 `Content-Length` 存在且不超过 `max_response_body_bytes` 时执行；
  chunked 或超大响应只做 Phase 3 头检测，并直接透传响应体。
- Phase 5 在响应已生成后执行；其破坏性决策不改变返回给客户端的响应，
  但会反映在审计事件的决策字段中。
- CRS 规则来自外部仓库，版本更新后数字会变化。
- 覆盖率是静态统计，不等于运行时命中率或误报率。

## 14. 请求/响应能力扩展（2026-10-23）

### 14.1 新增变量

- 请求：`REQUEST_URI_RAW`、`REQUEST_LINE`、`REQUEST_PROTOCOL`、`REQUEST_BASENAME`、
  `REQUEST_HEADERS_NAMES`、`REQUEST_COOKIES_NAMES`、`REQUEST_BODY_LENGTH`、
  `ARGS:name` / `ARGS_GET:name` / `ARGS_POST:name` 选择器。
- 匹配上下文：`MATCHED_VAR`、`MATCHED_VAR_NAME`。
- XML：`XML` / `XML:/*` 提取元素文本与属性值（使用 `roxmltree`）。
- 响应：`RESPONSE_STATUS`、`RESPONSE_HEADERS[:name]`、`RESPONSE_HEADERS_NAMES`、
  `RESPONSE_BODY`、`RESPONSE_BODY_LENGTH`、`RESPONSE_CONTENT_TYPE`。

### 14.2 libinjection

- 使用纯 Rust 的 `barbacane-libinjection`（crate 名 `libinjectionrs`），
  与 C 版做过差分测试，Windows 上无需 C 工具链。
- 支持 `@detectSQLi` 与 `@detectXSS`，两者不做字面量预筛，逐条求值。

### 14.3 capture / MATCHED_VAR

- 支持 `capture` 动作：正则捕获组写入 `TX:0..9`，并设置
  `MATCHED_VAR` / `MATCHED_VAR_NAME`。
- 宏展开支持 `%{TX.n}`、`%{MATCHED_VAR}`、`%{MATCHED_VAR_NAME}`（大小写不敏感）。

### 14.4 ctl 子集

支持以下 `ctl`，其余 ctl 在 lenient 模式下忽略：

- `ctl:auditEngine=Off|On|RelevantOnly`：关闭/开启审计事件。
- `ctl:ruleEngine=Off|On|DetectionOnly`：关闭/开启后续破坏性动作；
  `DetectionOnly` 目前等同于不拦截。
- `ctl:ruleRemoveById=<id>`：后续跳过该规则。
- `ctl:ruleRemoveByTag=<tag>`：后续跳过带该 tag 的规则（按分组首规则判断）。

### 14.5 响应 Phase 3/4

- 引擎新增 Phase 3（响应头）与 Phase 4（响应体）；Phase 5 在下一轮加入（见第 15 节）。
- 代理在收到上游响应后：
  1. 执行 Phase 3（`RESPONSE_STATUS` / `RESPONSE_HEADERS`）；
  2. 若 `Content-Length` 存在且 ≤ `max_response_body_bytes`，缓冲响应体并执行 Phase 4；
  3. 任一阶段拦截则返回规则状态码，不再透传上游响应体。
- chunked 或超大响应只做 Phase 3，之后直接透传，避免破坏流式语义。

### 14.6 验证

- 139 个测试全部通过。
- `cargo fmt --check` 与 `cargo clippy --workspace --all-targets -- -D warnings` 通过。
- 新增 `crates/aegis-proxy/tests/proxy_response_integration.rs` 覆盖 Phase 3/4
  和响应体超限跳过逻辑。

## 15. CRS 兼容性扩展（2026-10-24）

### 15.1 新增能力

- **multipart/FILES**：内置 `multipart/form-data` 解析，提供 `FILES`、`FILES_NAMES`、
  `FILES_SIZES`、`FILES_COMBINED_SIZE`；`FILES_TMPNAMES` 为空（不落临时文件）。
- **`@pmFromFile`**：按规则文件相对路径读取词表，忽略空行与 `#` 注释；大小写不敏感。
  `@pm` 与 `@pmFromFile` 统一为大小写不敏感匹配，预筛也按小写变体建立。
- **持久化集合**：`IP`、`SESSION`、`USER`、`GLOBAL` 变量，`initcol` 动作，
  以及 `setvar:ip.`/`session.`/`user.`/`global.` 作用域；代理进程内共享
  `MemoryCollectionStore`，跨请求保留。
- **Phase 5 与 `skipAfter`**：Phase 5 在响应处理完成后执行；`skipAfter:<label>`
  跳到当前阶段对应 `SecMarker` 之后。
- **`MATCHED_VARS`**：当前简化为上一规则匹配的变量名。
- **新增变换**：`jsDecode`、`cssDecode`、`cmdLine`、`utf8toUnicode`、
  `escapeSeqDecode`、`removeWhitespace`、`replaceComments`、`removeCommentsChar`、
  `normalizePathWin`、`length`、`sha1`、`hexEncode`；`t:none` 清除继承的默认变换。

### 15.2 CRS 覆盖变化

- 可编译 `SecRule`/`SecAction` 从 **541（78.1%）** 提升到 **599（86.4%）**。
- 阶段分组从 511 增加到 558；可预筛规则 55 条（9.2%）。
- 详细数字与原因分解见第 13 节。

### 15.3 验证

- 149 个测试全部通过（引擎 112，代理 37）。
- `cargo fmt --check` 与 `cargo clippy --workspace --all-targets -- -D warnings` 通过。
- `bash scripts/bench_crs.sh` 可复现第 13 节的数字。
