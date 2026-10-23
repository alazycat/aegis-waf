# aegis-waf

Rust 编写的反向代理 Web 应用防火墙（WAF）v0.1。

## 能力

- HTTP/1.1 反向代理
- ModSecurity `SecRule` 核心子集
- Phase 1（请求头/URI/参数/Cookie）与 Phase 2（请求体）检测
- `deny`/`block`/`allow`/`pass`、`status`、`msg`、`severity`、`tag`、`logdata`
- 变换、正则/字符串/IP/数值算子、`chain`
- TX 变量、`setvar` 与宏展开，可表达 CRS 风格异常评分
- 规则热重载（管理 API 与 Unix `SIGHUP`）
- 变量提取缓存与 Aho-Corasick 规则预筛（字面量型规则）
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
- `rules.lenient`：宽松模式下跳过未知指令/动作/变换和 Phase 3-5 规则。
- `limits`：URI/头部/请求体大小与读取超时。
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

- 不检测响应体
- 不终止 TLS，不支持 HTTP/2
- 不解析 multipart 表单
- 不完整支持 OWASP CRS，详见 `docs/compatibility.md`
- 不支持 `@detectSQLi`/`@detectXSS`、`ctl`、`skipAfter`、`capture`、持久化集合
- 变量取反当前按值排除，而非按变量项排除
- 头部大小限制在 hyper 解析后近似统计
- `on_error` 为未来引擎内部错误预留；当前引擎求值无可恢复错误路径

## 文档

- [设计文档](docs/superpowers/specs/2026-10-23-aegis-waf-design.md)
- [实现计划](docs/superpowers/plans/2026-10-23-aegis-waf-v0.1.md)
- [兼容性报告](docs/compatibility.md)
- [性能基准](docs/benchmarks.md)

## 许可证

Apache License 2.0
