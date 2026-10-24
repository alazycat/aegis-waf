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
| `FTW_EXCLUDE` | 空 | go-ftw `-e` 正则，追加排除项 |

## 基线（2026-10-24）

- CRS commit：`58ff33b`
- go-ftw：v2.6.1
- 全量：run=5259，success=5195，failed=63，skipped=1
- 门禁目录：passed=3547，failed=0，known-gap=44，stale-gap=0
- 非门禁失败（RESPONSE-* 等）只进入报告，不影响门禁

已知差异分类：

- hyper 在 WAF 之前拒绝或归一化的请求目标/请求头（原始 URI 字符、`encoded_request`）
- 非 UTF-8 请求字节被 lossy 转换（如 941310 malformed encoding）
- 少量 PCRE/transform 边界（如 `cmdLine` 与路径分隔符组合）

逐条原因见 `scripts/ftw-known-gaps.txt`。

## 调试

需要看 go-ftw 的通过/失败原因时：

```bash
FTW_NORMAL=1 FTW_INCLUDE='^942100-' bash scripts/ftw.sh --full
```

`FTW_NORMAL=1` 使用普通输出并附带 `--debug`，不生成 JSON 报告。

## 限制

- marker 机制依赖 `X-CRS-Test` 头与审计日志中的 `matched_rules[].id`
- hyper 在 WAF 之前拒绝的原始 HTTP 请求无法产生审计事件，相关用例列入已知差异
- go-ftw 拒绝发送包含裸 CR/LF 的请求头，并会中止整个运行；`921140-1` 因此由脚本固定排除
- 脚本把 CRS 测试复制到 `target/ftw/tests` 并移除 `retry_once: true`：
  go-ftw 在重试仍失败时会中止整个运行；本引擎 Phase 5 在审计写入前执行，不存在该竞态
- CRS 以 `lenient: true` 加载：CRS setup 使用 `auditlog` 动作，本引擎尚未实现该动作
- 已知差异不是通过标准；新增条目必须写明原因
