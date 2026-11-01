# ISeeCode v4.9（2026-11-01）

本版在 v4.8 基础上补齐规则覆盖、路由/鉴权提取与 Agent 任务状态，并修复 P1/P2 UI 问题。

## 规则与引擎

- 内置 Semgrep 规则覆盖 16 种语言：C/C++/C#/Dart/Go/HTML/Java/JavaScript/Kotlin/PHP/Python/Ruby/Rust/Scala/Swift/TypeScript。
- PHP 定向规则扩展到 13 条（含 MCP shell、调试开关、敏感默认值等）。
- 开源规则包：gosec 7 条 + njsscan 21 条（共 28 条）。`AUDIT_RULE_PACKS_MODE` 默认 `test`，支持 `off`；`extended` 预留且为空。规则文件缺失或 SHA256 不匹配时 fail-closed。项目特有的定向规则请放 `data/rules/`，不随仓库发布。
- 开源移植许可：gosec Apache-2.0、njsscan LGPL-3.0；未引入 AGPL 规则，详见 `app/skills/rule_pack_data/OPENSOURCE-NOTICE.md`。
- 规则命中仍是候选，不等于已验证漏洞。

## 路由与鉴权

- 修复 Java 类级 `@RequestMapping` 提取、JS 变量/多行 Express 路由、Django URLconf 解析。
- 路由归一化并排除前端目录，减少把客户端 API 调用当作服务端路由。
- 路由字典/鉴权结果仍需按具体任务复核。

## Agent / 任务

- 动态证据判定：区分真实 HTTP 请求/响应与 grep/静态输出。
- AgentRun 三态 claim + lease，支持中断后继续领取。
- 跨任务重复行去重，避免同一位置重复展示。
- 依赖 CVE 递归扫描工具 `tools/scan_dependencies.py`（Maven/npm/composer/requirements + OSV）。

## UI / 工程

- P1/P2 修复：报告与 POC 状态一致、API 空结果提示、时区展示、长代码换行、统一错误页。
- lab/沙箱统一视图；lab 操作只允许带 `iseecode.lab` 标签或名字以 `-lab` 结尾的容器。
- 本地 Lato/Fira Code 字体（SIL OFL 1.1）。

## 兼容性与边界

- Python 3.10+；本版不改数据库 schema。
- `verified` 只表示沙箱内验证，不代表生产环境可利用或 0day。
- 生产部署请设置强 `AUTH_TOKEN`/`AUTH_PASS`，不要把 `data/`、`master.key`、日志或真实 API key 提交到仓库。
