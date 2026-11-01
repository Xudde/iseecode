# ISeeCode 路线与状态（v4.9）

## v4.9 增量（2026-11-01）

- 多语言内置 Semgrep 规则覆盖 16 种语言；PHP 定向规则扩到 13 条
- 开源规则包：gosec 7 条 + njsscan 21 条；test/off 可切换，extended 预留；定向规则走 `data/rules/`
- 路由提取修复：Java 类级注解、JS 变量/多行 Express、Django URLconf
- Agent 动态证据/领取状态、任务去重、依赖 CVE 递归扫描、P1/P2 UI 修复

## 已完成主线

- **阶段 0**：上传/解压、任务队列、时区、沙箱存活、CodeQL 路径可见化、利用链图
- **阶段 1**：框架鉴权语义（Express/Django/DRF/Spring）与未授权接口清单
- **阶段 2**：补丁差分、同 sink 变体搜索、GitHub compare/commit 拉取
- **阶段 3**：利用链引擎 + 沙箱验证模板（file_read/SSRF/upload/code_exec）
- **阶段 4**：外部 Agent 四阶段协议 + 内部 ReAct 四阶段 + 全量审计四阶段
- **阶段 5**：OSV watchlist/事件/Webhook/可选自动建任务
- **阶段 6**：沙箱内 ffuf 轻量路径发现（固定字典，不生成注入载荷）
- **阶段 7**：
  - 审计事件、AES-GCM 配置密钥加密
  - 沙箱最小权限、只读根、依赖日志、egress 白名单代理
  - CLI、admin/auditor/viewer 令牌角色
  - EngineSpec 注册表与 `data/rules` 自定义 Semgrep 规则

## 当前边界

- 静态扫描有误报/漏报；`verified` 只代表沙箱内验证，不等于生产可利用或 0day
- 阶段 6 的注入/变异 fuzz 未内置（涉及生成攻击载荷）；当前只做路径发现
- 沙箱工作区在依赖安装阶段仍为读写；Java/Maven 的 Spring Boot 场景覆盖有限
- egress 白名单只覆盖 HTTP/HTTPS 包管理器流量，不是通用网络沙箱
- 外部 Python 插件不自动加载；扩展引擎需代码内 `register(EngineSpec)`
- 真正的多用户 RBAC（用户表/密码哈希/资源权限）尚未实现，当前是令牌级只读角色

## 可能的下一步

1. 多用户 RBAC 与用户管理 UI
2. 外部 CLI 引擎 manifest（子进程隔离）而非任意 Python 插件
3. 沙箱工作区在 POC 阶段切换为只读（需要重建容器或独立验证容器）
4. Java/Maven 沙箱完整回归
5. 报告/漏洞结果的更多导出格式与团队协作
