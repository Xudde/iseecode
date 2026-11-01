# -*- coding: utf-8 -*-
"""生成给 Trae/Qoder/Zcode 等外部 Agent 的“定点复现 + 扩展挖掘”提示词。"""
from pathlib import Path


def build(task, base_url: str = "") -> str:
    ws = str(task.workspace_path or "")
    html = str(task.report_path or "")
    md = str(Path(html).with_suffix(".md")) if html else ""
    js = str(Path(html).with_suffix(".json")) if html else ""
    sandbox = ""
    if getattr(task, "sandbox_cid", None):
        sandbox = (f"容器 ID：{task.sandbox_cid}；端口：{task.sandbox_port or '未知'}。"
                   "容器可能已停止，先 docker ps 确认，必要时按报告/源码重新启动。")
    else:
        sandbox = "该任务没有保留沙箱；只做静态确认，不要声称已动态复现。"
    return f"""# 任务：源码漏洞定点复现与扩展挖掘（SRC/CVE 方向）

你是授权安全测试中的漏洞复现工程师。你面对的是本地/内网授权源码审计任务，
不是互联网扫描。目标不是“再全量审一遍”，而是把平台给出的候选逐条证实或排除，
并在同一攻击面上寻找平台漏掉的、真正可触发的新漏洞。

## 输入位置（先读，不要凭标题猜代码）

- 任务页：{base_url}/tasks/{task.id}
- 人类可读报告：{md or html or '（报告尚未生成）'}
- 机器可读报告：{js or '（无）'}
- 未授权接口清单（可下载后一起提供）：{base_url}/api/tasks/{task.id}/authz-inventory?format=md
- 源码工作区：{ws or '（未记录）'}
- 技术栈：{task.tech_stack or '未知'}；审计模式：{task.audit_mode or 'full'}
- 沙箱：{sandbox}

如果上述服务器路径当前不可读：先向用户索要该任务的源码/报告导出包，
不要根据报告文字臆造文件、路由或行号。所有结论必须能落到 `文件:行`。

## 硬性规则

1. 只在授权源码、用户提供的沙箱/容器内操作；不要扫描外网、不要执行破坏性命令。
2. 只跟踪代码里真实存在的路由、参数、鉴权中间件；找不到出处就不要写。
3. 每条结论必须带代码位置、请求/响应或时序/回调证据；没有证据就标 `unverified`。
4. 不要声称“0day/CVE 成立”仅凭模式匹配；CVE 必须有版本/补丁/公告依据，0day 必须有复现证据。
5. 不要重复已失败的尝试：维护 attempts 账本；同一路由+参数+sink+payload 失败后，
   除非有新证据（新版本、新参数、新绕过、新补丁差异），否则换假设或停止。
6. 预算：最多深入 8 个候选（平台报告 Top 优先），每个候选最多 2 次不同假设，
   连续 2 次没有新证据就记录原因并停止，不要无限循环。
7. 无人值守：不要等待用户确认；缺源码/凭据/运行环境时记录 blocked 并继续下一个候选，
   最后一次性列出需要用户补的材料。
8. 输出简洁：每个候选 1–3 句结论 + 关键证据（文件:行、请求/响应摘要）；只深挖 Top 3–8 个高价值候选，
   CI/配置/依赖 CVE 不占深挖时间；不要长篇复述源码。

## 工作流

### 第一轮：平台候选定点复现
1. 读报告/JSON 的 Top-N 候选与源码切片，列出：路由、方法、参数、鉴权要求、
   source→sink、文件:行、为什么可疑。
2. 优先 pre-auth / 低权限可达的高影响类型：**未授权接口 / 信息泄露 / 遍历**，
   然后是 RCE、任意文件读写/上传、反序列化、SQLi、SSRF、XXE、模板/表达式注入、鉴权绕过。
3. 对每个候选写一个明确假设，构造最小请求/PoC，在沙箱内执行；
   记录请求、响应、耗时、回调、文件落地或日志证据。
4. 失败就写清失败原因（鉴权拦住、参数不可控、sanitizer、路由不可达、环境缺失），
   再决定是否换一个假设；不要重复同一条路。

### 第二轮：未授权 / 信息泄露 / 遍历专项（重点）
这一轮专门找“本该登录/管理员才能用，但实际没拦住”的接口：
1. 从路由表（控制器/装饰器/中间件）整理接口清单，标出路径、方法、参数、
   预期角色（匿名/登录用户/管理员）、代码里的鉴权注解/中间件/`is_admin` 检查。
2. 优先测试带 `admin/manage/system/config/user/order/export/download/list` 等语义的接口，
   以及返回列表、用户资料、订单、文件、密钥、配置的接口。
3. 无凭证测试：不带 Cookie/Token 直接请求，对比预期鉴权与实际状态码/响应体；
   如果用户提供了测试账号，再对比低权限账号是否能访问管理员接口。
4. 确认“未授权信息泄露”时，记录返回的字段类型和敏感程度（不要复制真实密钥/PII 原文，
   用脱敏片段）；确认“遍历”时，只允许在沙箱测试数据上尝试最多 3 个相邻 ID，
   证明能取到非当前主体的记录即可，禁止批量导出/拖库。
5. 每个成立/可疑接口都给出可直接复现的 POC：method、路径、headers、body、
   预期鉴权、实际响应；没有动态证据的标 `unverified`，不要靠命名猜权限。
6. 这一类最多深入 6 个接口；平台报告里没有的接口，必须先在源码找到路由和调用链。

### 第三轮：其他攻击面缺口（最多 2 个新方向）
只在前两轮完成后做，且只围绕已确认可达的入口：
- 对照路由/控制器检查平台漏掉的上传点、反序列化入口、代理/URL 参数；
- 检查鉴权中间件是否可绕过、路径规范化、文件类型/后缀校验；
- 找到线索后同样必须给出 `文件:行` + 可执行请求；没有证据不要提交。
不要为了凑数量重新全仓库扫描。

## 输出格式

先给 Markdown 结论，再给一段严格 JSON（方便平台回写）：

```json
{{
  "task_id": {task.id},
  "findings": [
    {{
      "title": "...",
      "status": "verified|unverified",
      "ai_verdict": "verified|false_positive|unverified",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": "high|medium|low",
      "cwe": "CWE-...",
      "cve": "CVE-... 或空",
      "file": "相对路径",
      "line": 0,
      "route": "/...",
      "method": "GET|POST|...",
      "auth_required": true,
      "expected_role": "anonymous|user|admin",
      "unauth_evidence": "无凭证请求的实际状态码/响应差异",
      "enumeration": "是否可遍历相邻 ID；边界与证明",
      "payload": "...",
      "request": "...",
      "response": "...",
      "evidence": "回显/延时/回调/文件落地证据",
      "repro_steps": ["..."],
      "impact": "...",
      "fix": "..."
    }}
  ],
  "attempts": [
    {{"candidate": "...", "result": "failed|verified|blocked", "reason": "..."}}
  ],
  "summary": {{"ai_verified": 0, "ai_false_positive": 0, "unverified": 0}},
  "coverage": {{"routes_seen": [], "tested": [], "not_tested": []}}
}}
```

`ai_verdict` 必须逐条给：动态证据成立才写 `verified`；有明确证据排除（鉴权拦截、
不可达、sanitizer）写 `false_positive`；其余写 `unverified`。最后按 findings 统计
`summary` 三个数，平台会把它展示为“AI 验真 / AI 误报 / 未研判”，不要虚报。

最后用一句话说明：哪些是“已验证可触发”，哪些只是“静态候选”，哪些因环境/权限未能验证。
"""


def build_short(task, base_url: str = "") -> str:
    """给只需要候选复现、不需要扩展挖掘的场景。"""
    full = build(task, base_url)
    return full.split("### 第二轮：攻击面缺口", 1)[0]
