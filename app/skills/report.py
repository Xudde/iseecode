"""报告生成 skill：双版本输出
- 人看版：自包含 HTML（主）+ Markdown（存档），面向审计人员阅读
- AI 版：结构化 JSON（task_{id}_report.json），面向下游 AI / 工单 / 研判系统消费
"""
import html
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.audit_labels import vuln_label
from app.config import REPORT_DIR

# 报告展示统一按 Asia/Shanghai，不依赖 uvicorn/cron 进程的本地时区。
CN_TZ = timezone(timedelta(hours=8))


def _now_cn() -> str:
    return datetime.now(CN_TZ).strftime("%Y-%m-%d %H:%M:%S")

SEVERITY_ORDER = {"CRITICAL": 0, "ERROR": 0, "HIGH": 0, "WARNING": 1, "MEDIUM": 1, "INFO": 2, "LOW": 2}
SEVERITY_COLORS = {
    "CRITICAL": "#d63031", "ERROR": "#d63031", "HIGH": "#e17055",
    "WARNING": "#fdcb6e", "MEDIUM": "#fdcb6e",
    "INFO": "#74b9ff", "LOW": "#74b9ff",
}

_PAGE_CSS = """\
:root{--bg:#f4f6fb;--card:#fff;--ink:#1e272e;--muted:#7f8c9b;--line:#e8ecf3;--brand:#0a66c2;}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;background:var(--bg);color:var(--ink);line-height:1.6;padding:32px 16px}
.wrap{max-width:1800px;margin:0 auto}
h1{font-size:24px}
h2{font-size:17px;margin:28px 0 12px;padding-left:10px;border-left:4px solid var(--brand)}
.hero{background:linear-gradient(135deg,#0a66c2,#1e90ff);color:#fff;border-radius:12px;padding:24px 28px;margin-bottom:20px}
.hero h1{margin-bottom:8px}
.hero .meta{font-size:13px;opacity:.92}
.hero .meta span{margin-right:18px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;text-align:center}
.card .num{font-size:26px;font-weight:700}
.card .lbl{font-size:12px;color:var(--muted);margin-top:2px}
.card.ok .num{color:#00a86b}.card.bad .num{color:#d63031}.card.warn .num{color:#e17055}.card.info .num{color:#0a66c2}
.vuln{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px 20px;margin-bottom:14px}
.vuln .head{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.vuln .idx{font-size:13px;color:var(--muted)}
.badge{color:#fff;font-size:12px;font-weight:600;padding:2px 10px;border-radius:10px;letter-spacing:.5px;white-space:nowrap}
.badge.poc{background:#00a86b}.badge.nopoc{background:#e0e4ec;color:#555}
.vuln .rule{font-size:15px;font-weight:600}
.vuln .kv{display:grid;grid-template-columns:auto 1fr;gap:4px 14px;font-size:13px;margin:12px 0}
.vuln .kv b{color:var(--muted);font-weight:600;min-width:72px}
.vuln .kv span{white-space:pre-wrap;word-break:break-word}
pre.code{background:#1e272e;color:#a5f3b0;border-radius:8px;padding:12px 14px;font-size:12.5px;overflow:auto;white-space:pre-wrap;word-break:break-word;overflow-wrap:anywhere;margin-top:10px;font-family:ui-monospace,Consolas,"Courier New",monospace}
.payload{background:#fff8e1;border:1px dashed #f0c14b;border-radius:8px;padding:8px 12px;font-size:12.5px;word-break:break-word;white-space:pre-wrap;margin-top:8px}
.result{background:#eef9f2;border-left:4px solid #00a86b;padding:8px 12px;border-radius:6px;font-size:13px;margin-top:8px;white-space:pre-wrap;word-break:break-word}
.result.no{border-color:#d63031;background:#fdecec}
.reason{background:#f6f8fc;border-radius:8px;padding:10px 12px;font-size:13px;margin-top:10px;border-left:4px solid #0a66c2;white-space:pre-wrap;word-break:break-word;line-height:1.7}
.evidence{background:#f0f7f0;border-left:4px solid #00a86b;border-radius:8px;padding:10px 12px;font-size:13px;margin-top:10px;white-space:pre-wrap;word-break:break-word}
.evidence pre{white-space:pre-wrap;font-size:12px;margin-top:6px;font-family:ui-monospace,Consolas,monospace}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:13px}
th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
td code, th code{word-break:break-all}
th{background:#fafbfd;color:var(--muted);font-weight:600}
tr:last-child td{border-bottom:none}
.pill{display:inline-block;font-size:11.5px;padding:1px 8px;border-radius:8px;font-weight:600;white-space:nowrap}
.pill.verified{background:#e2f5ec;color:#00a86b}.pill.fp{background:#fdecec;color:#d63031}
.pill.na{background:#eef1f5;color:var(--muted)}
.pill.ok{background:#e2f5ec;color:#00a86b}.pill.no{background:#fdecec;color:#d63031}.pill.dash{background:#eef1f5;color:var(--muted)}
.empty{background:var(--card);border:1px dashed var(--line);border-radius:10px;padding:28px;text-align:center;color:var(--muted)}
.note{background:#f4f8ff;border:1px solid #cfe0f5;border-radius:10px;padding:10px 14px;font-size:12.5px;color:#3d5a80;margin:14px 0}
.hot{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 18px;margin-bottom:12px}
.hot-top{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.hot-rank{font-size:13px;color:var(--muted);font-weight:700}
.hot-top code{font-size:13px;word-break:break-all;color:var(--brand);background:#f4f8ff;padding:1px 6px;border-radius:5px}
.hot-score{margin-left:auto;font-size:12px;color:var(--brand);font-weight:600}
.hot .why{font-size:13px;margin-top:7px}
.hot .kv{margin:6px 0;font-size:13px}
.hot .focus{margin-top:8px;font-size:12.5px;color:#3d5a80;background:#f4f8ff;border-radius:6px;padding:7px 10px}
td{word-break:break-word}
.static-all{margin-top:8px}
.static-all summary{cursor:pointer;color:var(--brand);font-weight:600;font-size:13px;margin:8px 0}
.static-all[open] summary{margin-bottom:10px}
.chain-card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:12px}
.chain-head{display:flex;gap:10px;align-items:center;flex-wrap:wrap;font-size:14px}
.chain-head .ok{color:#00a86b;font-size:12px}.chain-head .pending{color:#e17055;font-size:12px}
.chain-flow{font-family:ui-monospace,Consolas,monospace;font-size:12px;line-height:1.8;margin:8px 0;word-break:break-word}
.chain-node{border-top:1px dashed var(--line);padding:8px 0;font-size:12px}
.chain-node b{color:var(--brand);margin-right:6px}.chain-node code{background:#f4f8ff;color:var(--brand);padding:1px 5px;border-radius:4px;word-break:break-all}
.chain-node .ev{color:#3d5a80;white-space:pre-wrap;margin-top:4px;word-break:break-word}
footer{text-align:center;color:var(--muted);font-size:12px;margin-top:36px}
@media (prefers-color-scheme: dark){
  :root{--bg:#0f1012;--card:#17191d;--ink:#e6e9ef;--muted:#9aa4b2;--line:#2a2f36;--brand:#4da3ff}
  body{background:var(--bg);color:var(--ink)}
  th{background:#1f232a}
  .reason,.note,.hot .focus,.hot-top code,.chain-node code{background:#1b2330;color:#b9d4f5;border-color:#2d3b4f}
  .chain-node .ev{color:#b9d4f5}
  .payload{background:#2a2413;border-color:#7a6420;color:#f0d9a0}
  .result{background:#12261b;color:#a7e8c3}
  .result.no{background:#2a1516}
  .evidence{background:#12261b}
  .badge.nopoc{background:#2a2f36;color:#c3cad4}
  .pill.na,.pill.dash{background:#2a2f36;color:#c3cad4}
  .pill.verified,.pill.ok{background:#12261b;color:#5fd39a}
  .pill.fp,.pill.no{background:#2a1516;color:#ff8a84}
}
"""


def _sev_badge(sev: str) -> str:
    color = SEVERITY_COLORS.get((sev or "").upper(), "#636e72")
    return f'<span class="badge" style="background:{color}">{html.escape((sev or "N/A").upper())}</span>'


def _vt(v) -> str:
    """漏洞展示名：LLM 生成的中文名优先，其次内置规则名映射，最后规则 ID 尾段"""
    if v.get("title"):
        return str(v["title"])
    return vuln_label(v.get("rule_id", ""))


def _fmt_text(text: str) -> str:
    """把内联的 1) 2) 3)、•、-、一、二、等分点拆成行，便于报告阅读。"""
    t = str(text or "")
    t = re.sub(r"(?<!\n)\s+(?=\d{1,2}[.)、]\s)", "\n", t)
    t = re.sub(r"(?<!\n)\s+(?=[•·]|[-*]\s)", "\n", t)
    t = re.sub(r"(?<!\n)\s+(?=[一二三四五六七八九十]+、)", "\n", t)
    t = re.sub(r"([；;])\s*(?=(?:\d{1,2}[.)、]\s|[一二三四五六七八九十]+、|[•·]))", r"\1\n", t)
    return t


def _poc_badge(v: dict) -> str:
    if v.get("poc_verified") is True:
        return '<span class="badge poc">POC 已复现</span>'
    if v.get("poc_verified") is False:
        return '<span class="badge nopoc">POC 未复现</span>'
    return '<span class="badge nopoc">未验证</span>'


def _judge_pill(v: dict) -> str:
    status = v.get("agent_status")
    if v.get("llm_is_real") is True or status == "verified":
        return '<span class="pill verified">Agent 确认真实</span>'
    if v.get("llm_is_real") is False or status == "false_positive":
        return '<span class="pill fp">误报</span>'
    return '<span class="pill na">未研判</span>'


def _poc_pill(v: dict) -> str:
    if v.get("poc_verified") is True:
        return '<span class="pill ok">已复现</span>'
    if v.get("poc_verified") is False:
        return '<span class="pill no">未复现</span>'
    return '<span class="pill dash">—</span>'


def _vuln_card(i: int, v: dict) -> str:
    snippet = html.escape((v.get("code_snippet") or "").strip()[:1600])
    payload = html.escape(_fmt_text(v.get("poc_payload") or ""))
    verify = html.escape(_fmt_text(v.get("verify_result") or ""))
    evidence = _fmt_text(v.get("agent_evidence") or "")
    is_codeql = str(v.get("rule_id") or "").startswith("codeql:")
    reason = _fmt_text(v.get("llm_reason") or v.get("agent_reason") or "")
    confidence = v.get("agent_confidence") or v.get("llm_confidence") or "-"
    poc_cls = "result" + ("" if v.get("poc_verified") is True else " no")
    parts = [
        '<div class="vuln">',
        '<div class="head">',
        f'<span class="idx">#{i}</span>{_sev_badge(v.get("severity",""))}{_judge_pill(v)}{_poc_badge(v)}',
        f'<span class="rule" title="{html.escape(v.get("rule_id",""))}">{html.escape(_vt(v))}</span>',
        "</div>",
        '<div class="kv">',
        f"<b>位置</b><span>{html.escape(v.get('file_path',''))}:{v.get('line','')}</span>",
        f"<b>置信度</b><span>{html.escape(str(confidence))}</span>",
    ]
    if v.get("precondition"):
        parts.append(f"<b>复现条件</b><span>{html.escape(_fmt_text(str(v['precondition'])))}</span>")
    parts.append("</div>")
    if reason:
        parts.append(f'<div class="reason"><b>研判理由：</b>{html.escape(reason)}</div>')
    if payload:
        parts.append(f'<div class="payload"><b>POC Payload：</b><code>{payload}</code></div>')
    if verify:
        parts.append(f'<div class="{poc_cls}"><b>动态验证结果：</b>{verify}</div>')
    if evidence:
        label = "CodeQL 数据流路径" if is_codeql else "Agent 证据链"
        parts.append(f'<div class="evidence"><b>{label}：</b><pre>{html.escape(evidence)}</pre></div>')
    parts.append(f'<pre class="code">{snippet}</pre>')
    parts.append("</div>")
    return "\n".join(parts)


def _parse_exploitability(evidence: str) -> str:
    m = re.match(r"\s*\[exploitability=([a-zA-Z]+)\]", evidence or "")
    return m.group(1).lower() if m else ""


def _verdict_of(v: dict) -> str:
    if v.get("agent_status") in ("verified", "false_positive", "unverified", "error"):
        return v["agent_status"]
    if v.get("llm_is_real") is True:
        return "verified"
    if v.get("llm_is_real") is False:
        return "false_positive"
    return "unjudged"


def _fingerprint_dict(task) -> dict | None:
    raw = getattr(task, "fingerprint", "") or ""
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return None


def _build_ai_report(task, vulns: list[dict], real, false_positive, unjudged, poc_passed,
                     hotlist: dict | None = None, chains: list[dict] | None = None) -> dict:
    """构建 AI 版结构化报告（schema: source-audit-report/1.0）"""
    now = _now_cn()

    def _by_sev(items):
        out = {}
        for v in items:
            k = (v.get("severity") or "N/A").upper()
            out[k] = out.get(k, 0) + 1
        return out

    findings = []
    order = {"verified": 0, "unjudged": 1, "error": 2, "unverified": 1, "false_positive": 3}
    for v in sorted(vulns, key=lambda x: (order.get(_verdict_of(x), 9),
                                          SEVERITY_ORDER.get((x.get("severity") or "").upper(), 3))):
        findings.append({
            "id": v.get("id"),
            "source": v.get("source") or "semgrep",
            "rule_id": v.get("rule_id") or "",
            "title": v.get("title") or "",
            "precondition": v.get("precondition") or "",
            "label": vuln_label(v.get("rule_id") or ""),
            "severity": (v.get("severity") or "INFO").upper(),
            "file_path": v.get("file_path") or "",
            "line": v.get("line") or 0,
            "verdict": _verdict_of(v),
            "confidence": v.get("agent_confidence") or v.get("llm_confidence"),
            "exploitability": _parse_exploitability(v.get("agent_evidence") or "") or None,
            "reason": v.get("agent_reason") or v.get("llm_reason") or "",
            "evidence": v.get("agent_evidence") or "",
            "poc": {
                "payload": v.get("poc_payload") or "",
                "verified": v.get("poc_verified"),
                "result": v.get("verify_result") or "",
            },
            "code_snippet": (v.get("code_snippet") or "")[:2000],
            "analyzed_at": str(v.get("analyzed_at") or ""),
        })

    fp = _fingerprint_dict(task)
    dynamic_done = any(v.get("poc_verified") is not None for v in vulns)

    caveats = []
    if not dynamic_done:
        caveats.append("全部 finding 的 POC 均未经动态验证（无可用沙箱或任务类型不支持；沙箱为禁网环境，"
                       "真实 Java/Node 项目通常无法拉取依赖），verdict 为静态研判结论，payload 字段未经实际触发确认")
    if unjudged:
        caveats.append(f"{len(unjudged)} 条超出研判上限未处理，verdict=unjudged，可能包含真实漏洞")
    if (getattr(task, "audit_mode", "full") or "full") == "static":
        caveats.append("本任务为仅静态扫描模式，未执行 LLM/Agent 研判与动态验证")
    if (getattr(task, "audit_mode", "full") or "full") == "poc":
        caveats.append("本任务为沙箱 POC 验证模式，仅部署沙箱并验证命中，未执行 LLM/Agent 研判")
    if (getattr(task, "audit_mode", "full") or "full") == "large":
        caveats.append("本任务为大项目模式：已取消文件数熔断，CodeQL/全量审计耗时与 token 消耗可能较高")
    if getattr(task, "project_type", "") == "driver":
        caveats.append("驱动审计为静态 PE/导入/启发式 + capa/Ghidra 反汇编（如已安装），未加载驱动；"
                       "IOCTL/DACL 需人工复核")
    audit_fused = "全量审计已熔断" in (getattr(task, "log", "") or "")
    if audit_fused:
        caveats.append("全量审计已按文件数熔断跳过（大仓库全量审计实测产出极低），静态扫描与 Agent 研判结果不受影响")

    return {
        "schema": "source-audit-report/1.0",
        "report_type": "ai",
        "generated_at": now,
        "task": {
            "id": task.id,
            "filename": task.filename,
            "project_type": getattr(task, "project_type", "web"),
            "tech_stack": [s.strip() for s in (task.tech_stack or "").split(",") if s.strip()],
            "audit_mode": getattr(task, "audit_mode", "full"),
            "status": task.status,
            "created_at": str(task.created_at or ""),
            "tokens_used_estimate": getattr(task, "tokens_used", 0) or 0,
            "fingerprint": fp,
        },
        "summary": {
            "total_findings": len(vulns),
            "verified": len(real),
            "false_positive": len(false_positive),
            "unjudged": len(unjudged),
            "poc_verified": len(poc_passed),
            "by_severity": _by_sev(vulns),
            "verified_by_severity": _by_sev(real),
            "dynamic_verification_performed": dynamic_done,
        },
        "caveats": caveats,
        "hotlist": hotlist or {},
        "chains": chains or [],
        "findings": findings,
    }


def run_report(task, vulns: list[dict], hotlist: dict | None = None,
               chains: list[dict] | None = None) -> str:
    """生成三份报告：人看版 HTML（主）/ Markdown（存档）+ AI 版 JSON，返回 HTML 路径。
    hotlist：可选的人工深挖 Top-N 清单；chains：可选利用链（nodes/edges/verified）。"""
    now = _now_cn()

    def _real(v):
        return v.get("llm_is_real") is True or v.get("agent_status") == "verified"

    def _fp(v):
        return v.get("llm_is_real") is False or v.get("agent_status") == "false_positive"

    real = [v for v in vulns if _real(v)]
    false_positive = [v for v in vulns if _fp(v)]
    unjudged = [v for v in vulns if not _real(v) and not _fp(v)]
    poc_passed = [v for v in vulns if v.get("poc_verified") is True]
    real.sort(key=lambda v: SEVERITY_ORDER.get((v.get("severity") or "").upper(), 3))

    audit_note = ("；全量审计已按文件数熔断跳过（静态扫描与研判结果不受影响）"
                  if "全量审计已熔断" in (getattr(task, "log", "") or "") else "")
    driver_note = ("；驱动审计为静态 PE/导入/启发式 + capa/Ghidra 反汇编（如已安装），未加载驱动"
                   if getattr(task, "project_type", "") == "driver" else "")
    target_label = "驱动文件" if getattr(task, "project_type", "") == "driver" else "源码包"
    dynamic_note = ""
    if not any(v.get("poc_verified") is not None for v in vulns):
        dynamic_note = ('<div class="note"><b>阅读提示</b>：本报告所有结论均为静态研判（未执行动态 POC 验证；'
                        '沙箱为禁网环境，真实 Java/Node 项目通常无法部署），'
                        'verified 不代表 payload 已实际触发，请结合部署环境人工复核'
                        + audit_note + driver_note + '。</div>')

    hot_section = ""
    hot_md: list[str] = []
    hot_items = (hotlist or {}).get("items") or []
    if hot_items:
        blocks = []
        for it in hot_items:
            finds = "".join(
                f'<div class="kv"><b>命中</b><span>{_sev_badge(f.get("severity", ""))} '
                f'{html.escape(str(f.get("title") or ""))}'
                f'（第 {f.get("line", 0)} 行 · {html.escape(str(f.get("source") or ""))}）</span></div>'
                for f in (it.get("findings") or [])[:5])
            blocks.append(
                '<div class="hot">'
                f'<div class="hot-top"><span class="hot-rank">#{it.get("rank")}</span>'
                f'<code>{html.escape(str(it.get("file_path") or ""))}</code>'
                f'<span class="hot-score">优先级 {it.get("score")}</span></div>'
                f'<div class="why"><b>为什么先看：</b>{html.escape("；".join(it.get("reasons") or []))}</div>'
                + finds +
                f'<div class="focus"><b>建议动作：</b>{html.escape(str(it.get("focus") or ""))}</div>'
                '</div>')
        hot_section = (
            f"<h2>人工深挖 Top {len(hot_items)} 文件（按优先级）</h2>"
            '<div class="note"><b>怎么用</b>：从第 1 个文件开始读，配合 Trae/Qoder 的'
            '「单点打穿」提示词；不需要再从全仓目录重新扫。</div>'
            + "".join(blocks))
        hot_md = ["## 人工深挖 Top-N 文件（按优先级）", "",
                  "> 从第 1 个文件开始读，配合 IDE Agent 的「单点打穿」提示词；不需要重新扫全仓。", ""]
        for it in hot_items:
            hot_md += [f"### {it.get('rank')}. `{it.get('file_path')}`（优先级 {it.get('score')}）", "",
                       f"- **为什么先看**：{'；'.join(it.get('reasons') or [])}"]
            for f in (it.get("findings") or [])[:5]:
                hot_md.append(f"- **命中**：{f.get('severity')} {f.get('title')}"
                              f"（第 {f.get('line')} 行 · {f.get('source')}）")
            hot_md += [f"- **建议动作**：{it.get('focus', '')}", ""]

    chain_section = ""
    chain_md: list[str] = []
    if chains:
        cblocks = []
        for i, c in enumerate(chains, 1):
            nodes = c.get("nodes") or []
            flow = " → ".join(
                str(n.get("label") or n.get("type") or "") for n in nodes
                if (n.get("label") or n.get("type")))
            nhtml = "".join(
                f'<div class="chain-node"><b>{html.escape(str(n.get("type") or "node"))}</b>'
                f'{html.escape(str(n.get("label") or ""))}'
                + (f' <code>{html.escape(str(n.get("file") or ""))}:{n.get("line", "")}</code>' if n.get("file") else "")
                + (f'<div class="ev">{html.escape(_fmt_text(str(n.get("evidence") or n.get("code") or "")))}</div>' if (n.get("evidence") or n.get("code")) else "")
                + '</div>' for n in nodes)
            cblocks.append(
                f'<div class="chain-card"><div class="chain-head"><b>#{i} {html.escape(str(c.get("title") or "利用链"))}</b>'
                f'<span class="{"ok" if c.get("verified") else "pending"}">{"已验证" if c.get("verified") else "待验证"}</span></div>'
                f'<div class="chain-flow">{html.escape(flow)}</div>'
                f'<details><summary>节点详情</summary>{nhtml}</details></div>')
            chain_md += [f"### {i}. {'✅' if c.get('verified') else '⚠️'} {c.get('title') or '利用链'}", "",
                         f"- **状态**：{'已验证' if c.get('verified') else '待验证'}",
                         f"- **路径**：{flow}", ""]
            for n in nodes:
                loc = f" (`{n.get('file')}:{n.get('line')}`)" if n.get("file") else ""
                ev = str(n.get("evidence") or n.get("code") or "").strip()
                chain_md.append(f"  - **{n.get('type') or 'node'}**：{n.get('label') or ''}{loc}"
                                + (f" — {_fmt_text(ev)}" if ev else ""))
        chain_section = f"<h2>利用链（{len(chains)}）</h2>" + "".join(cblocks)
        chain_md = ["## 利用链", ""] + chain_md

    sev_rows = "".join(
        f'<tr><td>{i}</td><td>{_sev_badge(v["severity"])}</td>'
        f'<td title="{html.escape(v["rule_id"])}">{html.escape(_vt(v))}</td>'
        f'<td><code>{html.escape(v["file_path"])}:{v["line"]}</code></td>'
        f'<td>{_judge_pill(v)}</td><td>{_poc_pill(v)}</td></tr>'
        for i, v in enumerate(vulns, 1)
    ) or '<tr><td colspan="6" style="color:var(--muted)">无静态扫描结果</td></tr>'

    vuln_cards = "\n".join(_vuln_card(i, v) for i, v in enumerate(real, 1))
    vuln_section = (
        f"<h2>真实漏洞明细（{len(real)}）</h2>"
        + (vuln_cards if vuln_cards else '<div class="empty">未发现经确认的真实漏洞。</div>')
    )

    real_keys = {(v.get("rule_id"), v.get("file_path"), v.get("line")) for v in real}
    poc_only = [v for v in poc_passed
                if (v.get("rule_id"), v.get("file_path"), v.get("line")) not in real_keys]
    poc_section = ""
    if poc_only:
        poc_section = (
            f"<h2>POC 动态复现明细（{len(poc_only)}）</h2>"
            + "\n".join(_vuln_card(i, v) for i, v in enumerate(poc_only, 1))
        )

    cve_rows = [v for v in vulns
                if str(v.get("rule_id", "")).startswith("giants:self-cve:")]
    cve_section = ""
    if cve_rows:
        cve_table = "".join(
            f'<tr><td>{i}</td><td>{_sev_badge(v.get("severity", ""))}</td>'
            f'<td>{html.escape(v.get("title") or "")}</td>'
            f'<td><code>{html.escape(v.get("file_path", ""))}:{v.get("line", "")}</code></td>'
            f'<td>{html.escape((v.get("code_snippet") or "").split("；")[0])}</td></tr>'
            for i, v in enumerate(cve_rows[:30], 1)
        )
        cve_section = (
            f"<h2>项目自身版本 CVE（OSV，{len(cve_rows)}）</h2>"
            '<div class="note">按项目自身名称+版本查询 OSV，只发送包名与版本号；'
            "版本命中不等于已复现根因，需结合代码/部署确认。"
            + ("仅展示前 30 条。" if len(cve_rows) > 30 else "") + "</div>"
            "<table><thead><tr><th>#</th><th>等级</th><th>CVE / 包</th>"
            "<th>位置</th><th>修复版本</th></tr></thead>"
            f"<tbody>{cve_table}</tbody></table>"
        )

    authz_rows = [v for v in vulns
                  if str(v.get("rule_id", "")).startswith("authz:")]
    authz_section = ""
    if authz_rows:
        rows = "".join(
            f'<tr><td>{i}</td><td>{_sev_badge(v.get("severity", ""))}</td>'
            f'<td>{html.escape(v.get("title") or "")}</td>'
            f'<td><code>{html.escape(v.get("file_path", ""))}:{v.get("line", "")}</code></td>'
            f'<td><pre class="code" style="margin:0;white-space:pre-wrap">'
            f'{html.escape(v.get("poc_payload") or "")}</pre></td></tr>'
            for i, v in enumerate(authz_rows[:30], 1)
        )
        authz_section = (
            f"<h2>未授权接口候选（静态，{len(authz_rows)}）</h2>"
            '<div class="note">未发现鉴权标记 ≠ 未授权；全局中间件/框架安全配置需'
            "沙箱无凭证验证。以下为候选与 POC 请求，未动态验证前不要写成已复现。"
            + ("仅展示前 30 条。" if len(authz_rows) > 30 else "") + "</div>"
            "<table><thead><tr><th>#</th><th>等级</th><th>接口</th>"
            "<th>位置</th><th>无凭证 POC</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
        )

    fp_line = ""
    fp = _fingerprint_dict(task)
    if fp:
        comps = "、".join(fp.get("components") or []) or "未识别到知名组件"
        langs = "；".join(
            f"{k} {c}文件" for k, c in sorted(
                (fp.get("lang_stats") or {}).items(), key=lambda x: -x[1])[:6]
        ) or "-"
        fp_line = (f'<div style="margin-top:10px;font-size:13px;color:#dbeafe;">'
                   f'<b>组件指纹：</b>{html.escape(comps)} ｜ '
                   f'<b>语言分布：</b>{html.escape(langs)} ｜ '
                   f'<b>文件数：</b>{fp.get("total_files", 0)}</div>')

    guide = ('<div class="note"><b>怎么读</b>：先看“真实漏洞明细”和“POC 复现”；'
             '“静态扫描”里的命中只是候选，不等于已验证。误报/未研判不要直接当漏洞上报。</div>')

    priority = []
    seen_keys = set()
    for v in (real + poc_passed):
        key = (v.get("rule_id"), v.get("file_path"), v.get("line"))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        priority.append(v)
        if len(priority) >= 5:
            break
    if priority:
        prows = "".join(
            f'<tr><td>{i}</td><td>{_sev_badge(v.get("severity",""))}</td>'
            f'<td>{html.escape(_vt(v))}</td>'
            f'<td><code>{html.escape(v.get("file_path",""))}:{v.get("line","")}</code></td>'
            f'<td>{_poc_pill(v)}</td></tr>'
            for i, v in enumerate(priority, 1))
        priority_section = ('<h2>优先处理（前 5 条）</h2>'
                            '<div class="note">建议先按顺序核对入口/参数/鉴权，'
                            '再在沙箱复现；没有 POC 的条目按静态结论处理。</div>'
                            '<table><thead><tr><th>#</th><th>等级</th><th>漏洞</th>'
                            '<th>位置</th><th>POC</th></tr></thead>'
                            f'<tbody>{prows}</tbody></table>')
    else:
        priority_section = ''

    html_out = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>审计报告 - {html.escape(task.filename)}</title>
<style>{_PAGE_CSS}</style>
</head>
<body>
<div class="wrap">
  <div class="hero">
    <h1>源码自动化审计报告</h1>
    <div class="meta">
      <span>任务 ID：#{task.id}</span>
      <span>{target_label}：{html.escape(task.filename)}</span>
      <span>技术栈：{html.escape(task.tech_stack)}</span>
      <span>生成时间：{now}（Asia/Shanghai）</span>
    </div>
    {fp_line}
  </div>

  <div class="cards">
    <div class="card info"><div class="num">{len(vulns)}</div><div class="lbl">静态扫描发现</div></div>
    <div class="card bad"><div class="num">{len(real)}</div><div class="lbl">Agent 确认真实</div></div>
    <div class="card warn"><div class="num">{len(false_positive)}</div><div class="lbl">误报（Agent 排除）</div></div>
    <div class="card"><div class="num">{len(unjudged)}</div><div class="lbl">未经研判</div></div>
    <div class="card ok"><div class="num">{len(poc_passed)}</div><div class="lbl">POC 验证通过</div></div>
  </div>

  {dynamic_note}
  {guide}
  {priority_section}
  {chain_section}
  {hot_section}
  {vuln_section}
  {poc_section}
  {cve_section}
  {authz_section}

  <details class="static-all">
  <summary>静态扫描全量结果（{len(vulns)}）— 点击展开</summary>
  <table>
    <thead><tr><th>#</th><th>严重性</th><th>规则</th><th>位置</th><th>研判</th><th>POC</th></tr></thead>
    <tbody>{sev_rows}</tbody>
  </table>
  </details>

  <footer>由源码自动化审计平台生成 · {now}（Asia/Shanghai） · 机器可读版见 task_{task.id}_report.json</footer>
</div>
</body>
</html>
"""
    out = REPORT_DIR / f"task_{task.id}_report.html"
    out.write_text(html_out, encoding="utf-8")

    # ---------- Markdown 版（人看，存档/复制用） ----------
    def _mk(flag):
        return {True: "已复现", False: "未复现", None: "—"} .get(flag if flag is not None else None, "—")

    lines = [
        "# 源码自动化审计报告",
        "",
        f"- **任务 ID**：{task.id}",
        f"- **{target_label}**：{task.filename}",
        f"- **技术栈**：{task.tech_stack}",
        f"- **生成时间**：{now}（Asia/Shanghai）",
        "",
    ]
    if fp:
        comps = "、".join(fp.get("components") or []) or "未识别到知名组件"
        langs = "；".join(f"{k} {c}文件" for k, c in sorted(
            (fp.get("lang_stats") or {}).items(), key=lambda x: -x[1])[:6])
        lines += [f"- **组件指纹**：{comps}（语言分布：{langs}）", ""]

    lines += [
        "## 概览",
        "",
        "| 指标 | 数量 |",
        "| --- | --- |",
        f"| 静态扫描发现 | {len(vulns)} |",
        f"| Agent 确认真实 | {len(real)} |",
        f"| 误报（Agent 排除） | {len(false_positive)} |",
        f"| 未经研判 | {len(unjudged)} |",
        f"| POC 验证通过 | {len(poc_passed)} |",
        "",
    ]
    if dynamic_note:
        lines += ["> 阅读提示：本报告所有结论均为静态研判（未执行动态 POC 验证；沙箱为禁网环境，"
                  "真实 Java/Node 项目通常无法部署），verified 不代表 payload 已实际触发"
                  + audit_note + driver_note + "。", ""]

    if priority:
        lines += ["## 优先处理（前 5 条）", "",
                  "| # | 等级 | 漏洞 | 位置 | POC |", "| --- | --- | --- | --- | --- |"]
        for i, v in enumerate(priority, 1):
            pom = "已复现" if v.get("poc_verified") is True else "未复现"
            lines.append(f"| {i} | {v.get('severity','')} | {_vt(v)} | `{v.get('file_path','')}:{v.get('line','')}` | {pom} |")
        lines.append("")
    lines += chain_md
    lines += hot_md
    lines += ["## 真实漏洞明细（按严重性排序）", ""]
    if not real:
        lines.append("未发现经确认的真实漏洞。")
    for i, v in enumerate(real, 1):
        poc_mark = "已复现" if v.get("poc_verified") is True else ("未复现" if v.get("poc_verified") is False else "—")
        reason = _fmt_text(v.get("llm_reason") or v.get("agent_reason") or "-")
        evidence = _fmt_text(v.get("agent_evidence") or "")
        lines += [
            f"### {i}. [{v['severity']}] {_vt(v)} (`{v['rule_id']}`)",
            "",
            f"- **位置**：`{v['file_path']}:{v['line']}`",
            f"- **置信度**：{v.get('agent_confidence') or v.get('llm_confidence') or '-'}",
            f"- **复现条件**：{_fmt_text(v.get('precondition') or '待确认')}",
            f"- **研判理由**：{reason}",
            f"- **POC 验证**：{poc_mark}{('：' + v.get('verify_result')) if v.get('verify_result') else ''}",
            f"- **POC Payload**：`{v.get('poc_payload') or '—'}`",
        ]
        if evidence:
            lines += ["", "**Agent 证据链**：", "```", evidence, "```"]
        lines += ["", "```", v["code_snippet"].strip()[:1200], "```", ""]
    if poc_only:
        lines += ["## POC 动态复现明细", ""]
        for i, v in enumerate(poc_only, 1):
            evidence = _fmt_text(v.get("agent_evidence") or "")
            lines += [
                f"### {i}. [{v['severity']}] {_vt(v)} (`{v['rule_id']}`)",
                "",
                f"- **位置**：`{v['file_path']}:{v['line']}`",
                f"- **POC 验证**：{_mk(v.get('poc_verified'))}"
                f"{('：' + v.get('verify_result')) if v.get('verify_result') else ''}",
                f"- **POC Payload**：`{v.get('poc_payload') or '—'}`",
            ]
            if evidence:
                lines += ["", "**证据链**：", "```", evidence, "```"]
            lines += ["", "```", v["code_snippet"].strip()[:1200], "```", ""]
    if cve_rows:
        lines += ["## 项目自身版本 CVE（OSV）", "",
                  "> 按项目自身名称+版本查询 OSV，只发送包名与版本号；"
                  "版本命中不等于已复现根因，需结合代码/部署确认。", ""]
        if len(cve_rows) > 30:
            lines += [f"> 共 {len(cve_rows)} 条，仅展示前 30 条。", ""]
        lines += ["| # | 等级 | CVE / 包 | 位置 | 修复版本 |",
                  "| --- | --- | --- | --- | --- |"]
        for i, v in enumerate(cve_rows[:30], 1):
            fix = (v.get("code_snippet") or "").split("；")[0]
            lines.append(
                f"| {i} | {v.get('severity')} | {_vt(v)} | "
                f"`{v.get('file_path')}:{v.get('line')}` | {fix} |")
        lines += [""]
    if authz_rows:
        lines += ["## 未授权接口候选（静态）", "",
                  "> 未发现鉴权标记 ≠ 未授权；全局中间件/框架安全配置需沙箱无凭证验证。", ""]
        if len(authz_rows) > 30:
            lines += [f"> 共 {len(authz_rows)} 条，仅展示前 30 条。", ""]
        lines += ["| # | 等级 | 接口 | 位置 | 无凭证 POC |",
                  "| --- | --- | --- | --- | --- |"]
        for i, v in enumerate(authz_rows[:30], 1):
            poc = (v.get("poc_payload") or "").replace("\n", " / ")
            lines.append(f"| {i} | {v.get('severity')} | {_vt(v)} | "
                         f"`{v.get('file_path')}:{v.get('line')}` | `{poc}` |")
        lines += [""]
    lines += ["## 静态扫描全量结果", "",
              "| # | 严重性 | 规则 | 位置 | 研判 | POC |", "| --- | --- | --- | --- | --- | --- |"]
    for i, v in enumerate(vulns, 1):
        judge = "Agent 确认" if _real(v) else ("误报" if _fp(v) else "未研判")
        lines.append(f"| {i} | {v['severity']} | {_vt(v)} | `{v['file_path']}:{v['line']}` | {judge} | {_mk(v.get('poc_verified'))} |")

    md_out = out.with_suffix(".md")
    md_out.write_text("\n".join(lines), encoding="utf-8")

    # ---------- JSON 版（AI 消费） ----------
    ai = _build_ai_report(task, vulns, real, false_positive, unjudged, poc_passed,
                          hotlist=hotlist, chains=chains)
    json_out = out.with_suffix(".json")
    json_out.write_text(json.dumps(ai, ensure_ascii=False, indent=2), encoding="utf-8")

    return str(out)
