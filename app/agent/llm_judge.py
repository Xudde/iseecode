"""LLM 误报研判 skill：调用兼容 OpenAI 协议的 LLM 判断漏洞真实性"""
import json
from datetime import datetime
try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None

from app.models import Config
from app.secrets import decrypt
from sqlalchemy.orm import Session


def _parse_hhmm(value: str, default: str):
    raw = (value or default).strip()
    try:
        h, m = raw.split(":", 1)
        return int(h), int(m)
    except (ValueError, AttributeError):
        h, m = default.split(":", 1)
        return int(h), int(m)


def _in_window(now: datetime, start: str, end: str) -> bool:
    sh, sm = _parse_hhmm(start, "23:00")
    eh, em = _parse_hhmm(end, "08:45")
    cur = now.hour * 60 + now.minute
    s, e = sh * 60 + sm, eh * 60 + em
    if s == e:
        return True
    if s < e:
        return s <= cur < e
    return cur >= s or cur < e


def get_llm_config(db: Session) -> dict | None:
    """读取 LLM 配置；夜间窗口内优先使用 night_*，窗口外回落白天配置。
    未配置完整则返回 None（跳过研判）。"""
    rows = {c.key: c.value for c in db.query(Config).all()}
    base_url = rows.get("base_url", "")
    api_key = decrypt(rows.get("api_key", ""))
    model = rows.get("model", "")
    night_enabled = str(rows.get("night_enabled", "0")).strip() == "1"
    night_url = rows.get("night_base_url", "")
    night_key = decrypt(rows.get("night_api_key", ""))
    night_model = rows.get("night_model", "")
    now = datetime.now()
    tz_name = rows.get("night_tz", "Asia/Shanghai")
    if ZoneInfo and tz_name:
        try:
            now = datetime.now(ZoneInfo(tz_name))
        except Exception:
            pass
    if night_enabled and night_url and night_key and night_model and _in_window(
            now, rows.get("night_start", "23:00"),
            rows.get("night_end", "08:45")):
        base_url, api_key, model = night_url, night_key, night_model
    if not (base_url and api_key and model):
        return None
    return {"base_url": base_url, "api_key": api_key, "model": model}


SYSTEM_PROMPT = (
    "你是资深代码安全审计专家。给定静态扫描发现的漏洞信息（规则、代码片段、说明），"
    "判断该漏洞是否为真实漏洞而非误报。只输出 JSON，格式："
    '{"is_real": true/false, "reason": "简要理由（中文，100字内）", "confidence": "high/medium/low"}'
)


def judge_vulns(vulns: list[dict], llm_cfg: dict, task_log) -> None:
    """对每条漏洞逐条调用 LLM 研判，就地写入 llm_is_real / llm_reason / llm_confidence"""
    from openai import OpenAI

    client = OpenAI(base_url=llm_cfg["base_url"], api_key=llm_cfg["api_key"], timeout=60)
    for v in vulns:
        user_msg = (
            f"规则: {v['rule_id']}\n严重性: {v['severity']}\n"
            f"文件: {v['file_path']}:{v['line']}\n"
            f"代码片段:\n{v['code_snippet']}\n"
            f"扫描器说明: {v.get('message', '')}"
        )
        try:
            resp = client.chat.completions.create(
                model=llm_cfg["model"],
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0,
            )
            text = resp.choices[0].message.content.strip()
            # 容错解析：提取第一个 JSON 对象
            if text.startswith("```"):
                text = text.split("```")[1].lstrip("json\r\n")
            result = json.loads(text[text.find("{"): text.rfind("}") + 1])
            # 严格类型校验：LLM 输出 "false"/"true" 字符串时不得误判
            is_real = result.get("is_real")
            v["llm_is_real"] = is_real if isinstance(is_real, bool) else None
            v["llm_reason"] = str(result.get("reason", ""))[:500]
            v["llm_confidence"] = str(result.get("confidence", "low"))[:8]
        except Exception as e:  # 单条失败不影响整体
            v["llm_is_real"] = None
            v["llm_reason"] = f"LLM 研判失败: {e}"[:500]
            v["llm_confidence"] = "low"


NAMING_SYSTEM_PROMPT = (
    "你是漏洞报告编辑，任务是为扫描器命中的漏洞起「人能看懂的中文名称」并标注「复现条件」。\n"
    "命名规则：格式为 漏洞类型（关键成因/位置），例如：\n"
    "  SQL注入（订单号拼接查询）、反射型XSS（返回参数直嵌脚本）、命令注入（ping参数拼接）、\n"
    "  路径穿越（下载接口未过滤../）、硬编码密钥（JWT Secret）、不安全反序列化（pickle入参）、\n"
    "  SSRF（URL参数无白名单）、越权访问（接口缺少权限校验）、配置风险（Dockerfile以root运行）。\n"
    "要求：不超过 22 个汉字；类型要具体（不要只写“代码风险”）；括号里写这条漏洞特有的成因，"
    "与同类其他条目区分开；judged 字段是研判结论，可信时优先采纳其定性。\n"
    "复现条件（precondition）：一句话说明触发该漏洞的前提，重点回答——攻击者是否需要登录/认证？"
    "是否依赖特定数据或环境？例如：\n"
    "  匿名可达，无需登录 / 需登录学生账号（[CheckLogin] 保护）/ 需有效订单号存在数据库 / "
    "需目标启用默认配置 / 需管理员权限触发 / 仅本地文件存在时可触发。\n"
    "从代码与研判结论中能推断就写明，无法推断时写「待确认」；不要编造。\n"
    '只输出 JSON 数组：[{"id": 漏洞ID, "title": "名称", "precondition": "复现条件"}]，不要输出其他内容。'
)


def name_vulns(db, task, rows, llm_cfg: dict, log_fn=None) -> int:
    """为 title/precondition 为空的漏洞批量生成中文名称与复现条件并落库（报告生成前调用）。
    rows 为本会话的 Vulnerability ORM 对象列表；返回成功命名条数。
    20 条一批，单批失败跳过不影响整体；token 消耗很小（每批约数百 token）。"""
    from openai import OpenAI

    log_fn = log_fn or (lambda m: None)
    todo = [r for r in rows
            if not (getattr(r, "title", None) or "").strip()
            or not (getattr(r, "precondition", None) or "").strip()]
    if not todo:
        return 0
    client = OpenAI(base_url=llm_cfg["base_url"], api_key=llm_cfg["api_key"], timeout=25, max_retries=0)
    batch_size = 20
    done = 0
    for i in range(0, len(todo), batch_size):
        batch = todo[i:i + batch_size]
        items = [{
            "id": r.id,
            "rule_id": (r.rule_id or "")[:120],
            "severity": (r.severity or "").upper(),
            "location": f"{r.file_path}:{r.line}",
            "code": " ".join((r.code_snippet or "").split())[:160],
            "judged": " ".join((r.agent_reason or r.llm_reason or "").split())[:120],
        } for r in batch]
        try:
            resp = client.chat.completions.create(
                model=llm_cfg["model"],
                messages=[
                    {"role": "system", "content": NAMING_SYSTEM_PROMPT},
                    {"role": "user", "content": json.dumps(items, ensure_ascii=False)},
                ],
                temperature=0,
            )
            text = (resp.choices[0].message.content or "").strip()
            if text.startswith("```"):
                text = text.split("```")[1].lstrip("json\r\n")
            arr = json.loads(text[text.find("["): text.rfind("]") + 1])
            id2res = {}
            for it in arr:
                if isinstance(it, dict) and it.get("id"):
                    id2res[int(it["id"])] = (str(it.get("title", "")).strip()[:64],
                                             str(it.get("precondition", "")).strip()[:256])
            for r in batch:
                t, pre = id2res.get(r.id, ("", ""))
                changed = False
                if t and not (r.title or "").strip():
                    r.title = t
                    changed = True
                if pre and not (r.precondition or "").strip():
                    r.precondition = pre
                    changed = True
                if changed:
                    done += 1
            db.commit()
        except Exception as e:
            log_fn(f"漏洞命名批次失败（跳过该批）: {e}")
    return done
