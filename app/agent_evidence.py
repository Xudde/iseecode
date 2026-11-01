# -*- coding: utf-8 -*-
"""Agent 证据判定：区分真正的 HTTP 动态请求与 grep/静态检查。"""
import re


def parse_evidence(text: str) -> tuple[str, str]:
    """从 agent_evidence 的 REQUEST:/RESPONSE: 行还原请求与响应。"""
    req = resp = ""
    for line in (text or "").splitlines():
        raw = line.strip()
        if raw.startswith("REQUEST:"):
            req = raw[len("REQUEST:"):].strip()
        elif raw.startswith("RESPONSE:"):
            resp = raw[len("RESPONSE:"):].strip()
    return req, resp


def has_dynamic_evidence(f: dict) -> bool:
    """只有 HTTP method/curl + 响应状态码才算动态；grep/shell 输出不算。"""
    if f.get("dynamic") is True:
        return True
    req = str(f.get("request") or "").strip()
    resp = str(f.get("response") or "").strip()
    if not req or not resp:
        req, resp = parse_evidence(str(f.get("agent_evidence") or ""))
    if not req or not resp:
        return False
    looks_http = bool(
        re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+", req, re.I)
        or re.match(r"^curl\b", req, re.I))
    # 响应必须以真实 HTTP 状态码开头，或显式 status/code=xxx；
    # “预期 200”“预期返回 200”这类推演不算动态证据。
    has_status = bool(
        re.match(r"^(?:HTTP/\S+\s+)?[1-5]\d{2}\b", resp.strip(), re.I)
        or re.search(r"\b(?:status|code)\s*[=:]\s*[1-5]\d{2}\b",
                     resp[:300], re.I))
    return looks_http and has_status
