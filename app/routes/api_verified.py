# -*- coding: utf-8 -*-
"""动态复现结果：只返回 POC / 动态验证通过的条目。"""
import json

from fastapi import APIRouter, Depends
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.agent_evidence import has_dynamic_evidence, parse_evidence
from app.models import ExploitChain, Task, Vulnerability
from app.routes.api_config import get_db

router = APIRouter(prefix="/api/verified", tags=["verified"])
SEV_ORDER = {"CRITICAL": 0, "ERROR": 0, "HIGH": 1, "WARNING": 2,
             "MEDIUM": 2, "INFO": 3, "LOW": 4}


@router.get("")
def list_verified(q: str = "", severity: str = "", task_id: int | None = None,
                  db: Session = Depends(get_db)):
    query = db.query(Vulnerability, Task).join(
        Task, Task.id == Vulnerability.task_id).filter(
        or_(Vulnerability.poc_verified.is_(True),
            Vulnerability.agent_status == "verified"))
    if severity:
        query = query.filter(Vulnerability.severity == severity.upper())
    if task_id:
        query = query.filter(Vulnerability.task_id == task_id)
    rows = query.order_by(Task.id.desc(), Vulnerability.id.desc()).all()
    items = []
    for v, t in rows:
        blob = " ".join(str(x or "") for x in (
            v.title, v.rule_id, v.file_path, t.filename, v.verify_result, v.agent_evidence))
        if q and q.lower() not in blob.lower():
            continue
        req, resp = parse_evidence(v.agent_evidence or "")
        dynamic = bool(v.poc_verified is True) or has_dynamic_evidence({
            "request": req, "response": resp,
            "agent_evidence": v.agent_evidence,
        })
        if not dynamic:
            continue
        rule_low = str(v.rule_id or "").lower()
        title_low = str(v.title or "").lower()
        if rule_low.startswith(("giants:trivy", "giants:self-cve", "giants:gitleaks")):
            continue
        if v.poc_verified is not True:
            attack_hints = ("injection", "eval", "exec", "execution", "command", "xss", "ssrf",
                            "traversal", "deserial", "upload", "sql", "xxe", "template",
                            "csrf", "authz", "unauth", "rce", "path", "redirect",
                            "dynamic", "method", "chain", "file",
                            "admin", "password", "credential", "default", "auth")
            if not any(k in rule_low or k in title_low for k in attack_hints):
                continue
        items.append({
            "id": v.id, "task_id": t.id, "task_filename": t.filename,
            "title": v.title or v.rule_id, "rule_id": v.rule_id,
            "severity": (v.severity or "INFO").upper(),
            "file_path": v.file_path, "line": v.line,
            "payload": v.poc_payload or "", "verify_result": v.verify_result or "",
            "evidence": (v.agent_evidence or "")[:6000],
            "agent_status": v.agent_status, "agent_confidence": v.agent_confidence,
            "created_at": str(v.created_at or ""),
        })
    # 阶段 0.8：把利用链附到对应任务，前端可直接展示节点
    if items:
        task_ids = {x["task_id"] for x in items}
        chain_map = {}
        for c in db.query(ExploitChain).filter(ExploitChain.task_id.in_(task_ids)).all():
            try:
                nodes = json.loads(c.nodes_json or "[]")
            except Exception:
                nodes = []
            chain_map.setdefault(c.task_id, {
                "id": c.id, "title": c.title, "verified": bool(c.verified), "nodes": nodes})
        for x in items:
            x["chain"] = chain_map.get(x["task_id"])
    items.sort(key=lambda x: (SEV_ORDER.get(x["severity"], 4), -x["id"]))
    return {"total": len(items), "items": items}
