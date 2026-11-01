# -*- coding: utf-8 -*-
"""外部 AI 自动化深挖：任务领取租约、checkpoint、完成回写。"""
import json
import re
import uuid
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.agent_evidence import has_dynamic_evidence
from app.agent_state import claim_info, claim_state
from app.models import AgentRun, ExploitChain, Task, Vulnerability
from app.routes.api_config import get_db

router = APIRouter(prefix="/api/agent", tags=["agent"])
LEASE_MINUTES = 15
MAX_CHECKPOINT = 100_000
STAGES = {"triage", "exploit", "verify", "judge", "done"}


def _iso(dt) -> str | None:
    return dt.isoformat(sep=" ", timespec="seconds") if dt else None


def _latest_runs(db: Session) -> dict[int, AgentRun]:
    latest = {}
    for r in db.query(AgentRun).order_by(AgentRun.id.desc()).all():
        latest.setdefault(r.task_id, r)
    return latest


def _pack_url(request: Request, task_id: int) -> str:
    return str(request.base_url).rstrip("/") + f"/api/tasks/{task_id}/agent-pack"


def _run_payload(request: Request, task: Task, run: AgentRun,
                 checkpoint: str = "", resumed: bool = False) -> dict:
    cid = getattr(task, "sandbox_cid", None)
    running = False
    if cid:
        try:
            from app.skills import sandbox as sandbox_skill
            running = sandbox_skill.is_running(cid)
        except Exception:
            running = False
    runtime_ready = bool(cid) and running
    if not cid:
        runtime_note = ("无沙箱：只允许读 pack 内 source/ 和报告，禁止遍历当前工作目录；"
                        "标记 static_only 并结束，等待人工起沙箱")
    elif not running:
        runtime_note = ("沙箱容器已退出（保留容器已过期/被清理），runtime_ready=false；"
                        "只读 pack 内 source/ 和报告，或让用户重新部署沙箱后再动态验证")
    else:
        runtime_note = "有沙箱，可用 environment.json 的 agent_token 动态验证"
    return {
        "run_id": run.id,
        "task_id": task.id,
        "task": {"filename": task.filename, "tech_stack": task.tech_stack,
                 "audit_mode": task.audit_mode, "project_type": task.project_type},
        "pack_url": _pack_url(request, task.id),
        "pack_auth": "Authorization: Bearer <PLATFORM_TOKEN>",
        "runtime_ready": runtime_ready,
        "sandbox_state": ("running" if runtime_ready else ("exited" if cid else "none")),
        "runtime_note": runtime_note,
        "stage": run.stage or "",
        "checkpoint": checkpoint or run.checkpoint or "",
        "lease_until": _iso(run.lease_until),
        "last_activity": _iso(run.updated_at),
        "lease_minutes": LEASE_MINUTES,
        "server_time": _iso(datetime.now()),
        "heartbeat_api": f"/api/agent/runs/{run.id}/heartbeat",
        "resumed": resumed,
        **claim_info(run),
        "has_result": bool(_extract_result(checkpoint or run.checkpoint or "")),
        "run_api": f"/api/agent/runs/{run.id}",
        "reingest_api": f"/api/agent/runs/{run.id}/reingest",
        "state_api": {
            "progress": "/api/agent/runs/{run_id}/progress",
            "complete": "/api/agent/runs/{run_id}/complete",
        },
    }


def _claim_specific(request: Request, db: Session, session: str, mode: str,
                    task_id: int, reopen: bool, now: datetime,
                    latest: dict[int, AgentRun]) -> dict:
    """定向领取指定任务：绝不回退去领别的任务；已完成任务默认只返回旧 run。"""
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail=f"任务 {task_id} 不存在")
    if task.status != "completed":
        return {"status": "not_ready", "task_id": task_id,
                "task_status": task.status,
                "message": "任务尚未完成，不能领取深挖",
                "server_time": _iso(datetime.now())}
    run = latest.get(task_id)
    if run is not None and run.status != "completed":
        lease_ok = (run.status == "running" and run.lease_until is not None
                    and run.lease_until > now)
        if lease_ok and run.session_key != session:
            return {"status": "busy", "task_id": task_id,
                    "message": "该任务已有其他会话持有租约",
                    "active_run": {"run_id": run.id, "task_id": task_id,
                                   "session_key": run.session_key,
                                   "stage": run.stage or "",
                                   "last_activity": _iso(run.updated_at),
                                   "lease_until": _iso(run.lease_until)},
                    "next_at": _iso(run.lease_until),
                    "server_time": _iso(datetime.now())}
        # running / blocked / expired 统一回到 running，续用原 checkpoint
        run.status = "running"
        run.session_key = session
        run.lease_until = now + timedelta(minutes=LEASE_MINUTES)
        db.commit()
        return {"status": "ok",
                **_run_payload(request, task, run, run.checkpoint, True)}
    if run is not None and run.status == "completed" and not reopen:
        parsed = _extract_result(run.checkpoint or "")
        return {"status": "already_completed", "task_id": task_id,
                "run_id": run.id, "stage": run.stage or "",
                "last_activity": _iso(run.updated_at),
                "has_result": bool(parsed),
                "result_summary": (parsed or {}).get("summary") or {},
                "checkpoint_tail": (run.checkpoint or "")[-4000:],
                "run_api": f"/api/agent/runs/{run.id}",
                "reingest_api": f"/api/agent/runs/{run.id}/reingest",
                "reopen_hint": "如需重新深挖，同一请求加 reopen=1（会新建 run，旧结论保留）",
                "server_time": _iso(datetime.now())}
    cid = getattr(task, "sandbox_cid", None)
    if mode == "dynamic" and not cid:
        return {"status": "not_eligible", "task_id": task_id,
                "reason": "该任务没有沙箱；请用 mode=static 领取",
                "server_time": _iso(datetime.now())}
    if mode == "static" and cid:
        return {"status": "not_eligible", "task_id": task_id,
                "reason": "该任务有沙箱；请用 mode=dynamic 领取",
                "server_time": _iso(datetime.now())}
    n_cand = db.query(func.count(Vulnerability.id)).filter(
        Vulnerability.task_id == task_id).scalar() or 0
    if n_cand <= 0:
        return {"status": "not_eligible", "task_id": task_id,
                "reason": "该任务没有候选漏洞",
                "server_time": _iso(datetime.now())}
    run = AgentRun(task_id=task_id, session_key=session, status="running",
                   lease_until=now + timedelta(minutes=LEASE_MINUTES),
                   checkpoint="")
    db.add(run)
    db.commit()
    db.refresh(run)
    return {"status": "ok", "targeted": True,
            **_run_payload(request, task, run)}


@router.get("/next")
def agent_next(request: Request, session: str = "", mode: str = "dynamic",
               task_id: int | None = None, reopen: bool = False,
               db: Session = Depends(get_db)):
    """领取下一个未完成深挖任务；mode=dynamic 只领有沙箱的任务；
    mode=static 只领无沙箱静态任务（可多窗口并行）；mode=all 两者都领。
    带 task_id 时只处理该任务，不会回退去领别的任务。"""
    if not session:
        session = "sess_" + uuid.uuid4().hex[:12]
    now = datetime.now()
    latest = _latest_runs(db)
    if task_id is not None:
        return _claim_specific(request, db, session, mode, task_id, reopen,
                               now, latest)

    # 1) 续领所有“已接取未完成”的会话（running/blocked/expired，租约过期或已释放）
    for tid, run in sorted(latest.items(), key=lambda kv: kv[1].id):
        if run.status == "completed":
            continue
        if run.status == "running" and run.lease_until and run.lease_until > now:
            continue
        task = db.get(Task, tid)
        if task is None or task.status != "completed":
            continue
        cid = getattr(task, "sandbox_cid", None)
        if mode == "dynamic" and not cid:
            continue
        if mode == "static" and cid:
            continue
        run.status = "running"
        run.session_key = session
        run.lease_until = now + timedelta(minutes=LEASE_MINUTES)
        db.commit()
        return {"status": "ok", **_run_payload(request, task, run, run.checkpoint, True)}

    # 2) 已完成任务中，挑选从未深挖/未被完成的任务；跳过仍在租约内的会话
    counts = {}
    for tid, in db.query(Vulnerability.task_id).all():
        counts[tid] = counts.get(tid, 0) + 1
    tasks = db.query(Task).filter(Task.status == "completed").order_by(Task.id.asc()).all()
    busy_until = None
    busy_run = None
    for task in tasks:
        run = latest.get(task.id)
        cid = getattr(task, "sandbox_cid", None)
        if run is not None:
            if run.status == "completed":
                continue
            # 三态：非 completed 都是“已接取”。租约有效的会话算 busy；
            # 租约过期/已释放/blocked 的会话在步骤 1 续领，这里不再新建 run。
            if (run.status == "running" and run.lease_until
                    and run.lease_until > now):
                if mode == "static":
                    # 静态并发：跳过已有会话的任务，但不阻塞其他静态任务
                    continue
                if mode == "dynamic" and not cid:
                    continue
                if busy_run is None or run.lease_until > busy_run.lease_until:
                    busy_run = run
                busy_until = max(busy_until, run.lease_until) if busy_until else run.lease_until
            continue
        if counts.get(task.id, 0) <= 0:
            continue
        if mode == "dynamic" and not cid:
            continue
        if mode == "static" and cid:
            continue
        run = AgentRun(task_id=task.id, session_key=session, status="running",
                       lease_until=now + timedelta(minutes=LEASE_MINUTES),
                       checkpoint="")
        db.add(run)
        db.commit()
        db.refresh(run)
        return {"status": "ok", **_run_payload(request, task, run)}

    if mode == "static":
        busy_until = None  # 静态任务允许并行，不返回 busy
    return {"status": "busy" if busy_until else "idle",
            "message": "没有待深挖任务" if not busy_until else "当前任务租约未到期",
            "next_at": _iso(busy_until), "session": session,
            "active_run": ({"run_id": busy_run.id, "task_id": busy_run.task_id,
                            "last_activity": _iso(busy_run.updated_at),
                            "lease_until": _iso(busy_run.lease_until)}
                           if busy_run else None),
            "server_time": _iso(datetime.now()),
            "dynamic_pending": sum(1 for t in tasks if getattr(t, "sandbox_cid", None)
                                   and (latest.get(t.id) is None or
                                        latest.get(t.id).status not in ("completed",))),
            "static_pending": sum(1 for t in tasks if not getattr(t, "sandbox_cid", None)
                                  and (latest.get(t.id) is None or
                                       latest.get(t.id).status not in ("completed",)))}


@router.post("/runs/{run_id}/progress")
def agent_progress(run_id: int, data: dict = Body(default={}),
                   db: Session = Depends(get_db)):
    run = db.get(AgentRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run 不存在")
    if run.status == "completed":
        return {"ok": True, "status": "completed"}
    run.checkpoint = str(data.get("checkpoint") or run.checkpoint or "")[:MAX_CHECKPOINT]
    if data.get("stage") in STAGES:
        run.stage = data["stage"]
    if data.get("status") in ("running", "blocked"):
        # 三态：blocked 也是“已接取未完成”，中断后可续领
        run.status = "running"
    if run.status == "running":
        run.lease_until = datetime.now() + timedelta(minutes=LEASE_MINUTES)
    db.commit()
    return {"ok": True, "run_id": run.id, "status": run.status,
            **claim_info(run),
            "stage": run.stage or "", "lease_until": _iso(run.lease_until),
            "checkpoint": run.checkpoint}


def _extract_result(checkpoint: str) -> dict | None:
    """提取 checkpoint 中最后一个合法 RESULT_JSON。

    先只认显式 RESULT_JSON 标记，避免把 result_schema 示例当成真实结论；
    没有标记时才回退到裸 JSON。取最后一个合法块，兼容多轮 progress 堆叠。
    """
    text = checkpoint or ""

    def _pick(start_at: int) -> dict | None:
        best = None
        best_pos = -1
        j = text.find("{", start_at)
        while j >= 0:
            try:
                data, end = json.JSONDecoder().raw_decode(text[j:])
            except (ValueError, TypeError):
                data, end = None, 0
            if (isinstance(data, dict) and isinstance(data.get("findings"), list)
                    and j > best_pos):
                best = data
                best_pos = j
            j = text.find("{", j + 1 if end <= 0 else j + end)
        return best

    for needle in ("RESULT_JSON", '{"findings"', '{"task_id"'):
        found = None
        found_pos = -1
        start = 0
        while True:
            i = text.find(needle, start)
            if i < 0:
                break
            candidate = _pick(i)
            if candidate is not None:
                pos = text.find("{", i)
                if pos > found_pos:
                    found, found_pos = candidate, pos
            start = i + len(needle)
        if found is not None:
            return found
    return None


def _clean_rel_path(fp) -> str:
    """findings[].file 只接受工作区相对路径，拒绝绝对路径和 ../ 穿越。"""
    s = str(fp or "").replace("\\", "/").strip()
    while s.startswith("./"):
        s = s[2:]
    s = s.lstrip("/")
    parts = [p for p in s.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return ""
    return "/".join(parts)


def _has_dynamic_evidence(f: dict) -> bool:
    """兼容旧调用：动态证据判定统一放在 app.agent_evidence。"""
    return has_dynamic_evidence(f)


def _file_in_task_workspace(task: Task, fp: str) -> bool:
    """findings[].file 必须能在该任务工作区找到，挡住串包/别的任务的文件。"""
    if not fp:
        return True
    ws = Path(getattr(task, "workspace_path", "") or "")
    if not ws.is_dir():
        return True  # 工作区不在本机时无法校验，不误杀
    try:
        if (ws / fp).is_file():
            return True
        for child in ws.iterdir():
            if child.is_dir() and (child / fp).is_file():
                return True
    except OSError:
        return True
    return False


def _agent_stats(db: Session, task_id: int) -> dict:
    rows = db.query(Vulnerability.agent_status, func.count(Vulnerability.id)).filter(
        Vulnerability.task_id == task_id).group_by(Vulnerability.agent_status).all()
    out = {"total": 0, "verified": 0, "false_positive": 0, "unverified": 0,
           "poc_verified": 0}
    for status, n in rows:
        out["total"] += int(n or 0)
        if status in ("verified", "false_positive", "unverified"):
            out[status] += int(n or 0)
    out["poc_verified"] = db.query(func.count(Vulnerability.id)).filter(
        Vulnerability.task_id == task_id,
        Vulnerability.poc_verified.is_(True)).scalar() or 0
    return out


def _refresh_report(db: Session, task: Task) -> str:
    """深挖结果落库后重生成报告，避免任务页/报告仍是旧结论。"""
    try:
        from app.models import ExploitChain
        from app.skills import hotlist as hotlist_skill
        from app.skills import report as report_skill
        rows = db.query(Vulnerability).filter(
            Vulnerability.task_id == task.id).order_by(Vulnerability.id).all()
        report_vulns = [{
            "id": r.id, "source": r.source,
            "rule_id": r.rule_id, "title": r.title, "precondition": r.precondition,
            "severity": r.severity, "file_path": r.file_path,
            "line": r.line, "code_snippet": r.code_snippet,
            "llm_is_real": r.llm_is_real, "llm_reason": r.llm_reason,
            "llm_confidence": r.llm_confidence, "poc_payload": r.poc_payload,
            "poc_verified": r.poc_verified, "verify_result": r.verify_result,
            "agent_status": r.agent_status, "agent_evidence": r.agent_evidence,
            "agent_confidence": r.agent_confidence, "agent_reason": r.agent_reason,
            "agent_payload": r.poc_payload,
        } for r in rows]
        try:
            hot = hotlist_skill.build(task, rows, top_n=20)
        except Exception:
            hot = None
        chains = []
        for c in db.query(ExploitChain).filter(
                ExploitChain.task_id == task.id).order_by(ExploitChain.id).all():
            try:
                nodes = json.loads(c.nodes_json or "[]")
            except (ValueError, TypeError):
                nodes = []
            chains.append({"id": c.id, "title": c.title,
                           "verified": bool(c.verified), "nodes": nodes})
        path = report_skill.run_report(task, report_vulns, hotlist=hot, chains=chains)
        task.report_path = path
        db.commit()
        return path
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        return f"error: {e}"


def _norm_verdict(finding: dict) -> str:
    raw = str(finding.get("ai_verdict") or finding.get("status") or "").lower()
    if raw in ("verified", "real", "true"):
        return "verified"
    if raw in ("false_positive", "false-positive", "fp", "false"):
        return "false_positive"
    return "unverified"


def _create_external_row(db: Session, run: AgentRun, f: dict, verdict: str,
                         fp: str, line: int) -> Vulnerability:
    """深挖结论在平台没有对应扫描记录时，新建 source=agent-external 条目，
    避免 AI 验真/误报结果被静默丢弃（阶段 0.1）。"""
    rid = str(f.get("rule_id") or "").strip() or "agent-reported"
    evidence = str(f.get("evidence") or "")
    row = Vulnerability(
        task_id=run.task_id,
        source="agent-external",
        rule_id=rid[:128],
        title=(str(f.get("title") or "").strip()[:128] or None),
        severity=str(f.get("severity") or "WARNING").upper()[:16],
        file_path=fp[:512],
        line=line,
        code_snippet=(str(f.get("code_snippet") or evidence))[:2000],
        precondition=(str(f.get("precondition") or "")[:512] or None),
        poc_payload=(str(f.get("payload") or "")[:2000] or None),
        agent_status=verdict,
        agent_confidence=(str(f.get("confidence") or "")[:8] or None),
        agent_reason=(str(f.get("reason") or f.get("impact") or "")[:2000] or None),
        agent_evidence=(evidence[:6000] or None),
        analyzed_at=datetime.now(),
    )
    if verdict == "verified":
        dynamic = _has_dynamic_evidence(f)
        if dynamic:
            row.poc_verified = True
        if not row.poc_payload:
            if f.get("payload"):
                row.poc_payload = str(f["payload"])[:2000]
            elif dynamic:
                row.poc_payload = json.dumps({
                    "request": f.get("request") or "",
                    "response": f.get("response") or "",
                }, ensure_ascii=False)[:2000]
        row.verify_result = (evidence or str(f.get("response") or ""))[:2000] or None
    db.add(row)
    db.flush()
    return row


def _store_chain(db: Session, run: AgentRun, f: dict) -> int:
    """阶段 0.8：把 findings[].chain 落库为利用链节点图。"""
    chain = f.get("chain")
    if not isinstance(chain, dict):
        return 0
    nodes = chain.get("nodes") or []
    if not isinstance(nodes, list) or not nodes:
        return 0
    title = str(chain.get("title") or f.get("title") or "利用链")[:200]
    exists = db.query(ExploitChain).filter(
        ExploitChain.task_id == run.task_id, ExploitChain.title == title).first()
    if exists is not None:
        return 0
    db.add(ExploitChain(
        task_id=run.task_id, run_id=run.id, title=title,
        nodes_json=json.dumps(nodes, ensure_ascii=False)[:20000],
        edges_json=json.dumps(chain.get("edges") or [], ensure_ascii=False)[:8000],
        verified=bool(chain.get("verified")),
    ))
    db.flush()
    return 1


def _ingest_result(db: Session, run: AgentRun, checkpoint: str) -> dict:
    data = _extract_result(checkpoint)
    if not data:
        return {"parsed": False, "ingested": 0, "updated": 0, "created": 0,
                "note": "未找到 RESULT_JSON，仅保存 checkpoint"}
    declared = data.get("task_id")
    if declared is not None:
        try:
            if int(declared) != int(run.task_id):
                return {"parsed": True, "ingested": 0, "updated": 0, "created": 0,
                        "error": f"task_id 不一致：RESULT_JSON={declared} run.task_id={run.task_id}"}
        except (TypeError, ValueError):
            pass
    task = db.get(Task, run.task_id)
    updated = 0
    created = 0
    created_chains = 0
    skipped_missing = []
    counts = {"verified": 0, "false_positive": 0, "unverified": 0}
    seen = set()
    for f in (data.get("findings") or []):
        if not isinstance(f, dict):
            continue
        verdict = _norm_verdict(f)
        created_chains += _store_chain(db, run, f)
        vid = f.get("cand_id") or f.get("vuln_id")
        if not vid:
            m = re.search(r"\[(\d+)\]", str(f.get("title") or ""))
            if m:
                vid = int(m.group(1))
        fp = _clean_rel_path(f.get("file"))
        if fp and task is not None and not _file_in_task_workspace(task, fp):
            skipped_missing.append(fp)
            continue
        try:
            line = int(f.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        row = None
        if vid:
            try:
                row = db.get(Vulnerability, int(vid))
                if row is not None and row.task_id != run.task_id:
                    row = None
            except (TypeError, ValueError):
                row = None
        if row is None and fp:
            rows = db.query(Vulnerability).filter(
                Vulnerability.task_id == run.task_id,
                Vulnerability.file_path == fp,
                Vulnerability.line == line).all()
            if len(rows) == 1:
                row = rows[0]
        # 平台没有对应扫描行时，按 (file,line,rule_id) 去重后新建；
        # 只落 verified / false_positive，unverified 未命中不制造噪声。
        if row is None and fp and verdict in ("verified", "false_positive"):
            rid = str(f.get("rule_id") or "").strip() or "agent-reported"
            row = db.query(Vulnerability).filter(
                Vulnerability.task_id == run.task_id,
                Vulnerability.file_path == fp,
                Vulnerability.line == line,
                Vulnerability.rule_id == rid[:128]).first()
            if row is None:
                row = _create_external_row(db, run, f, verdict, fp, line)
                created += 1
        if row is None or row.id in seen:
            continue
        seen.add(row.id)
        row.agent_status = verdict
        row.agent_confidence = str(f.get("confidence") or "")[:8] or row.agent_confidence
        reason = f.get("reason") or f.get("impact") or f.get("summary") or ""
        if reason:
            row.agent_reason = str(reason)[:2000]
        evidence = f.get("evidence") or ""
        extra = []
        if f.get("request"):
            extra.append("REQUEST: " + str(f["request"])[:3000])
        if f.get("response"):
            extra.append("RESPONSE: " + str(f["response"])[:3000])
        if f.get("repro_steps"):
            extra.append("REPRO: " + json.dumps(f["repro_steps"], ensure_ascii=False)[:2000])
        row.agent_evidence = ("\n".join([str(evidence)] + extra))[:6000]
        row.analyzed_at = datetime.now()
        if verdict == "verified":
            # 只有真正的 HTTP 请求/响应才算动态复现；grep/离线核对不冒充 poc_verified
            dynamic = _has_dynamic_evidence(f)
            if dynamic:
                row.poc_verified = True
            if f.get("payload"):
                row.poc_payload = str(f["payload"])[:2000]
            elif dynamic and not (row.poc_payload or "").strip():
                row.poc_payload = json.dumps({
                    "request": f.get("request") or "",
                    "response": f.get("response") or "",
                }, ensure_ascii=False)[:2000]
            row.verify_result = (str(evidence) or str(f.get("response") or ""))[:2000]
        counts[verdict] += 1
        updated += 1
    db.commit()
    return {"parsed": True, "ingested": len(data.get("findings") or []),
            "updated": updated, "created": created, "created_chains": created_chains,
            "skipped_missing_file": len(skipped_missing),
            "missing_files": skipped_missing[:10],
            "counts": counts, "summary": data.get("summary") or {}}


@router.post("/runs/{run_id}/complete")
def agent_complete(run_id: int, data: dict = Body(default={}),
                   db: Session = Depends(get_db)):
    run = db.get(AgentRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run 不存在")
    declared = data.get("task_id")
    if declared is not None:
        try:
            if int(declared) != int(run.task_id):
                raise HTTPException(status_code=400, detail="task_id 与 run 不匹配")
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="task_id 非法")
    checkpoint = str(data.get("checkpoint") or run.checkpoint or "").strip()
    if len(checkpoint) < 50:
        raise HTTPException(status_code=400,
                            detail="checkpoint 太短：完成前必须留下候选结论/证据摘要，防止掉线被误记完成")
    old = (run.checkpoint or "").strip()
    was_completed = run.status == "completed"
    if was_completed and old and checkpoint != old and not data.get("force"):
        raise HTTPException(
            status_code=409,
            detail="run 已完成且 checkpoint 不同；如需覆盖请带 force=true，"
                   "或改用 POST /api/agent/tasks/{task_id}/result 追加新结论")
    task = db.get(Task, run.task_id)
    run.status = "completed"
    run.stage = "done"
    run.lease_until = None
    run.checkpoint = checkpoint[:MAX_CHECKPOINT]
    db.commit()
    ingested = _ingest_result(db, run, checkpoint)
    report_path = ""
    if task is not None:
        # 完成即重写漏洞报告，避免报告停留在 Agent 运行前
        report_path = _refresh_report(db, task)
    return {"ok": True, "run_id": run.id, "task_id": run.task_id,
            "status": "completed", "stage": run.stage, "ingest": ingested,
            "agent_stats": _agent_stats(db, run.task_id),
            "report_path": report_path or None,
            "already_completed": bool(was_completed and old == checkpoint)}


def _run_detail_payload(db: Session, run: AgentRun) -> dict:
    task = db.get(Task, run.task_id)
    parsed = _extract_result(run.checkpoint or "")
    return {"run_id": run.id, "task_id": run.task_id,
            "filename": task.filename if task else "",
            "task_status": task.status if task else "",
            "status": run.status, **claim_info(run), "stage": run.stage or "",
            "session_key": run.session_key,
            "lease_until": _iso(run.lease_until),
            "created_at": _iso(run.created_at),
            "last_activity": _iso(run.updated_at),
            "has_result": bool(parsed),
            "result_summary": (parsed or {}).get("summary") or {},
            "result_findings": len((parsed or {}).get("findings") or []),
            "agent_stats": _agent_stats(db, run.task_id),
            "checkpoint": run.checkpoint or ""}


@router.get("/runs/{run_id}")
def agent_run_detail(run_id: int, db: Session = Depends(get_db)):
    """查询单个 run（含完整 checkpoint），用于已完成任务的结果核对/补写。"""
    run = db.get(AgentRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run 不存在")
    return _run_detail_payload(db, run)


@router.get("/tasks/{task_id}/run")
def agent_task_run(task_id: int, db: Session = Depends(get_db)):
    """按任务查最新 run；不存在时明确返回 run=null，而不是静默换任务。"""
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    run = db.query(AgentRun).filter(AgentRun.task_id == task_id).order_by(
        AgentRun.id.desc()).first()
    if run is None:
        return {"task_id": task_id, "filename": task.filename,
                "task_status": task.status, "run": None,
                "message": "该任务没有任何 agent run；可用 POST /api/agent/tasks/{task_id}/result 补写"}
    return _run_detail_payload(db, run)


@router.post("/runs/{run_id}/reingest")
def agent_reingest(run_id: int, db: Session = Depends(get_db)):
    """对已有 checkpoint 重新解析入库（幂等）；用于历史结果漏回写修复。"""
    run = db.get(AgentRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run 不存在")
    checkpoint = (run.checkpoint or "").strip()
    if not checkpoint:
        raise HTTPException(status_code=400, detail="该 run 没有 checkpoint")
    ingested = _ingest_result(db, run, checkpoint)
    task = db.get(Task, run.task_id)
    report_path = ""
    if task is not None and ingested.get("parsed"):
        report_path = _refresh_report(db, task)
    return {"ok": True, "run_id": run.id, "task_id": run.task_id,
            "run_status": run.status, **claim_info(run), "ingest": ingested,
            "agent_stats": _agent_stats(db, run.task_id),
            "report_path": report_path or None}


@router.post("/tasks/{task_id}/result")
def agent_task_result(task_id: int, data: dict = Body(default={}),
                      db: Session = Depends(get_db)):
    """任务级回写：没有可用 run 时补建 completed run；已有 run 默认不覆盖。"""
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    checkpoint = str(data.get("checkpoint") or "").strip()
    if len(checkpoint) < 50:
        raise HTTPException(status_code=400, detail="checkpoint 太短")
    parsed = _extract_result(checkpoint)
    if not parsed:
        raise HTTPException(status_code=400, detail="未找到 RESULT_JSON，拒绝任务级回写")
    declared = parsed.get("task_id")
    if declared is not None:
        try:
            if int(declared) != task_id:
                raise HTTPException(status_code=400,
                                    detail=f"RESULT_JSON task_id={declared} 与 URL {task_id} 不一致")
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="RESULT_JSON task_id 非法")
    bad_paths = [str(f.get("file")) for f in (parsed.get("findings") or [])
                 if isinstance(f, dict) and f.get("file")
                 and not _clean_rel_path(f.get("file"))]
    if bad_paths:
        raise HTTPException(status_code=400,
                            detail=f"findings[].file 存在非法路径: {bad_paths[:5]}")
    run = None
    run_id = data.get("run_id")
    if run_id is not None:
        try:
            run = db.get(AgentRun, int(run_id))
        except (TypeError, ValueError):
            run = None
        if run is None or run.task_id != task_id:
            raise HTTPException(status_code=400, detail="run_id 不属于该任务")
    else:
        latest = db.query(AgentRun).filter(
            AgentRun.task_id == task_id).order_by(AgentRun.id.desc()).first()
        if (latest is not None and latest.status == "completed"
                and (latest.checkpoint or "").strip() == checkpoint):
            run = latest  # 完全相同的补写直接幂等复用，避免堆重复 run
    replace = bool(data.get("replace"))
    if run is not None and run.status == "completed" and not replace:
        old = (run.checkpoint or "").strip()
        if old != checkpoint:
            run = None  # 保留旧 run，结果另建一条审计记录
    if run is None:
        run = AgentRun(task_id=task_id,
                       session_key=str(data.get("session") or "agent-result")[:80],
                       status="completed", stage="done", lease_until=None,
                       checkpoint=checkpoint[:MAX_CHECKPOINT])
        db.add(run)
    else:
        run.status = "completed"
        run.stage = "done"
        run.lease_until = None
        run.checkpoint = checkpoint[:MAX_CHECKPOINT]
    db.commit()
    db.refresh(run)
    ingested = _ingest_result(db, run, checkpoint)
    report_path = _refresh_report(db, task)
    return {"ok": True, "run_id": run.id, "task_id": task_id,
            "status": "completed", "ingest": ingested,
            "agent_stats": _agent_stats(db, task_id),
            "report_path": report_path or None}


@router.post("/runs/{run_id}/heartbeat")
def agent_heartbeat(run_id: int, data: dict = Body(default={}),
                    db: Session = Depends(get_db)):
    run = db.get(AgentRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run 不存在")
    if run.status == "completed":
        return {"ok": False, "status": run.status}
    run.status = "running"
    run.lease_until = datetime.now() + timedelta(minutes=LEASE_MINUTES)
    if data.get("stage") in STAGES:
        run.stage = data["stage"]
    if data.get("checkpoint"):
        run.checkpoint = str(data["checkpoint"])[:20000]
    db.commit()
    return {"ok": True, "run_id": run.id, "status": run.status,
            "stage": run.stage or "",
            "last_activity": _iso(run.updated_at), "lease_until": _iso(run.lease_until)}


@router.post("/runs/{run_id}/release")
def agent_release(run_id: int, data: dict = Body(default={}),
                  db: Session = Depends(get_db)):
    run = db.get(AgentRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run 不存在")
    if run.status != "completed":
        # 释放租约不等于完成：仍保持“已接取”，其他会话可直接续领
        run.status = "running"
        run.lease_until = None
        run.checkpoint = str(data.get("checkpoint") or run.checkpoint or "")[:MAX_CHECKPOINT]
        db.commit()
    return {"ok": True, "run_id": run.id, "status": run.status, **claim_info(run)}


@router.get("/state")
def agent_state(task_id: int | None = None, limit: int = 80,
                claim_state_filter: str = "", db: Session = Depends(get_db)):
    latest = _latest_runs(db)
    q = db.query(Task).filter(Task.status == "completed")
    if task_id is not None:
        q = q.filter(Task.id == task_id)
    tasks = q.order_by(Task.id.desc()).limit(max(1, min(limit, 500))).all()
    out = []
    for t in tasks:
        r = latest.get(t.id)
        parsed = _extract_result(r.checkpoint or "") if r else None
        info = claim_info(r)
        stats = _agent_stats(db, t.id)
        out.append({"task_id": t.id, "filename": t.filename,
                    "deep_status": info["claim_state"],
                    **info,
                    "stage": (r.stage or "") if r else "",
                    "run_id": r.id if r else None,
                    "raw_run_status": (r.status or "") if r else "",
                    "lease_until": _iso(r.lease_until) if r else None,
                    "has_result": bool(parsed),
                    "result_summary": (parsed or {}).get("summary") or {},
                    "vulns": stats["total"],
                    "agent_verified": stats["verified"],
                    "poc_verified": stats["poc_verified"],
                    "checkpoint": (r.checkpoint or "")[:300] if r else ""})
    summary = {"pending": 0, "running": 0, "completed": 0}
    for item in out:
        summary[item["claim_state"]] = summary.get(item["claim_state"], 0) + 1
    items = ([x for x in out if x["claim_state"] == claim_state_filter]
             if claim_state_filter else out)
    return {"items": items, "summary": summary,
            "total_completed": db.query(func.count(Task.id)).filter(
                Task.status == "completed").scalar() or 0}


@router.get("/audit/zero-token")
def agent_zero_token_audit(limit: int = 200, db: Session = Depends(get_db)):
    """只读核查 tokens_used=0 的已完成任务，区分设计内 0 token 与异常未回写。

    不自动重置任何任务；suspect_* 只代表需要人工/Zcode 复核。
    """
    zero_modes = {"static", "poc"}
    zero_types = {"apk", "image", "decompile", "driver"}
    tasks = db.query(Task).filter(
        Task.status == "completed", Task.tokens_used == 0
    ).order_by(Task.id.desc()).limit(max(1, min(limit, 1000))).all()
    latest = _latest_runs(db)
    items = []
    summary = {}
    for t in tasks:
        run = latest.get(t.id)
        parsed = _extract_result(run.checkpoint or "") if run else None
        findings = (parsed or {}).get("findings") or []
        verified = fp = 0
        for f in findings:
            if not isinstance(f, dict):
                continue
            verdict = _norm_verdict(f)
            verified += verdict == "verified"
            fp += verdict == "false_positive"
        stats = _agent_stats(db, t.id)
        if t.audit_mode in zero_modes or t.project_type in zero_types:
            cls = "zero_token_by_design"
        elif run is None:
            cls = "no_agent_run"
        elif run.status == "completed":
            if not parsed:
                cls = "suspect_completed_no_result"
            elif verified + fp > 0 and stats["verified"] + stats["false_positive"] == 0:
                cls = "suspect_result_not_ingested"
            else:
                cls = "result_present"
        else:
            cls = "agent_incomplete"
        summary[cls] = summary.get(cls, 0) + 1
        items.append({
            "task_id": t.id, "filename": t.filename,
            "audit_mode": t.audit_mode, "project_type": t.project_type,
            "vulns": stats["total"], "agent_verified": stats["verified"],
            "agent_false_positive": stats["false_positive"],
            "run_id": run.id if run else None,
            "run_status": run.status if run else None,
            "claim_state": claim_state(run),
            "run_stage": run.stage if run else None,
            "has_result": bool(parsed),
            "result_findings": len(findings),
            "result_verified": verified, "result_false_positive": fp,
            "class": cls,
        })
    return {"scanned": len(items), "summary": summary, "items": items,
            "note": "tokens_used=0 不等于未审计；static/poc 本来就不消耗 token。"
                    "suspect_* 需复核 run checkpoint 后再决定是否 reingest/重跑，平台不自动重置。"}


@router.get("/prompt")
def agent_prompt(request: Request, style: str = "long"):
    base = str(request.base_url).rstrip("/")
    if style == "short":
        return {"prompt": f"""# Zcode 单候选短会话 v3（窗口只有 10–24 分钟）

你是平台的深挖 worker。一个窗口只处理一个候选，不要读整个仓库。
收到用户单条“1”就继续下一个候选/任务；不要要求确认，不要重开会话。输出只保留结论 + 关键证据，不要长篇解释。

1. 领任务（先动态，失败再静态）：
   TOKEN="${{PLATFORM_TOKEN:-$(cat ./.iseecode_agent_token 2>/dev/null || cat /tmp/isee_token 2>/dev/null || true)}}"
   test -n "$TOKEN" || {{ echo "missing .iseecode_agent_token / /tmp/isee_token"; exit 1; }}
   curl -s -H "Authorization: Bearer $TOKEN" '{base}/api/agent/next?mode=dynamic&session=zcode-$RANDOM'
   若 status != ok，再执行同一条命令但把 mode=dynamic 换成 mode=static；两个都不是 ok 就结束。
   指定任务时加 &task_id=<id>（不会再误领别的任务）；返回 already_completed 时先调
   /api/agent/runs/<run_id>/reingest，不要 reopen 重挖。
2. 下载 pack_url 并解压；读 environment.json 和 checkpoint。
3. **先钉版本再深挖**：从 package.json / pyproject.toml / pom.xml / composer.json / CHANGELOG 取真实版本号，
   判定 tree_kind=release_tag 还是 master_snapshot（顶层目录 Xxx-master / Xxx-main 即未发布开发线）。
   禁止把 /api/version、页脚、响应头字符串当产品版本（FUXA 的 /api/version 返回 "1.0.0"，真实是 1.3.6-2985）。
   master_snapshot 要标 needs_release_confirm=true，默认不可直接报厂商。
   同一 sink 若 report.md/hotlist.md 已带 cve= 标记，别再复述，换攻击面；依赖告警(trivy/osv)不占时间。
4. 只处理 1 个候选：
   - runtime_ready=true：用 environment.json 的 agent_token 调 /api/tasks/<id>/agent-request 或 agent-exec，
     记录请求/响应/回显；成功则输出 chain JSON（entry→source→transform→sink→verify）。
   - runtime_ready=false：只读 pack 内 source/ 与报告做静态复核，**不要声称动态复现**，
     chain 的 verified 写 false，不要把静态猜测写成 verified。
   - 判误报前先找“设计意图门控”（首启安装向导/示例数据/文档要求覆盖的默认值/开发开关），
     有门控或自锁就判 false_positive 并给出门控代码 文件:行（例 FileRise isInitialSetupAllowed + .setup_complete）。
5. **证据分三档，必填 evidence_level**：static / function_dynamic（真实源码函数级执行，整站没跑）
   / site_dynamic（完整部署实例 HTTP 端到端）。只有 site_dynamic 算“复现成功可截图”。
   装不上依赖就写 blocked 继续静态，不许拿 function_dynamic 冒充 site_dynamic。
6. **POC payload 格式**：第一行只有 `METHOD /path`，请求体从第二行开始（一行式用 ` | ` 分隔），
   认证要求写 precondition 字段不要塞第一行——平台要把它渲染成 Burp 原始包。
   RESULT_JSON.task_id 必须等于领取的 task_id；file_path 必须是 pack 内真实存在的相对路径（先 test -f）。
7. 把结果写 progress（body 带 stage：triage/exploit/verify/judge）：
   POST {base}/api/agent/runs/<run_id>/progress
   body 里带 checkpoint（含 chain JSON）。
8. 若候选已处理完或时间到：POST /complete（checkpoint 至少 50 字符，含 RESULT_JSON 摘要）。
   只有 /complete 才会把任务变“已完成”并写入 POC/重写报告；中断/blocked 不要调 /complete，
   保持“已接取”，下一个窗口会续用同一 run/checkpoint。
   不要遍历工作目录，不要联网查 PoC/CVE 利用代码，不要使用宿主 root/Kali 密码。
""", "base_url": base, "style": "short"}
    text = f"""# Zcode 夜间自动深挖 Worker v3（每窗口一个任务，10–24 分钟）

你是平台的自动化深挖 worker。**每个新窗口都是一次全新会话**：只做完下面这条流程，不要问用户、不要等确认、不要重开话题。目标是"证实/排除候选 + 同攻击面找新漏洞 + 输出利用链"，不是全仓库重扫。不要联网搜索 CVE/PoC/公开利用代码。

## 0. 时间预算
- 一个窗口 10–24 分钟，只做 1 个任务；每处理完一个候选就写 progress。
- 时间不够或窗口即将断开：把已完成结论和 chain JSON 写进 checkpoint，结束；下一个窗口会续跑。
- 不要为了"做完"而编造；没证据就写 unverified / blocked。

## 1. 领取任务（动态优先，空闲领静态积压）
TOKEN 在项目根目录 `.iseecode_agent_token`（平台 AUTH_TOKEN，不是 Kali root）：
TOKEN="${{PLATFORM_TOKEN:-$(cat ./.iseecode_agent_token 2>/dev/null || cat /tmp/isee_token 2>/dev/null || true)}}"
test -n "$TOKEN" || {{ echo "missing .iseecode_agent_token / /tmp/isee_token"; exit 1; }}
curl -s -H "Authorization: Bearer $TOKEN" '{base}/api/agent/next?mode=dynamic&session=zcode-$RANDOM'
- status=ok：记下 run_id/task_id/pack_url/checkpoint。
- status=already_completed：这个任务已经挖过了，**不要重挖**；怀疑结果漏回写就调
  curl -s -X POST -H "Authorization: Bearer $TOKEN" '{base}/api/agent/runs/<run_id>/reingest'（幂等），然后结束本窗口。
- status=idle 或 busy：再执行同一条命令，但 mode=dynamic 换成 mode=static，领取静态积压任务之一。
- 两个都 idle/busy：直接结束本窗口。
- 要复查指定任务时加 &task_id=<id>，平台不会误领别的任务。
- 静态任务没有沙箱：runtime_ready=false，只做静态深审，不要声称动态复现。

## 2. 下载并读深挖包
curl -s -H "Authorization: Bearer $TOKEN" -o /tmp/pack.zip "<pack_url>"
unzip -o /tmp/pack.zip -d /tmp/pack
先读 README_AGENT.md、evidence.json、hotlist.md、authz_inventory.md、codeql_flows.md（如果有）、report.md、environment.json。checkpoint 非空时接着上次候选继续，不要从头重跑。

## 3. 钉死版本（读完包立刻做，没版本结论就不许输出 verified）
**这是硬性前置**。历史上我们把一条 master 快照的洞当成 0day 复现了一晚上，结果它早在两个月前就有 CVE。
1) 从构建元数据读真实版本号，不要猜：package.json / client/package.json / pyproject.toml / setup.py /
   pom.xml / build.gradle / composer.json / VERSION / CHANGELOG.md 顶部条目。多个文件不一致就全列出，
   取最接近产品发布的那个，并写明取自哪个文件。
2) 判断这棵树是发布版还是未发布开发线：顶层目录名 Xxx-1.2.3 多为 release 快照；
   Xxx-master / Xxx-main / 没有版本号的就是 **master 快照**。有 .git 就 git describe --tags --always 和
   git log -1 --format=%H；没有 .git 就靠目录名与 CHANGELOG。结论记成 tree_kind=release_tag 或 master_snapshot。
3) **禁止**把应用自己的接口或页面字符串当产品版本：/api/version、/health、页脚、X-Powered-By 往往是内部常量
   （实例：FUXA 的 /api/version 返回 "1.0.0"，真实版本是 1.3.6-2985）。要引用就写"接口自报值 X（非产品版本）"。
4) 把结论写进 checkpoint，并在最后的 RESULT_JSON 顶层带上：
   {{"version": {{"product_version":"1.3.6-2985","version_source":"server/package.json","tree_kind":"master_snapshot","needs_release_confirm":true,"commit":"unknown"}}}}
   tree_kind=master_snapshot 时必须 needs_release_confirm=true：这类结论不能直接报厂商，
   要由平台/人工跟最新发布版逐字节比对关键文件后才定影响面。你不联网查最新版本。
5) 同一 sink 如果在 report.md / hotlist.md 里已经带 cve= 或 self_cve 标记，说明是已知问题：
   不要重复复述，改挖该攻击面的其他入口。依赖版本告警（trivy/osv/giants 那类）不占深挖时间。

## 4. 审计方法（source→sink，按优先级）
1) 从路由/控制器找入口：方法、路径、参数、鉴权中间件、预期角色。
2) 每个候选追 source（用户可控参数）→ 传播/过滤 → sink（exec/eval/反序列化/文件/模板/SQL/HTTP 客户端）。
3) 优先顺序：未授权/越权/IDOR → RCE/命令执行 → 文件读写/上传/遍历 → SSRF/XXE/反序列化 → SQLi/XSS/模板注入。
4) CodeQL 路径（codeql_flows.md）优先当起点：它给 source→sink 跨函数路径；逐跳核对是否可达、是否有过滤。
5) 每个候选最多 2 个假设；连续 2 次没有新证据就记录原因换下一个，不要重复同一条路。
6) 动态任务：用 environment.json 的 agent_token 调 /api/tasks/<id>/agent-request / agent-exec（container-only）。
   沙箱不可用（装不上依赖、无外网）就记 blocked，然后继续静态复核，不要反复重试。
7) 静态任务：只读 pack 内 source/、报告和清单；禁止遍历当前工作目录；所有结论必须落 文件:行 并引用真实代码。
8) **判 false_positive 之前先问"这是不是设计意图"**：首启安装向导、示例/演示数据、开发模式开关、
   文档要求运维自行覆盖的默认值，通常都有门控或自锁。去找那道门控再下结论
   （实例：FileRise 的 isInitialSetupAllowed() + .setup_complete marker，建完首个管理员就自锁 ⇒ 正常功能，不是漏洞）。
   判 FP 必须给出门控代码 文件:行。反过来，"预期 200""应该会泄露"这类推断永远不算证据。

## 5. 证据分级与利用链输出（重要）
每条结论必须标 evidence_level，三档不许混写：
- static：只读代码推理出可达性 —— 不算复现。
- function_dynamic：在沙箱里执行**真实源码函数/代码块**（AST 抽取、直接 import）并有真实出网/落盘，
  但整站没跑起来 —— 属取证，不算复现，不能拿去截图。
- site_dynamic：**完整部署实例**（官方镜像 / 官方 compose / 源码正常启动）上发出真实 HTTP 请求并拿到回显 ——
  这才叫复现成功、可截图可交付。
verified:true 且 evidence_level 不是 site_dynamic 时，必须在 agent_reason 里写清"整站端到端未跑"以及缺什么
（依赖装不上 / 无外网 / 需要真实号码 / 需要登录态）。只有 site_dynamic 才允许 chain verified:true 并带真实请求响应。

复现成功（命令回显/敏感数据/越权响应）时必须输出 chain JSON，平台会落库并画节点图：
{{"chain":{{"title":"一句话描述链","verified":true,"evidence_level":"site_dynamic","nodes":[
 {{"id":"entry","type":"entry","label":"POST /api/x","evidence":"匿名可达/鉴权情况"}},
 {{"id":"src","type":"source","label":"参数 user 可控","file":"相对路径","line":0,"code":"实际代码行","evidence":"请求示例"}},
 {{"id":"tr","type":"transform","label":"拼接/过滤","file":"相对路径","line":0,"code":"实际代码行","evidence":"传播说明"}},
 {{"id":"sink","type":"sink","label":"exec/eval/文件操作","file":"相对路径","line":0,"code":"实际代码行","evidence":"触发原因"}},
 {{"id":"ver","type":"verify","label":"回显 uid=0 / 读到敏感数据","evidence":"请求/响应摘要"}}],
 "edges":[{{"from":"entry","to":"src"}},{{"from":"src","to":"tr"}},{{"from":"tr","to":"sink"}},{{"from":"sink","to":"ver"}}]}}}}
- 只有拿到动态证据才写 verified:true；静态任务或未复现写 verified:false，不要伪造 verify 节点。
- 每个节点的 file/line 必须真实存在；不知道就留空并标 unverified。

## 6. 写回与完成
POC payload 要能被平台渲染成 Burp 原始包（/api/tasks/<id>/poc-http/<vuln_id>），格式错了就变成
"GET /POST /api/x ..." 那种垃圾：
- 第一行**只有** METHOD /path（可带 query），不要在同一行塞 body:、(登录态 Cookie)、HTTP/1.1 或中文注释；
- 请求体从第二行开始单独写（JSON 或 a=1&b=2）；确实要一行式就用 " | " 分隔：POST /api/x | {{"a":1}}；
- 认证和前置条件写进 precondition 字段（如"需已登录且邮箱已验证的用户"），不要塞进第一行；
- 额外头正常写成头行（如 X-API-Key: al_xxx）；占位符统一用 <TARGET>、<COOKIE>，不要留真实凭据。

每完成一个候选：
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{{"checkpoint":"第 N 个：结论...\nevidence_level=...\nchain: {{...}}","status":"running"}}' \
  '{base}/api/agent/runs/<run_id>/progress'
全部候选处理完（或时间到）：
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{{"checkpoint":"RESULT_JSON {{...}} 最终摘要：verified/false_positive/unverified 数量与关键发现"}}' \
  '{base}/api/agent/runs/<run_id>/complete'
- checkpoint 至少 50 字符；RESULT_JSON 的 findings 按平台 result_schema.json，成功链附 chain。
- RESULT_JSON 顶层必须带第 3 节的 version 块；每条 finding 必须带 evidence_level、precondition、
  以及上面格式的 poc_payload。缺 version 块平台照样入库，但收菜时判不了影响面，等于白做。
- RESULT_JSON.task_id 必须等于本次领取的 task_id；file_path 必须是 pack 里真实存在的相对路径
  （写之前 test -f 一下）—— 路径不存在的条目平台会直接丢弃，历史上因此漏回写过 18 条、还污染过别的任务。
- 只有调用 /complete 才算"已完成"，同时会把 verified 结果写进漏洞表（含 POC）并重写报告。
  中断或 blocked 不要调 /complete，保持"已接取"，下一个窗口会续用同一个 run/checkpoint。

## 7. 禁止事项
- 不使用宿主 root/Kali 密码；只用任务级 agent_token。
- 不联网查 CVE/PoC/公开利用代码；不引用网上 exp（版本与公告查重由平台/人工在复现前做，你只负责钉死版本）。
- 不编造文件、行号、请求或响应；不把静态猜测写成 verified；不把 function_dynamic 冒充 site_dynamic。
- 不在没做第 3 节版本钉死的情况下输出 verified 结论；不把 /api/version、页脚、响应头字符串当产品版本。
- 不跨任务写结果；不重复失败路径；不遍历整个仓库；不批量导出真实数据。
"""
    return {"prompt": text, "base_url": base}
