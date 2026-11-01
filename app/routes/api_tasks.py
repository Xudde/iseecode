"""任务管理 API：上传（含去重）+ 列表 + 详情 + 漏洞 + 停止 + 删除 + 报告下载 + 手工 POC"""
import hashlib
import hmac
import json
import os
import time
import re
import shutil
import threading
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Body, Depends, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session

from app.agent_state import claim_info
from app.audit_labels import vuln_label
from app.config import (ALLOWED_EXTENSIONS, DECOMPILE_EXTENSIONS, DRIVER_EXTENSIONS,
                        MAX_UPLOAD_SIZE, REPORT_DIR, UPLOAD_DIR, WORKSPACE_DIR)
from app.models import AgentRun, AuthzEndpoint, ExploitChain, PatchFeature, Task, Vulnerability
from app.queue_worker import enqueue
from app.routes.api_config import get_db
from app.schemas import TaskDetailOut, TaskOut, VulnerabilityOut
from app.skills import hotlist, poc, sandbox

router = APIRouter(prefix="/api/tasks", tags=["tasks"])

# 上传写库互斥锁：防止同一文件并发上传时双双通过去重检查
_upload_lock = threading.Lock()

# 活跃（可停止）状态
ACTIVE_STATUSES = ("pending", "preprocessing", "sast", "llm_judging", "agent_analyzing",
                   "agent_full_audit", "sandbox_deploying", "poc_verifying", "reporting")
# 去重时视为"已在审计/已审计"的状态
DEDUP_BLOCK_STATUSES = ACTIVE_STATUSES + ("completed",)

# 文件名 → (项目, 版本) 解析：包名重打也算同一个项目版本，补 file_hash 去重的漏洞
_MODE_SUFFIX = re.compile(r"[_-]{1,2}(poc|static|full|large)$", re.I)
_VERSION_RE = re.compile(r"\d+(?:\.\d+)+|20\d{6}")


def project_version(filename: str) -> tuple[str, str]:
    """从包名里拆 (project, version)；拆不出来就返回空串，不参与去重（避免误拦）。"""
    stem = _MODE_SUFFIX.sub("", os.path.splitext(filename or "")[0])
    last = None
    for m in _VERSION_RE.finditer(stem):
        last = m
    if last is None:
        return "", ""
    name = re.sub(r"[_\-]?v$", "", stem[:last.start()].strip("_-.").lower()).strip("_-.")
    return name, last.group(0)


def find_version_duplicate(db: Session, filename: str) -> Task | None:
    proj, ver = project_version(filename)
    if not proj or not ver:
        return None
    for t in db.query(Task).filter(Task.status.in_(DEDUP_BLOCK_STATUSES)).order_by(Task.id).all():
        p2, v2 = project_version(t.filename or "")
        if p2 == proj and v2 == ver:
            return t
    return None


@router.post("/upload", response_model=TaskOut)
async def upload_zip(file: UploadFile = File(...),
                     audit_mode: str = Form("full"),
                     force: str = Form("0"),
                     db: Session = Depends(get_db)):
    """上传源码包，创建任务并入队；同内容文件自动去重，避免重复审计浪费 token
    audit_mode: full=完整审计（Agent 深度研判+全量审计，消耗 token）；
                static=仅静态扫描（semgrep 免费结果，不消耗 token）；
                poc=沙箱 POC 验证（部署沙箱并验证命中，不调用 LLM/Agent，0 token）；
                large=大项目模式（取消文件数熔断，heavy 队列，适合 1GB/万文件级项目）
    force: 1=跳过"同项目同版本"去重（引擎升级后想重审同一版本时才用）"""
    if audit_mode not in ("full", "static", "poc", "large"):
        audit_mode = "full"
    ext = Path(file.filename).suffix.lower()
    is_dockerfile = "dockerfile" in file.filename.lower() or ext == ".dockerfile"
    if ext == ".apk":
        ptype = "apk"
    elif ext in DRIVER_EXTENSIONS:
        ptype = "driver"
        audit_mode = "static"  # 驱动只做静态审计，强制不消耗 token
    elif is_dockerfile or ext == ".tar":
        ptype = "image"
    elif ext in DECOMPILE_EXTENSIONS:
        ptype = "decompile"
    elif ext in ALLOWED_EXTENSIONS:
        ptype = "web"
    else:
        raise HTTPException(status_code=400, detail="支持 .zip 源码包 / .sys 驱动 / .apk 应用 / .tar 镜像包 / Dockerfile / 反编译文件（.jar .war .class .dex .dll .exe .pyc .so .elf）")

    # 同项目同版本去重：包重新打过、hash 变了也算重复，防止多方（我/Zcode/手工）重复拉同一 release
    if force not in ("1", "true", "yes"):
        dup = find_version_duplicate(db, file.filename)
        if dup is not None:
            raise HTTPException(
                status_code=409,
                detail=(f"同项目同版本已在审计或已审计：task #{dup.id} {dup.filename}"
                        f"（状态 {dup.status}，{str(dup.created_at)[:10]}）。"
                        f"要重审同一版本请带 force=1；换版本请直接上传新版本包"))

    # 流式落盘：边收边写临时文件并增量计算哈希（旧实现整包读进内存，
    # 大文件×并发上传会吃掉数百 MB 内存）
    hasher = hashlib.sha256()
    total = 0
    tmp_path = UPLOAD_DIR / f".uploading_{datetime.now().strftime('%Y%m%d%H%M%S')}_{os.getpid()}"
    try:
        with tmp_path.open("wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)  # 1MB 分块
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_UPLOAD_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="文件超过 %dMB 上限" % (MAX_UPLOAD_SIZE // 1024 // 1024))
                hasher.update(chunk)
                out.write(chunk)
        if total == 0:
            raise HTTPException(status_code=400, detail="文件为空")
        file_hash = hasher.hexdigest()

        with _upload_lock:
            # 同内容文件去重：已有任务正在审计或已完成，直接指向旧任务，不重复消耗 token
            dup = db.query(Task).filter(Task.file_hash == file_hash).order_by(Task.id.asc()).first()
            if dup and dup.status in DEDUP_BLOCK_STATUSES:
                raise HTTPException(
                    status_code=409,
                    detail=f"相同文件已存在（任务 #{dup.id}，状态：{dup.status}），已避免重复审计浪费 token。请直接查看该任务结果。",
                )

            # 保存：临时文件原子改名
            ts = datetime.now().strftime("%Y%m%d%H%M%S")
            safe_name = f"{ts}_{Path(file.filename).name}"
            save_path = UPLOAD_DIR / safe_name
            tmp_path.replace(save_path)

            task = Task(filename=file.filename, file_hash=file_hash,
                        upload_path=str(save_path), workspace_path=str(save_path),
                        project_type=ptype, audit_mode=audit_mode)
            db.add(task)
            db.commit()
            db.refresh(task)
    except HTTPException:
        tmp_path.unlink(missing_ok=True)  # 失败清理半成品临时文件
        raise
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise

    enqueue(task.id)
    return task


@router.get("", response_model=list[TaskOut])
def list_tasks(db: Session = Depends(get_db)):
    return db.query(Task).order_by(Task.id.desc()).all()


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """总览仪表盘：跨任务统计（任务状态/漏洞来源/严重性分布/最近任务）"""
    tasks = db.query(Task).order_by(Task.id.desc()).all()
    vulns = db.query(Vulnerability).all()

    final = ("completed", "failed", "skipped", "cancelled")
    t_status = Counter(t.status for t in tasks)
    verdict = Counter()
    by_source = Counter()
    by_severity = Counter()
    for v in vulns:
        if v.agent_status == "verified" or v.llm_is_real is True:
            verdict["verified"] += 1
        elif v.agent_status == "false_positive" or v.llm_is_real is False:
            verdict["false_positive"] += 1
        else:
            verdict["unjudged"] += 1
        by_source[(v.source or "semgrep")] += 1
        by_severity[(v.severity or "INFO").upper()] += 1

    # 每任务的漏洞数（用于最近任务表）
    vc = Counter(v.task_id for v in vulns)
    recent = [{
        "id": t.id, "filename": t.filename, "status": t.status,
        "tech_stack": t.tech_stack, "vuln_count": vc.get(t.id, 0),
        "created_at": str(t.created_at or ""),
    } for t in tasks[:8]]

    return {
        "tasks": {
            "total": len(tasks),
            "active": sum(n for s, n in t_status.items() if s not in final),
            "completed": t_status.get("completed", 0),
            "failed": t_status.get("failed", 0) + t_status.get("skipped", 0) + t_status.get("cancelled", 0),
        },
        "vulns": {
            "total": len(vulns),
            "verified": verdict["verified"],
            "false_positive": verdict["false_positive"],
            "unjudged": verdict["unjudged"],
            "poc_verified": sum(1 for v in vulns if v.poc_verified is True),
        },
        "by_source": dict(by_source),
        "by_severity": dict(by_severity),
        "recent": recent,
    }


@router.get("/history")
def get_history(db: Session = Depends(get_db)):
    """历史审计项目：按 SHA-256 聚合，展示已审计版本/重复次数，避免重复上传。"""
    tasks = db.query(Task).order_by(Task.id.desc()).all()
    vc = Counter()
    for v in db.query(Vulnerability.task_id).all():
        vc[v[0]] += 1
    groups = {}
    for t in tasks:
        key = t.file_hash or f"name:{t.filename}"
        g = groups.get(key)
        if g is None:
            g = {
                "key": key, "filename": t.filename,
                "project_type": t.project_type, "tech_stack": t.tech_stack,
                "first_at": str(t.created_at or ""), "last_at": str(t.created_at or ""),
                "runs": 0, "vuln_count": 0, "task_ids": [],
                "latest_id": t.id, "latest_status": t.status,
                "latest_mode": t.audit_mode,
            }
            groups[key] = g
        g["runs"] += 1
        g["vuln_count"] += vc.get(t.id, 0)
        g["task_ids"].append(t.id)
        if t.id > g["latest_id"]:
            g["latest_id"] = t.id
            g["latest_status"] = t.status
            g["latest_mode"] = t.audit_mode
            g["last_at"] = str(t.created_at or "")
    items = sorted(groups.values(), key=lambda x: -x["latest_id"])
    latest_runs = {}
    for r in db.query(AgentRun).order_by(AgentRun.id.desc()).all():
        latest_runs.setdefault(r.task_id, r)
    for g in items:
        r = latest_runs.get(g["latest_id"])
        info = claim_info(r)
        g["deep_status"] = info["claim_state"]
        g.update(info)
        g["raw_run_status"] = (r.status or "") if r else ""
        g["deep_checkpoint"] = (r.checkpoint or "")[:200] if r else ""
    return {"total": len(items), "items": items}


def _agent_token(task_id: int, ttl: int = 43200) -> str:
    """任务级限时令牌：只能访问该任务沙箱的 HTTP 代理，不是宿主 SSH 密码。"""
    secret = (os.environ.get("AUTH_TOKEN") or "audit-agent-secret").encode()
    exp = int(time.time()) + ttl
    sig = hmac.new(secret, f"{task_id}:{exp}".encode(), hashlib.sha256).hexdigest()[:32]
    return f"{task_id}.{exp}.{sig}"


def _verify_agent_token(task_id: int, token: str) -> bool:
    try:
        tid, exp, sig = token.split(".", 2)
        if int(tid) != task_id or int(exp) < int(time.time()):
            return False
        secret = (os.environ.get("AUTH_TOKEN") or "audit-agent-secret").encode()
        want = hmac.new(secret, f"{task_id}:{exp}".encode(), hashlib.sha256).hexdigest()[:32]
        return hmac.compare_digest(sig, want)
    except (ValueError, TypeError):
        return False


_SENSITIVE_SUFFIXES = (
    ".db", ".sqlite", ".sqlite3", ".db-wal", ".db-shm", ".db-journal",
    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".secret",
    ".env", ".kdbx",
)
_SENSITIVE_NAMES = {
    ".auth_secret", "auth_secret", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "credentials", "secrets", ".netrc", ".pgpass", ".htpasswd",
}


def _is_sensitive_rel(rel: str) -> bool:
    """深挖包不携带运行时数据库/密钥；只发源码切片。"""
    parts = [p for p in str(rel or "").replace("\\", "/").split("/") if p]
    if not parts or any(p == ".." for p in parts):
        return True
    if any(p in (".git", ".svn", ".hg") for p in parts):
        return True
    name = parts[-1].lower()
    if name in _SENSITIVE_NAMES or name.startswith(".env"):
        return True
    if name.startswith("id_rsa") or name.startswith("id_ed25519"):
        return True
    return name.endswith(_SENSITIVE_SUFFIXES)


def _write_agent_pack(zf, task, rows, base: str, prefix: str = "") -> bool:
    """把单个任务的 AI 深挖包写入已打开的 zip；prefix 用于批量导出子目录。"""
    from app.skills import agent_prompt, authz_inventory
    ws = Path(task.workspace_path or "")
    if not ws.is_dir():
        return False
    prompt = agent_prompt.build(task, base)
    try:
        inv = authz_inventory.scan(str(ws))
        inv_md = authz_inventory.to_markdown(inv, task)
    except Exception:
        inv = {}
        inv_md = "# authz inventory generation failed"
    try:
        hot = hotlist.build(task, rows, top_n=20)
        hot_md = hotlist.to_markdown(task, hot)
    except Exception:
        hot, hot_md = {"items": []}, "# hotlist generation failed"
    evidence = {
        "task": {"id": task.id, "filename": task.filename,
                 "tech_stack": task.tech_stack, "audit_mode": task.audit_mode,
                 "report": task.report_path},
        "candidates": [{
            "id": v.id, "source": v.source, "rule_id": v.rule_id,
            "title": v.title, "severity": v.severity,
            "file_path": v.file_path, "line": v.line,
            "precondition": v.precondition, "poc_payload": v.poc_payload,
            "poc_verified": v.poc_verified, "verify_result": v.verify_result,
            "agent_evidence": v.agent_evidence,
        } for v in rows[:120]],
        "authz_summary": inv.get("summary") if isinstance(inv, dict) else {},
    }
    schema = {
        "task_id": task.id,
        "findings": [{"title": "string", "status": "verified|unverified",
                      "ai_verdict": "verified|false_positive|unverified",
                      "severity": "CRITICAL|HIGH|MEDIUM|LOW", "confidence": "high|medium|low",
                      "cwe": "CWE-xxx", "cve": "CVE-xxx or ''", "file": "relative/path",
                      "line": 0, "route": "/...", "method": "GET|POST", "auth_required": True,
                      "expected_role": "anonymous|user|admin", "payload": "",
                      "request": "", "response": "", "evidence": "",
                      "repro_steps": [], "impact": "", "fix": "",
                      "chain": {"title": "string", "verified": True,
                                "nodes": [{"id": "entry|src|tr|sink|ver",
                                           "type": "entry|source|transform|sink|verify",
                                           "label": "字符串", "file": "relative/path",
                                           "line": 0, "code": "该行代码",
                                           "evidence": "请求/响应/推理摘要"}],
                                "edges": [{"from": "entry", "to": "src"}]}}],
        "summary": {"ai_verified": 0, "ai_false_positive": 0, "unverified": 0},
        "attempts": [{"candidate": "", "result": "failed|verified|blocked", "reason": ""}],
    }
    access = None
    cid = getattr(task, "sandbox_cid", None)
    sandbox_running = False
    if cid:
        try:
            sandbox_running = sandbox.is_running(cid)
        except Exception:
            sandbox_running = False
    if cid and sandbox_running:
        access = {
            "mode": "remote-sandbox-http-proxy",
            "api": base + f"/api/tasks/{task.id}/agent-request",
            "token": _agent_token(task.id),
            "expires_in_seconds": 43200,
            "scope": "仅该任务沙箱 HTTP 请求；不包含宿主 SSH/Kali 密码",
            "usage": "POST JSON {method,path,params}; Header X-Agent-Token: <token>",
            "exec_api": base + f"/api/tasks/{task.id}/agent-exec",
            "exec_usage": "POST JSON {command,timeout}; Header X-Agent-Token: <token>; container-only",
            "sandbox_cid": task.sandbox_cid,
            "sandbox_port": task.sandbox_port,
        }
    if access is None and task.audit_mode == "poc":
        env_note = ("沙箱容器已退出/被清理，runtime_ready=false；如需动态验证请重新部署沙箱，"
                    "否则只读 pack 内 source/ 与报告，不要遍历工作目录。")
    elif access is None:
        env_note = ("NO_RUNTIME_TOKEN：静态任务没有沙箱。只允许读 pack 内 source/ 和报告，"
                    "禁止遍历当前工作目录；标记 static_only 并结束，等待人工起沙箱。")
    else:
        env_note = "有沙箱：优先使用任务级 HTTP/exec 代理；不要把宿主 root/Kali 密码写进任何 AI 会话。"
    environment = {
        "task_id": task.id,
        "workspace": str(task.workspace_path),
        "runtime_ready": bool(access),
        "sandbox": access,
        "note": env_note,
        "sandbox_state": ("running" if access else ("exited" if cid else "none")),
        "credentials": {"host_root": "NOT INCLUDED BY DESIGN",
                        "test_accounts": "由用户在任务环境内创建；平台不会生成或导出宿主密码"},
    }
    readme = prompt + """

## Zcode 使用说明

这是平台导出的 AI 深挖包，平台不会直接调用 Zcode 的夜间模型额度；额度由你在 Zcode 里开会话消耗。

1. 先读 `report.md`、`evidence.json`、`hotlist.md`、`authz_inventory.md`。
2. `source/` 是平台排出的重点源码切片；如果不够，向用户索要完整项目目录，不要臆造文件。
3. 按提示词逐条验证候选：每个候选最多 2 个假设，失败写 attempts，不要重复全路径。
4. 夜间窗口建议 23:00–08:45；08:30 后停止开新候选，避免跨过期点。
5. 输出严格按 `result_schema.json` 的 JSON，便于平台回写 AI 验真/误报统计。
6. `environment.json` 里若有任务级 agent_token，可调用 `/api/tasks/<id>/agent-request`
   访问沙箱 HTTP，或 `/api/tasks/<id>/agent-exec` 在沙箱容器内执行命令；
   它不是宿主 SSH/Kali 密码，且 12 小时后失效。
7. 如果 `environment.json` 的 `runtime_ready=false`：只读 pack 内 `source/` 和报告，
   **禁止遍历当前工作目录**，把 checkpoint 写 `static_only` 并结束。
8. 包内不会携带运行时数据库/密钥（`*.db`、`*.sqlite`、`.auth_secret`、`.env`、`*.pem` 等）；
   如果你在工作区看到这些文件，禁止读取、复制或用于登录，只能作为“存在敏感文件”的静态事实记录。
"""
    zf.writestr(prefix + "environment.json",
                json.dumps(environment, ensure_ascii=False, indent=2))
    zf.writestr(prefix + "README_AGENT.md", readme)
    zf.writestr(prefix + "evidence.json", json.dumps(evidence, ensure_ascii=False, indent=2))
    zf.writestr(prefix + "result_schema.json", json.dumps(schema, ensure_ascii=False, indent=2))
    zf.writestr(prefix + "authz_inventory.md", inv_md)
    zf.writestr(prefix + "hotlist.md", hot_md)
    try:
        from app.db import SessionLocal
        from app.skills import authz_semantic
        s = SessionLocal()
        try:
            arows = s.query(AuthzEndpoint).filter(AuthzEndpoint.task_id == task.id).all()
            if arows:
                adata = authz_semantic.rows_to_data(arows)
                zf.writestr(prefix + "authz_semantic.md",
                            authz_semantic.to_markdown(adata, task))
        finally:
            s.close()
    except Exception:
        pass
    codeql_flows = [v for v in rows if (v.source or "") == "codeql" and v.agent_evidence]
    if codeql_flows:
        flow_md = ["# CodeQL 数据流路径", "",
                   "> 由 CodeQL codeFlows 提取：source → ... → sink，每步带 file:line 与代码。", ""]
        for v in codeql_flows[:80]:
            flow_md.append(f"- **{v.rule_id}** `{v.file_path}:{v.line}` {v.title or ''}")
            flow_md.append("  " + (v.agent_evidence or "").replace("\n", " ")[:1200])
            flow_md.append("")
        zf.writestr(prefix + "codeql_flows.md", "\n".join(flow_md))
    if task.report_path:
        rp = Path(task.report_path)
        for pth, arc in ((rp.with_suffix(".md"), "report.md"),
                         (rp.with_suffix(".json"), "report.json")):
            if pth.exists():
                zf.write(pth, prefix + arc)
    total = 0
    excluded_sensitive = []
    ws_root = ws.resolve()
    for it in (hot.get("items") or [])[:20]:
        rel = str(it.get("file_path") or "").replace("\\", "/").lstrip("/")
        if _is_sensitive_rel(rel):
            excluded_sensitive.append(rel)
            continue
        src = ws / rel
        try:
            src.resolve().relative_to(ws_root)
        except (OSError, ValueError):
            excluded_sensitive.append(rel)
            continue
        try:
            if not src.is_file() or src.stat().st_size > 300 * 1024:
                continue
            data = src.read_bytes()
            if total + len(data) > 10 * 1024 * 1024:
                break
            zf.writestr(prefix + "source/" + rel, data)
            total += len(data)
        except OSError:
            continue
    if excluded_sensitive:
        zf.writestr(prefix + "excluded_sensitive.json", json.dumps({
            "note": "runtime secrets/databases are never packed",
            "paths": excluded_sensitive[:200],
        }, ensure_ascii=False, indent=2))
    return True


@router.get("/{task_id}/agent-pack")
def get_agent_pack(task_id: int, request: Request, db: Session = Depends(get_db)):
    """导出单个任务的 AI 深挖包：报告 + 候选 + 清单 + 源码切片 + 提示词。

    失败时不留半成品：以前 `with ZipFile(out,"w")` 先建文件再抛 404，关闭时剩下 22 字节的
    合法空 zip，看起来像"包已生成"，下游台账会误判成可离线复核
    （2026-11-01 实测 data/reports 里有 40 个这种空包）。
    """
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    rows = db.query(Vulnerability).filter(Vulnerability.task_id == task_id).all()
    out = REPORT_DIR / f"task_{task_id}_agent_pack.zip"
    try:
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
            if not _write_agent_pack(zf, task, rows, str(request.base_url).rstrip("/")):
                raise HTTPException(status_code=404, detail="工作区不存在，无法生成深挖包")
            entries = sum(1 for n in zf.namelist() if not n.endswith("/"))
        if entries == 0:
            raise HTTPException(status_code=409,
                                detail=f"深挖包内容为空（工作区可能是空目录），不产出空包 #{task_id}")
    except HTTPException:
        try:
            out.unlink()
        except OSError:
            pass
        raise
    return FileResponse(out, media_type="application/zip",
                        filename=f"task_{task_id}_agent_pack.zip")


@router.post("/agent-packs")
def get_agent_packs(task_ids: list[int] = Body(..., embed=True),
                    request: Request = None, db: Session = Depends(get_db)):
    """批量导出多个任务的 AI 深挖包（外层一个 zip，每个任务一个目录）。"""
    if not task_ids:
        raise HTTPException(status_code=400, detail="task_ids 不能为空")
    ids = list(dict.fromkeys(task_ids))[:20]
    base = str(request.base_url).rstrip("/") if request else ""
    out = REPORT_DIR / f"agent_packs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    included = []
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for tid in ids:
            task = db.get(Task, tid)
            if task is None:
                continue
            rows = db.query(Vulnerability).filter(Vulnerability.task_id == tid).all()
            if _write_agent_pack(zf, task, rows, base, f"task_{tid}/"):
                involved = task.filename
                included.append((tid, involved))
        manifest = "# 批量 AI 深挖包 | " + " | ".join(
            f"task_{tid}: {name}" for tid, name in included)
        zf.writestr("README_BATCH.md", manifest)
    if not included:
        try:
            out.unlink()
        except OSError:
            pass
        raise HTTPException(status_code=404, detail="没有可导出的任务工作区")
    return FileResponse(out, media_type="application/zip",
                        filename=out.name)


@router.post("/{task_id}/agent-request")
def agent_request(task_id: int, payload: dict = Body(...),
                  x_agent_token: str | None = Header(None, alias="X-Agent-Token"),
                  agent_token: str = "",
                  db: Session = Depends(get_db)):
    """任务级沙箱 HTTP 代理：供 AI 深挖包里的 agent_token 使用，不暴露宿主密码。"""
    token = x_agent_token or agent_token
    if not token or not _verify_agent_token(task_id, token):
        raise HTTPException(status_code=403, detail="agent_token 无效或已过期")
    task = db.get(Task, task_id)
    if task is None or not getattr(task, "sandbox_cid", None):
        raise HTTPException(status_code=400, detail="该任务没有保留沙箱")
    method = str(payload.get("method") or "GET").upper()
    if method not in ("GET", "POST"):
        raise HTTPException(status_code=400, detail="agent 代理只允许 GET/POST")
    path = str(payload.get("path") or "/")
    if not path.startswith("/"):
        raise HTTPException(status_code=400, detail="path 必须以 / 开头")
    params = payload.get("params") or None
    if params is not None and not isinstance(params, dict):
        raise HTTPException(status_code=400, detail="params 必须是对象")
    import docker
    try:
        client = docker.from_env()
        container = client.containers.get(task.sandbox_cid)
        handle = sandbox.SandboxHandle(client, container, None, task.sandbox_port)
        status, body = handle.request(path, params=params, method=method)
    except docker.errors.NotFound:
        raise HTTPException(status_code=400, detail="沙箱容器不存在")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"沙箱请求失败: {exc}")
    return {"status": status, "body": (body or "")[:8000]}


@router.post("/{task_id}/agent-exec")
def agent_exec(task_id: int, payload: dict = Body(...),
               x_agent_token: str | None = Header(None, alias="X-Agent-Token"),
               db: Session = Depends(get_db)):
    """任务级沙箱 exec：只在容器内执行，不触碰宿主/Kali root。"""
    token = x_agent_token or str(payload.get("token") or "")
    if not token or not _verify_agent_token(task_id, token):
        raise HTTPException(status_code=403, detail="agent_token 无效或已过期")
    task = db.get(Task, task_id)
    if task is None or not getattr(task, "sandbox_cid", None):
        raise HTTPException(status_code=400, detail="该任务没有保留沙箱")
    command = str(payload.get("command") or "").strip()
    if not command or len(command) > 3000:
        raise HTTPException(status_code=400, detail="command 为空或过长")
    try:
        timeout = max(1, min(int(payload.get("timeout") or 20), 60))
    except (TypeError, ValueError):
        timeout = 20
    import docker
    try:
        client = docker.from_env()
        container = client.containers.get(task.sandbox_cid)
        out = container.exec_run(["timeout", str(timeout), "sh", "-lc", command],
                                 demux=False)
        text = (out.output or b"").decode(errors="replace")
        return {"exit_code": out.exit_code, "output": text[:20000],
                "scope": "container-only; no host/Kali root"}
    except docker.errors.NotFound:
        raise HTTPException(status_code=400, detail="沙箱容器不存在")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"容器执行失败: {exc}")


@router.get("/{task_id}", response_model=TaskDetailOut)
def get_task(task_id: int, db: Session = Depends(get_db)):
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    return task


@router.get("/{task_id}/vulns", response_model=list[VulnerabilityOut])
def get_task_vulns(task_id: int, db: Session = Depends(get_db)):
    return db.query(Vulnerability).filter(Vulnerability.task_id == task_id).all()


@router.get("/{task_id}/chains")
def get_task_chains(task_id: int, db: Session = Depends(get_db)):
    """阶段 0.8：任务页利用链节点图数据（nodes/edges）。"""
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    rows = db.query(ExploitChain).filter(
        ExploitChain.task_id == task_id).order_by(ExploitChain.id).all()
    out = []
    for c in rows:
        try:
            nodes = json.loads(c.nodes_json or "[]")
        except Exception:
            nodes = []
        try:
            edges = json.loads(c.edges_json or "[]")
        except Exception:
            edges = []
        out.append({"id": c.id, "title": c.title, "verified": bool(c.verified),
                    "nodes": nodes, "edges": edges,
                    "created_at": c.created_at.isoformat(sep=" ", timespec="seconds")
                    if c.created_at else None})
    return out


@router.post("/{task_id}/chains/generate")
def generate_task_chains(task_id: int, db: Session = Depends(get_db)):
    """阶段 3：按鉴权入口 + sink 候选生成静态利用链（verified=false）。"""
    from app.skills import chain_engine
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    try:
        n = chain_engine.generate_and_store(db, task_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"利用链生成失败: {e}")
    return {"ok": True, "task_id": task_id, "created": n}


@router.post("/{task_id}/chains/{chain_id}/verify")
def verify_task_chain(task_id: int, chain_id: int, payload: dict = Body(default={}),
                      db: Session = Depends(get_db)):
    """阶段 3 v2：在任务沙箱内验证一条链；成功后写动态复现库。"""
    from app.skills import chain_engine
    task = db.get(Task, task_id)
    chain = db.get(ExploitChain, chain_id)
    if task is None or chain is None or chain.task_id != task_id:
        raise HTTPException(status_code=404, detail="任务或利用链不存在")
    spec = payload or None
    try:
        if spec:
            result = chain_engine.verify_chain(db, task, chain, spec)
        else:
            specs = chain_engine.auto_specs(chain, int(task.sandbox_port or 5000))
            if not specs:
                raise RuntimeError("没有可用的自动模板，请显式提供 method/path/params/expect_*")
            result = {"ok": True, "verified": False, "attempts": [],
                      "note": "全部自动尝试失败"}
            for s in specs:
                result = chain_engine.verify_chain(db, task, chain, s)
                if result.get("verified"):
                    break
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"链验证失败: {e}")
    return result


@router.post("/{task_id}/tool-scan")
def tool_scan(task_id: int, payload: dict = Body(default={}),
              db: Session = Depends(get_db)):
    """阶段 6：沙箱内 ffuf 轻量路径扫描（不生成注入 payload）。"""
    from app.skills import tool_scan as ts
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if not getattr(task, "sandbox_cid", None) or not sandbox.is_running(task.sandbox_cid):
        raise HTTPException(status_code=400, detail="沙箱未运行或已退出")
    tool = str(payload.get("tool") or "ffuf")
    try:
        timeout = max(10, min(int(payload.get("timeout") or 90), 180))
    except (TypeError, ValueError):
        timeout = 90
    try:
        result = ts.run_tool(task, tool, timeout)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"轻扫失败: {e}")
    return {"ok": True, **result}


@router.get("/{task_id}/hotlist")
def get_hotlist(task_id: int, top_n: int = 20, format: str = "json",
                db: Session = Depends(get_db)):
    """人工深挖 Top-N 文件清单（0 token）：默认 JSON；format=md 用于复制/下载给 IDE Agent。"""
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    vulns = db.query(Vulnerability).filter(Vulnerability.task_id == task_id).all()
    data = hotlist.build(task, vulns, top_n=max(5, min(int(top_n or 20), 50)))
    if format == "md":
        md = hotlist.to_markdown(task, data)
        return Response(
            content=md, media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="task_{task_id}_hotlist.md"'},
        )
    return data


@router.post("/{task_id}/stop")
def stop_task(task_id: int, db: Session = Depends(get_db)):
    """请求停止任务：协作式取消，worker 在阶段间检查并清理沙箱，且保留已发现结果生成阶段性报告"""
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if task.status not in ACTIVE_STATUSES:
        raise HTTPException(status_code=400, detail=f"任务已结束（{task.status}），无需停止")
    task.cancel_requested = True
    if task.status == "pending":
        task.status = "cancelled"  # 还在队列里，直接标记取消
        task.error_msg = "任务已被停止（已发现结果已保存，可点击“继续任务”续跑）"
    db.commit()
    return {"ok": True, "id": task.id, "status": task.status, "hint": "已发现结果将保留并生成阶段性报告，可点击“继续任务”续跑"}


@router.post("/{task_id}/resume")
def resume_task(task_id: int, db: Session = Depends(get_db)):
    """继续任务：停止/失败/跳过的任务从已有进度续跑。
    已研判的漏洞（agent_status 非空）不会重复分析，不重复消耗 token。"""
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if task.status not in ("cancelled", "failed", "skipped"):
        raise HTTPException(status_code=400, detail=f"仅已停止/失败/跳过的任务可继续（当前 {task.status}）")
    if task.cancel_requested:
        task.cancel_requested = False
    task.status = "pending"
    task.error_msg = None
    task.log = (task.log or "") + f"\n[{datetime.now().strftime('%H:%M:%S')}] 任务继续：从已有进度恢复，已研判结果不重复消耗 token"
    db.commit()
    enqueue(task.id)
    return {"ok": True, "id": task.id, "status": task.status}


@router.delete("/{task_id}")
def delete_task(task_id: int, db: Session = Depends(get_db)):
    """删除任务：清理数据库记录与上传/工作区/报告文件；仅允许删除终态任务。
    （此前"cancel_requested 即可删"会与仍在运行的 worker 竞态：删除 rmtree 工作区导致
    运行中任务异常，且 SQLite 复用 rowid 造成新旧任务同 id 双跑——task 25 事故根因）"""
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if task.status not in ("completed", "failed", "skipped", "cancelled"):
        raise HTTPException(status_code=409, detail="任务仍在运行/排队，请先停止并等待任务进入终态后再删除")

    db.query(Vulnerability).filter(Vulnerability.task_id == task_id).delete()
    # 阶段 0.5：同步删除深挖会话记录，否则 SQLite 复用 rowid 时新任务会继承旧 run 状态
    db.query(AgentRun).filter(AgentRun.task_id == task_id).delete()
    db.query(ExploitChain).filter(ExploitChain.task_id == task_id).delete()
    db.query(AuthzEndpoint).filter(AuthzEndpoint.task_id == task_id).delete()
    db.query(PatchFeature).filter(PatchFeature.task_id == task_id).delete()
    # 销毁保留的沙箱容器（手工 POC 验证用），避免容器残留
    if getattr(task, "sandbox_cid", None):
        try:
            import docker
            docker.from_env().containers.get(task.sandbox_cid).remove(force=True)
        except Exception:
            pass
    paths = {task.upload_path, task.workspace_path,
             str(WORKSPACE_DIR / f"task_{task_id}_driver_decompiled")}
    if task.report_path:
        paths.add(task.report_path)
        paths.add(str(Path(task.report_path).with_suffix(".md")))
    db.delete(task)
    db.commit()

    for p in paths:
        if not p:
            continue
        try:
            fp = Path(p)
            if fp.is_dir():
                shutil.rmtree(fp, ignore_errors=True)
            elif fp.exists():
                fp.unlink(missing_ok=True)
        except Exception:
            pass
    return {"ok": True, "id": task_id}


@router.get("/{task_id}/authz-semantic")
def get_authz_semantic(task_id: int, format: str = "json",
                       db: Session = Depends(get_db)):
    """阶段 1：框架级鉴权语义（标签 + 中间件链证据）。"""
    from app.skills import authz_semantic
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    rows = db.query(AuthzEndpoint).filter(AuthzEndpoint.task_id == task_id).all()
    if not rows:
        ws = Path(task.workspace_path or "")
        if not ws.is_dir():
            raise HTTPException(status_code=404, detail="工作区不存在，无法分析")
        data = authz_semantic.scan(str(ws))
        authz_semantic.store(db, task_id, data)
    else:
        data = authz_semantic.rows_to_data(rows)
    if format == "md":
        return Response(
            authz_semantic.to_markdown(data, task),
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition":
                     f'attachment; filename="task_{task_id}_authz_semantic.md"'})
    return Response(json.dumps(data, ensure_ascii=False),
                    media_type="application/json; charset=utf-8")


@router.get("/{task_id}/authz-inventory")
def get_authz_inventory(task_id: int, format: str = "json",
                        db: Session = Depends(get_db)):
    """未授权/越权接口静态候选清单（路由 + 鉴权标记 + 无凭证 POC）。"""
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if not task.workspace_path or not Path(task.workspace_path).is_dir():
        raise HTTPException(status_code=404, detail="工作区不存在，可能已被清理")
    from app.skills import authz_inventory
    data = authz_inventory.scan(task.workspace_path)
    if format == "md":
        return Response(
            authz_inventory.to_markdown(data, task),
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition":
                     f'attachment; filename="task_{task_id}_authz_inventory.md"'})
    return Response(authz_inventory.to_json(data),
                    media_type="application/json; charset=utf-8")


@router.post("/{task_id}/authz-probe")
def authz_probe(task_id: int, max_n: int = 10, allow_write: bool = False,
                confirm: str = "", db: Session = Depends(get_db)):
    """对未授权候选做无凭证 GET 探测；只证明可访问性，不批量导出。"""
    if allow_write and confirm != "YES":
        raise HTTPException(status_code=400,
                            detail="写操作探测必须显式确认：allow_write=true&confirm=YES")
    task = db.get(Task, task_id)
    if task is None or not getattr(task, "sandbox_cid", None):
        raise HTTPException(status_code=400, detail="该任务没有保留沙箱，无法动态探测")
    if not task.workspace_path or not Path(task.workspace_path).is_dir():
        raise HTTPException(status_code=404, detail="工作区不存在")
    from app.skills import authz_inventory
    data = authz_inventory.scan(task.workspace_path)
    allowed_methods = {"GET", "ANY"} | ({"POST"} if allow_write else set())
    candidates = [e for e in data.get("items", [])
                  if not e.get("protected") and e.get("method") in allowed_methods]
    max_n = max(1, min(int(max_n or 10), 20))
    import docker
    try:
        client = docker.from_env()
        container = client.containers.get(task.sandbox_cid)
        handle = sandbox.SandboxHandle(client, container, None, task.sandbox_port)
    except docker.errors.NotFound:
        raise HTTPException(status_code=400, detail="沙箱容器不存在，可能已被清理")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"连接沙箱失败: {e}")
    blocked_marks = ("unauthorized", "forbidden", "permission denied",
                     "please log in", "请先登录", "未登录", "无权限", "登录后")
    param_pat = re.compile(r"\{[^}]+\}|:[A-Za-z_]\w*|<[^>]+>")
    results = []
    for e in candidates[:max_n]:
        raw = e.get("path", "")
        method = "GET" if e.get("method") == "ANY" else e.get("method", "GET")
        if method == "POST" and any(k in raw.lower() for k in (
                "delete", "remove", "drop", "reset", "shutdown", "logout", "revoke")):
            results.append({"method": method, "path": raw, "status": 0,
                            "accessible_without_auth": False,
                            "note": "危险写操作路径，已跳过自动探测"})
            continue
        path = e["poc"]["path"]
        try:
            status, body = handle.request(path, method=method)
        except Exception as exc:
            results.append({"method": "GET", "path": raw, "status": 0,
                            "accessible_without_auth": False,
                            "error": f"{type(exc).__name__}: {exc}"[:200]})
            continue
        low = (body or "").lower()
        blocked = status in (401, 403) or any(m in low for m in blocked_marks)
        accessible = 200 <= status < 400 and not blocked and bool((body or "").strip())
        item = {
            "method": method, "path": raw, "file": e.get("file"),
            "line": e.get("line"), "status": status,
            "accessible_without_auth": accessible,
            "body_snippet": (body or "")[:300],
            "note": ("无凭证返回 2xx/3xx，需结合业务确认是否越权" if accessible
                     else ("疑似被鉴权拦截" if blocked else "无有效响应/路由不可达")),
        }
        if method == "GET" and accessible and param_pat.search(raw):
            variants = []
            for n in (2, 3):
                p = param_pat.sub(str(n), raw)
                try:
                    st2, body2 = handle.request(p, method="GET")
                except Exception:
                    continue
                variants.append({"path": p, "status": st2,
                                 "sample": (body2 or "")[:120]})
            if variants and any(v["status"] == 200 for v in variants):
                item["enumeration_signal"] = True
                item["enumeration_samples"] = variants[:2]
                item["note"] += "；相邻 ID 也返回 200，需确认是否可越权取数（仅测 3 个 ID）"
        results.append(item)
    return {
        "task_id": task_id, "sandbox_cid": task.sandbox_cid,
        "summary": {"tested": len(results),
                    "accessible_without_auth": sum(1 for r in results if r.get("accessible_without_auth")),
                    "enumeration_signal": sum(1 for r in results if r.get("enumeration_signal")),
                    "note": "仅 GET/ANY + 显式确认的 POST；只证明可访问性，不是漏洞结论"},
        "results": results,
    }


@router.get("/{task_id}/agent-prompt")
def get_agent_prompt(task_id: int, request: Request, download: bool = False,
                     db: Session = Depends(get_db)):
    """生成给外部 IDE Agent 的定点复现/扩展挖掘提示词（不含密钥）。"""
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    from app.skills.agent_prompt import build
    prompt = build(task, str(request.base_url).rstrip("/"))
    if download:
        return Response(
            prompt, media_type="text/plain; charset=utf-8",
            headers={"Content-Disposition":
                     f'attachment; filename="task_{task_id}_agent_prompt.md"'})
    return {
        "prompt": prompt,
        "workspace": task.workspace_path,
        "report": task.report_path,
    }


@router.get("/{task_id}/report")
def download_report(task_id: int, db: Session = Depends(get_db), format: str = "html"):
    """下载报告：默认自包含 HTML；format=md 人看 Markdown；format=json AI 版结构化 JSON"""
    task = db.get(Task, task_id)
    if task is None or not task.report_path or not Path(task.report_path).exists():
        raise HTTPException(status_code=404, detail="报告不存在")
    if format == "md":
        md_path = Path(task.report_path).with_suffix(".md")
        if not md_path.exists():
            raise HTTPException(status_code=404, detail="Markdown 报告不存在")
        return FileResponse(md_path, media_type="text/markdown", filename=f"task_{task_id}_report.md")
    if format == "json":
        json_path = Path(task.report_path).with_suffix(".json")
        if not json_path.exists():
            raise HTTPException(status_code=404, detail="JSON 报告不存在（旧版报告代码生成，可重新生成）")
        return FileResponse(json_path, media_type="application/json", filename=f"task_{task_id}_report.json")
    return FileResponse(
        task.report_path,
        media_type="text/html",
        filename=f"task_{task_id}_report.html",
    )


@router.post("/{task_id}/poc-test")
def poc_test(task_id: int, vuln_id: int = Body(...), payload: str = Body(""),
             db: Session = Depends(get_db)):
    """手工 POC 验证：在保留的沙箱容器内执行 payload，返回 HTTP 状态码与回显内容"""
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if not getattr(task, "sandbox_cid", None):
        raise HTTPException(status_code=400, detail="沙箱已销毁：仅已完成且保留沙箱的任务可手动验证")
    vuln = db.get(Vulnerability, vuln_id)
    if vuln is None or vuln.task_id != task_id:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    payload = (payload or vuln.poc_payload or "").strip()
    if not payload:
        raise HTTPException(status_code=400, detail="该漏洞没有可执行的 payload")
    req = poc.parse_poc_request(payload)
    try:
        import docker
        client = docker.from_env()
        container = client.containers.get(task.sandbox_cid)
        handle = sandbox.SandboxHandle(client, container, None, task.sandbox_port)
        url = req["route"]
        if req["query_params"]:
            qs = "&".join(f"{k}={v}" for k, v in req["query_params"].items())
            url += ("&" if "?" in url else "?") + qs
        status, text = handle.request(url, params=req["body_params"] or None, method=req["method"])
    except docker.errors.NotFound:
        raise HTTPException(status_code=400, detail="沙箱容器已不存在（可能被清理），请重新审计")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"沙箱执行失败: {e}")
    return {"status": status, "response": text[:4000]}


@router.get("/{task_id}/poc-script/{vuln_id}")
def poc_script(task_id: int, vuln_id: int, db: Session = Depends(get_db)):
    """下载该漏洞的独立 Python POC 脚本（可对真实部署执行）"""
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    vuln = db.get(Vulnerability, vuln_id)
    if vuln is None or vuln.task_id != task_id:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    payload = (vuln.poc_payload or "").strip()
    if not payload:
        raise HTTPException(status_code=400, detail="该漏洞没有已验证 payload，无法生成 POC 脚本")
    script = poc.generate_python_poc(payload, vuln_label(vuln.rule_id))
    return Response(
        content=script,
        media_type="text/x-python",
        headers={"Content-Disposition": f'attachment; filename="poc_task{task_id}_vuln{vuln_id}.py"'},
    )


@router.get("/{task_id}/poc-http/{vuln_id}")
def poc_http(task_id: int, vuln_id: int, db: Session = Depends(get_db)):
    """下载 Burp Repeater 原始请求包（.http）"""
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    vuln = db.get(Vulnerability, vuln_id)
    if vuln is None or vuln.task_id != task_id:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    payload = (vuln.poc_payload or "").strip()
    if not payload:
        raise HTTPException(status_code=400, detail="该漏洞没有 POC payload")
    if not re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+/", payload, re.I):
        for line in (vuln.agent_evidence or "").splitlines():
            m = re.search(r"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/\S*)",
                          line.strip(), re.I)
            if m:
                payload = f"{m.group(1).upper()} {m.group(2)}\n{payload}"
                break
    raw = poc.generate_burp_request(payload)
    return Response(
        content=raw,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="poc_task{task_id}_vuln{vuln_id}.http"'},
    )
