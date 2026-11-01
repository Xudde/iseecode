"""页面路由"""
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.audit_labels import vuln_label
from app.config import MAX_UPLOAD_SIZE
from app.models import Task, Vulnerability
from app.routes.api_config import get_db

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent.parent / "templates"))
router = APIRouter(tags=["pages"])

FINAL_STATUSES = ("completed", "failed", "skipped", "cancelled")


@router.get("/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)):
    tasks = db.query(Task).order_by(Task.id.desc()).all()
    # 进行中 / 已完成分开展示
    active_tasks = [t for t in tasks if t.status not in FINAL_STATUSES]
    done_tasks = [t for t in tasks if t.status in FINAL_STATUSES]
    # Starlette 1.9 新签名：TemplateResponse(request, name, context)
    return TEMPLATES.TemplateResponse(
        request, "index.html",
        {"tasks": tasks, "active_tasks": active_tasks, "done_tasks": done_tasks,
         "max_upload_mb": MAX_UPLOAD_SIZE // 1024 // 1024},
    )


@router.get("/tasks/{task_id}", response_class=HTMLResponse)
def task_detail(request: Request, task_id: int, db: Session = Depends(get_db)):
    task = db.get(Task, task_id)
    vulns = db.query(Vulnerability).filter(Vulnerability.task_id == task_id).all() if task else []
    # 漏洞中文名映射：{vuln_id: "SQL 注入"} 等
    labels = {v.id: vuln_label(v.rule_id) for v in vulns}
    return TEMPLATES.TemplateResponse(
        request, "task_detail.html",
        {"task": task, "vulns": vulns, "vuln_labels": labels},
        status_code=404 if task is None else 200,
    )


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    return TEMPLATES.TemplateResponse(request, "dashboard.html", {})


@router.get("/config", response_class=HTMLResponse)
def config_page(request: Request):
    return TEMPLATES.TemplateResponse(request, "config.html", {})


@router.get("/engines", response_class=HTMLResponse)
def engines_page(request: Request):
    return TEMPLATES.TemplateResponse(request, "engines.html", {})


@router.get("/history", response_class=HTMLResponse)
def history_page(request: Request):
    return TEMPLATES.TemplateResponse(request, "history.html", {})


@router.get("/auto", response_class=HTMLResponse)
def auto_page(request: Request):
    return TEMPLATES.TemplateResponse(request, "auto.html", {})


@router.get("/intel", response_class=HTMLResponse)
def intel_page(request: Request):
    return TEMPLATES.TemplateResponse(request, "intel.html", {})


@router.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request):
    return TEMPLATES.TemplateResponse(request, "audit.html", {})


@router.get("/verified", response_class=HTMLResponse)
def verified_page(request: Request):
    return TEMPLATES.TemplateResponse(request, "verified.html", {})


@router.get("/labs", response_class=HTMLResponse)
def labs_page(request: Request):
    return TEMPLATES.TemplateResponse(request, "labs.html", {})
