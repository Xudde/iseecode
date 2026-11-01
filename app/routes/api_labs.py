"""复现环境（lab 容器）与任务沙箱的统一视图 + 起停控制。

安全边界：只允许操作**打了 iseecode.lab 标签或名字以 -lab 结尾**的容器，
不能通过本接口碰平台沙箱、mobsf、egress-proxy 或任意其他容器。
"""
import os
import shutil

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.models import Config, Task
from app.routes.api_config import get_db

router = APIRouter(prefix="/api/labs", tags=["labs"])
LAB_LABEL = "iseecode.lab"
LAB_DIR = os.environ.get("AUDIT_LAB_DIR", "/opt/labs/deploy")
# 与清理任务保持同一套镜像名单，页面据此解释容器为什么会被回收
CLEANUP_IMAGES = ("node:20-slim", "golang:1.22", "php:8-cli", "audit-python-base", "maven:3.9")
CLEANUP_KEEP = ("iseecode-egress-proxy", "mobsf")

# 已复现 lab 登记处：公开仓库默认留空，部署方按自己的复现环境补充。
# 每项字段：name / title / port / dir / evidence；dir 下的 start_lab.sh 用于重新起环境。
LAB_REGISTRY: list[dict] = []


def _docker():
    try:
        import docker
        return docker.from_env(timeout=20), ""
    except Exception as exc:  # noqa: BLE001
        return None, f"{type(exc).__name__}: {exc}"


def _is_lab(name: str, labels: dict) -> bool:
    return bool((labels or {}).get(LAB_LABEL)) or (name or "").endswith("-lab")


def _ports(c) -> list[str]:
    out, seen = [], set()
    for priv, binds in (c.attrs.get("NetworkSettings", {}) or {}).get("Ports", {}).items():
        for b in (binds or []):
            hp = b.get("HostPort")
            if hp and (hp, priv) not in seen:      # IPv4/IPv6 会各报一次，去重
                seen.add((hp, priv))
                out.append(f"{hp}→{priv}")
    return out


def _compose_dir(c) -> str:
    """优先用 compose 自己写的标签，比按容器名猜目录可靠（hc-lab 的目录其实叫 healthchecks）。"""
    cfg = (c.labels or {}).get("com.docker.compose.project.config_files", "")
    if cfg:
        return os.path.dirname(cfg)
    return f"{LAB_DIR}/{c.name.replace('-lab', '')}" if c.name.endswith("-lab") else ""


def _brief(c) -> dict:
    return {
        "name": c.name,
        "image": (c.image.tags or [""])[0] if c.image else "",
        "state": c.status,
        "health": ((c.attrs.get("State", {}) or {}).get("Health", {}) or {}).get("Status", ""),
        "ports": _ports(c),
        "created": c.attrs.get("Created", "")[:19],
        "compose_dir": _compose_dir(c),
        "redeploy": f"bash {_compose_dir(c)}/start_lab.sh" if _compose_dir(c) else "",
        "lab": _is_lab(c.name, c.labels),
    }


def sandbox_enabled(db: Session) -> bool:
    row = db.get(Config, "sandbox_enabled")
    return (row.value if row else "1") != "0"


def _history(by_name: dict) -> list[dict]:
    """登记过的 lab：容器还在就报实际状态，被删了就报 removed + 目录/证据是否仍在。"""
    out = []
    for item in LAB_REGISTRY:
        c = by_name.get(item["name"])
        out.append({
            **item,
            "state": c["state"] if c else "removed",
            "health": c["health"] if c else "",
            "ports": c["ports"] if c else [],
            "dir_exists": os.path.isdir(item["dir"]),
            "start_cmd": f"bash {item['dir']}/start_lab.sh",
        })
    # 登记处之外、但实际活着的 lab 容器也要显示出来
    for name, c in by_name.items():
        if name not in {x["name"] for x in out}:
            out.append({
                "name": name, "title": "（未登记的 lab）", "port": "", "dir": c["compose_dir"],
                "evidence": "", "state": c["state"], "health": c["health"], "ports": c["ports"],
                "dir_exists": bool(c["compose_dir"]) and os.path.isdir(c["compose_dir"]),
                "start_cmd": c["redeploy"],
            })
    return out


@router.get("")
def overview(db: Session = Depends(get_db)):
    cli, err = _docker()
    labs, sandboxes, infra = [], [], []
    live_ids = set()
    if cli:
        try:
            for c in cli.containers.list(all=True):
                b = _brief(c)
                live_ids.add(c.id)
                live_ids.add(c.id[:12])
                if b["lab"]:
                    labs.append(b)
                elif c.name in CLEANUP_KEEP:
                    infra.append(b)
        except Exception as exc:  # noqa: BLE001
            err = f"列出容器失败: {exc}"
        rows = db.query(Task).filter(Task.sandbox_cid.isnot(None), Task.sandbox_cid != "").all()
        for t in rows:
            cid = t.sandbox_cid or ""
            sandboxes.append({
                "task_id": t.id, "filename": t.filename, "status": t.status,
                "audit_mode": t.audit_mode, "cid": cid[:12],
                "port": t.sandbox_port, "alive": bool(cid) and (cid in live_ids or cid[:12] in live_ids),
            })
    free_gb = round(shutil.disk_usage("/").free / 1024 ** 3, 1)
    return {
        "docker_error": err,
        "labs": sorted(labs, key=lambda x: x["name"]),
        "history": _history({x["name"]: x for x in labs}),
        "infra": infra,
        "sandboxes": sandboxes,
        "sandbox_enabled": sandbox_enabled(db),
        "policy": {
            "modes": {
                "full": {"沙箱": "部署", "POC": "验证", "容器": "web 任务完成后保留，可手工重放",
                         "CodeQL": "跑", "LLM/Agent": "跑（消耗 token）"},
                "large": {"沙箱": "部署", "POC": "验证", "容器": "同上（heavy 队列）",
                          "CodeQL": "跑", "LLM/Agent": "跑（全量审计）"},
                "poc": {"沙箱": "部署", "POC": "验证", "容器": "验证后立即销毁（不堆容器）",
                        "CodeQL": "跳过", "LLM/Agent": "跳过（0 token）"},
                "static": {"沙箱": "不部署", "POC": "跳过", "容器": "-",
                           "CodeQL": "跑", "LLM/Agent": "跳过（0 token）"},
            },
            "no_sandbox_project_types": ["apk", "image", "decompile", "driver"],
            "cleanup_cron": {"schedule": "*/10 * * * *", "min_age_min": 20,
                             "images": list(CLEANUP_IMAGES), "keep": list(CLEANUP_KEEP),
                             "lab_exemption": f"容器带标签 {LAB_LABEL}=true 或名字以 -lab 结尾即不回收"},
            "env": {"ANALYSIS_WORKERS": os.getenv("ANALYSIS_WORKERS", "1"),
                    "AUDIT_MIN_FREE_GB": os.getenv("AUDIT_MIN_FREE_GB", "4")},
            "disk_free_gb": free_gb,
        },
    }


@router.post("/sandbox_enabled")
def set_sandbox_enabled(value: int, db: Session = Depends(get_db)):
    """沙箱总开关：关掉后新任务不再部署 Docker 沙箱（也不做 POC 验证），已有容器不受影响。"""
    if value not in (0, 1):
        raise HTTPException(status_code=400, detail="value 只能是 0 或 1")
    row = db.get(Config, "sandbox_enabled")
    if row is None:
        db.add(Config(key="sandbox_enabled", value=str(value)))
    else:
        row.value = str(value)
    db.commit()
    return {"sandbox_enabled": value}


@router.post("/{name}/{action}")
def lab_action(name: str, action: str):
    if action not in ("start", "stop", "restart"):
        raise HTTPException(status_code=400, detail="action 只能是 start/stop/restart")
    cli, err = _docker()
    if cli is None:
        raise HTTPException(status_code=503, detail=f"docker 不可用: {err}")
    try:
        c = cli.containers.get(name)
    except Exception:  # noqa: BLE001
        raise HTTPException(
            status_code=404,
            detail=f"容器不存在: {name}（已删除的 lab 要先在服务器上执行 start_lab.sh 重新起）") from None
    if not _is_lab(c.name, c.labels):
        raise HTTPException(status_code=403,
                            detail=f"{name} 不是复现 lab（需标签 {LAB_LABEL}=true 或名字以 -lab 结尾），拒绝操作")
    try:
        getattr(c, action)()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"{action} 失败: {exc}") from None
    c.reload()
    return {"name": c.name, "state": c.status, "action": action}
