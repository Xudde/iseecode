"""LLM 配置 API（阶段0）+ Agent 引擎设置（运行时动态可调）"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.agent_settings import AGENT_SETTING_DEFAULTS, SETTING_LABELS, agent_settings
from app.db import SessionLocal
from app.models import Config
from app.schemas import ConfigOut, ConfigUpdate
from app.secrets import decrypt, set_secret

router = APIRouter(prefix="/api/config", tags=["config"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def mask_api_key(key: str) -> str:
    """api_key 脱敏：sk-***xxxx"""
    if not key:
        return ""
    if len(key) <= 4:
        return "sk-***" + key
    return "sk-***" + key[-4:]


def _get_value(db: Session, key: str) -> str:
    row = db.get(Config, key)
    return decrypt(row.value) if row else ""


@router.get("", response_model=ConfigOut)
def get_config(db: Session = Depends(get_db)):
    st = agent_settings(db)
    return ConfigOut(
        base_url=_get_value(db, "base_url"),
        api_key=mask_api_key(_get_value(db, "api_key")),
        model=_get_value(db, "model"),
        **{k: str(st[k]) for k in AGENT_SETTING_DEFAULTS},
        night_enabled=_get_value(db, "night_enabled") or "0",
        night_start=_get_value(db, "night_start") or "23:00",
        night_end=_get_value(db, "night_end") or "08:45",
        night_base_url=_get_value(db, "night_base_url"),
        night_api_key=mask_api_key(_get_value(db, "night_api_key")),
        night_model=_get_value(db, "night_model"),
        night_tz=_get_value(db, "night_tz") or "Asia/Shanghai",
        intel_enabled=_get_value(db, "intel_enabled") or "0",
        intel_run_time=_get_value(db, "intel_run_time") or "21:30",
        intel_webhook_url=_get_value(db, "intel_webhook_url"),
        intel_webhook_type=_get_value(db, "intel_webhook_type") or "wecom",
    )


@router.post("")
def update_config(data: ConfigUpdate, db: Session = Depends(get_db)):
    """更新配置；空值不覆盖已有配置；脱敏值不可写回。"""
    values = {"base_url": data.base_url, "api_key": data.api_key, "model": data.model}
    for k, v in values.items():
        if not v:
            continue
        if v.startswith("sk-***"):
            continue  # 脱敏值不可写回数据库
        if k == "api_key":
            set_secret(db, k, v)
            continue
        row = db.get(Config, k)
        if row is None:
            db.add(Config(key=k, value=v))
        else:
            row.value = v
    # 夜间 LLM 窗口（字符串/开关）
    for k in ("night_start", "night_end", "night_base_url", "night_model", "night_tz"):
        v = getattr(data, k, "") or ""
        if not v:
            continue
        row = db.get(Config, k)
        if row is None:
            db.add(Config(key=k, value=v))
        else:
            row.value = v
    if data.night_api_key and not data.night_api_key.startswith("sk-***"):
        set_secret(db, "night_api_key", data.night_api_key)
    if data.night_enabled is not None and data.night_enabled in (0, 1):
        row = db.get(Config, "night_enabled")
        if row is None:
            db.add(Config(key="night_enabled", value=str(data.night_enabled)))
        else:
            row.value = str(data.night_enabled)

    # 情报闭环配置
    for k in ("intel_run_time", "intel_webhook_url", "intel_webhook_type"):
        v = getattr(data, k, "") or ""
        if not v:
            continue
        if k == "intel_webhook_url":
            set_secret(db, k, v)
            continue
        row = db.get(Config, k)
        if row is None:
            db.add(Config(key=k, value=v))
        else:
            row.value = v
    if data.intel_enabled is not None and data.intel_enabled in (0, 1):
        row = db.get(Config, "intel_enabled")
        if row is None:
            db.add(Config(key="intel_enabled", value=str(data.intel_enabled)))
        else:
            row.value = str(data.intel_enabled)

    # Agent 引擎设置：显式传入（非 None）才保存
    for k in AGENT_SETTING_DEFAULTS:
        v = getattr(data, k, None)
        if v is None:
            continue
        if not isinstance(v, int):
            continue
        if k.startswith("engine_"):
            if v not in (0, 1):
                continue
        elif k == "codeql_ram_mb":
            if v < 512:
                continue
        elif k == "codeql_threads":
            if not 1 <= v <= 8:
                continue
        elif k == "codeql_java_buildless":
            if v not in (0, 1):
                continue
        elif k == "codeql_high_value":
            if v not in (0, 1):
                continue
        elif k in ("full_audit_max_files", "codeql_max_files",
                   "codeql_db_timeout", "codeql_analyze_timeout", "codeql_min_free_mb"):
            if v < 0:
                continue
        elif v < 1:
            continue
        row = db.get(Config, k)
        if row is None:
            db.add(Config(key=k, value=str(v)))
        else:
            row.value = str(v)
    db.commit()
    return {"ok": True}
