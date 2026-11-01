"""Pydantic 请求响应模型"""
from datetime import datetime

from pydantic import BaseModel


class TaskOut(BaseModel):
    id: int
    filename: str
    status: str
    project_type: str
    tech_stack: str
    fingerprint: str = ""
    audit_mode: str = "full"
    tokens_used: int = 0
    cancel_requested: bool = False
    error_msg: str | None = None
    report_path: str | None = None
    sandbox_cid: str | None = None
    sandbox_port: int | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class TaskDetailOut(TaskOut):
    """详情接口专用：附带执行日志（列表接口保持轻量不返回 log）"""
    log: str = ""


class VulnerabilityOut(BaseModel):
    id: int
    task_id: int
    source: str
    rule_id: str
    title: str | None = None  # AI 生成的中文漏洞名
    precondition: str | None = None  # 复现条件
    severity: str
    file_path: str
    line: int
    code_snippet: str
    llm_is_real: bool | None = None
    llm_reason: str | None = None
    llm_confidence: str | None = None
    poc_verified: bool | None = None
    verify_result: str | None = None
    poc_payload: str | None = None
    agent_status: str | None = None
    agent_evidence: str | None = None
    agent_confidence: str | None = None
    agent_reason: str | None = None
    analyzed_at: datetime | None = None

    model_config = {"from_attributes": True}


class ConfigUpdate(BaseModel):
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    # Agent 引擎可调参数（int | None 表示不修改）
    agent_max_vulns: int | None = None
    agent_max_steps: int | None = None
    agent_concurrency: int | None = None
    agent_token_budget: int | None = None
    full_audit_rounds: int | None = None
    full_audit_token_per_round: int | None = None
    full_audit_max_findings: int | None = None
    full_audit_max_files: int | None = None
    engine_jsintel: int | None = None
    engine_codeql: int | None = None
    engine_gitleaks: int | None = None
    engine_trivy: int | None = None
    engine_trivy_cve: int | None = None
    engine_self_cve: int | None = None
    engine_authz: int | None = None
    codeql_ram_mb: int | None = None
    codeql_threads: int | None = None
    codeql_max_files: int | None = None
    codeql_db_timeout: int | None = None
    codeql_analyze_timeout: int | None = None
    codeql_min_free_mb: int | None = None
    codeql_java_buildless: int | None = None
    codeql_high_value: int | None = None
    night_enabled: int | None = None
    night_start: str = ""
    night_end: str = ""
    night_base_url: str = ""
    night_api_key: str = ""
    night_model: str = ""
    night_tz: str = "Asia/Shanghai"
    intel_enabled: int | None = None
    intel_run_time: str = ""
    intel_webhook_url: str = ""
    intel_webhook_type: str = ""


class ConfigOut(BaseModel):
    base_url: str
    api_key: str  # 脱敏后
    model: str
    intel_enabled: str = "0"
    intel_run_time: str = "21:30"
    intel_webhook_url: str = ""
    intel_webhook_type: str = "wecom"
    # Agent 引擎可调参数（当前生效值，字符串形式便于前端展示）
    agent_max_vulns: str = "20"
    agent_max_steps: str = "15"
    agent_concurrency: str = "3"
    agent_token_budget: str = "1500000"
    full_audit_rounds: str = "3"
    full_audit_token_per_round: str = "400000"
    full_audit_max_findings: str = "8"
    full_audit_max_files: str = "500"
    engine_jsintel: str = "1"
    engine_codeql: str = "1"
    engine_gitleaks: str = "1"
    engine_trivy: str = "1"
    engine_trivy_cve: str = "1"
    engine_self_cve: str = "1"
    engine_authz: str = "1"
    codeql_ram_mb: str = "4096"
    codeql_threads: str = "2"
    codeql_max_files: str = "10000"
    codeql_db_timeout: str = "1800"
    codeql_analyze_timeout: str = "1800"
    codeql_min_free_mb: str = "1024"
    codeql_java_buildless: str = "1"
    codeql_high_value: str = "0"
    night_enabled: str = "0"
    night_start: str = "23:00"
    night_end: str = "08:45"
    night_base_url: str = ""
    night_api_key: str = ""
    night_model: str = ""
    night_tz: str = "Asia/Shanghai"
