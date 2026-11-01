"""Agent 引擎可调参数：Config 表（key/value）优先，env/默认值兜底。
与 config.py 的静态常量解耦：worker 在阶段 6.5/7.5 启动前动态读取，
支持前端"设置"页调整后即时生效（新任务按新值执行），无需重启服务。
"""
from app.models import Config

# 默认值（与 app/config.py 中 os.environ 兜底值保持一致）
AGENT_SETTING_DEFAULTS = {
    "agent_max_vulns": 20,                # 单任务 Agent 深度研判条数上限
    "agent_max_steps": 15,                # 单条漏洞 Agent 步数硬上限
    "agent_concurrency": 3,               # Agent 分析线程池并发
    "agent_token_budget": 1_500_000,      # 每任务 token 软上限（估算）
    "full_audit_rounds": 3,               # 全量审计轮次
    "full_audit_token_per_round": 400_000,  # 每轮 token 软上限（估算）
    "full_audit_max_findings": 8,         # 每轮提交漏洞条数上限
    "full_audit_max_files": 500,          # 工作区文件数超过该值自动跳过全量审计（熔断）
    "engine_jsintel": 1,                  # 前端 JS 情报
    "engine_codeql": 1,                   # CodeQL 数据流
    "engine_gitleaks": 1,                 # gitleaks 密钥
    "engine_trivy": 1,                    # trivy 配置基线
    "engine_trivy_cve": 1,                # trivy 依赖 CVE
    "engine_self_cve": 1,                 # 项目自身版本 CVE（OSV）
    "engine_authz": 1,                    # 未授权接口清单
    "codeql_ram_mb": 4096,                # CodeQL 分析内存上限
    "codeql_threads": 2,                  # CodeQL 分析线程
    "codeql_max_files": 10000,            # CodeQL 目标语言源码文件上限；0=不限制
    "codeql_db_timeout": 1800,            # CodeQL 建库超时（秒）；0=不限制
    "codeql_analyze_timeout": 1800,       # CodeQL 查询超时（秒）；0=不限制
    "codeql_min_free_mb": 1024,           # CodeQL 启动前保留的系统可用内存（MB）；0=不检查
    "codeql_java_buildless": 1,           # Java 用 buildless 手动建库，跳过 Gradle/Maven autobuild
    "codeql_high_value": 0,               # Java 只用高价值 CWE 子集（省内存）；0=全量 suite
}

SETTING_LABELS = {
    "agent_max_vulns": "深度研判条数上限",
    "agent_max_steps": "单条 Agent 步数上限",
    "agent_concurrency": "研判并发数",
    "agent_token_budget": "每任务 token 预算",
    "full_audit_rounds": "全量审计轮次",
    "full_audit_token_per_round": "每轮 token 预算",
    "full_audit_max_findings": "每轮漏洞条数上限",
    "full_audit_max_files": "全量审计文件数熔断阈值",
    "engine_jsintel": "前端 JS 情报",
    "engine_codeql": "CodeQL 数据流",
    "engine_gitleaks": "gitleaks 密钥",
    "engine_trivy": "trivy 配置基线",
    "engine_trivy_cve": "trivy 依赖 CVE",
    "engine_self_cve": "项目自身版本 CVE（OSV）",
    "engine_authz": "未授权接口清单",
    "codeql_ram_mb": "CodeQL 内存上限（MB）",
    "codeql_threads": "CodeQL 线程数",
    "codeql_max_files": "CodeQL 源码文件上限（0=不限制）",
    "codeql_db_timeout": "CodeQL 建库超时（秒，0=不限制）",
    "codeql_analyze_timeout": "CodeQL 查询超时（秒，0=不限制）",
    "codeql_min_free_mb": "CodeQL 启动保留内存（MB）",
    "codeql_java_buildless": "Java buildless（跳过 Gradle/Maven）",
    "codeql_high_value": "高价值 CWE 子集（省内存）",
}


def agent_settings(db) -> dict:
    """读取 Agent 引擎参数（Config 表优先，默认值兜底），全部返回 int。"""
    rows: dict[str, str] = {}
    if db is not None:
        try:
            rows = {c.key: c.value for c in db.query(Config).all()}
        except Exception:
            rows = {}
    out: dict[str, int] = {}
    for k, default in AGENT_SETTING_DEFAULTS.items():
        raw = rows.get(k)
        if raw is None or str(raw).strip() == "":
            raw = default
        try:
            out[k] = int(raw)
        except (TypeError, ValueError):
            out[k] = default
    return out
