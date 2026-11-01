"""SAST skill：调用 semgrep 用内置规则 + 官方规则集缓存扫描源码（阶段 1 扩展：多语言多栈）"""
import json
import os
import subprocess
from pathlib import Path

from app.config import SAST_TIMEOUT, DATA_DIR
from app.skills import rule_packs

RULES_DIR = Path(__file__).parent / "rules"
RULE_LANG_FILES = {
    "python": "python.yaml",
    "java": "java.yaml",
    "php": "php.yaml",
    "javascript": "javascript.yaml",
    "typescript": "typescript.yaml",
    "go": "go.yaml",
    "csharp": "csharp.yaml",
    "c": "c.yaml",
    "cpp": "cpp.yaml",
    "kotlin": "kotlin.yaml",
    "ruby": "ruby.yaml",
    "rust": "rust.yaml",
    "swift": "swift.yaml",
    "dart": "dart.yaml",
    "scala": "scala.yaml",
    "html": "html.yaml",
}

# 单次任务最多扫描多少个技术栈（防止大项目扫描时间爆炸）
MAX_SCAN_STACKS = 4
# 官方规则集（semgrep registry，semgrep.dev 官方托管；只含模式匹配规则、不执行代码，无危险操作）
# 通用漏洞规则包：所有语言共用
OFFICIAL_GENERIC = ["p/security-audit", "p/owasp-top-ten", "p/command-injection", "p/sql-injection", "p/xss"]
# 语言专属规则包：只对对应主栈附加
OFFICIAL_LANG = {
    "python": ["p/python"],
    "java": ["p/java"],
    "php": ["p/php"],
    "javascript": ["p/javascript"],
    "typescript": ["p/javascript"],
    "go": ["p/golang"],
    "csharp": ["p/csharp"],
}
# 扫描超时：大源码默认 30 分钟，可用 AUDIT_SAST_TIMEOUT 调整
SAST_TIMEOUT_OFFICIAL = SAST_TIMEOUT


def _run_semgrep(configs: list[str], workspace: str, timeout: int = SAST_TIMEOUT) -> list[dict]:
    """执行一次 semgrep，返回原始 results 列表"""
    cmd = ["semgrep", "--json", "--quiet", "--no-git-ignore",
           "--metrics=off", "--disable-nosem", "--max-memory", "2048"]
    for c in configs:
        cmd += ["--config", c]
    cmd += [workspace]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError("semgrep 扫描超时")
    except FileNotFoundError:
        raise RuntimeError("semgrep 未安装，无法执行静态扫描")

    if proc.returncode not in (0, 1, 2):  # semgrep 发现漏洞时返回非 0
        raise RuntimeError(f"semgrep 执行失败: {proc.stderr[:300]}")
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        head = (proc.stdout or "").strip().replace("\n", " ")[:180]
        raise RuntimeError(f"semgrep 输出解析失败: {head!r}")
    return data.get("results", [])


def _official_configs(tech: str) -> list[str]:
    """对主栈返回可用官方规则包（逐个探测，失败静默剔除，结果持久化到 data/official_rules.json）
    安全说明：仅从 semgrep.dev 官方 registry 拉取，规则为纯模式匹配 yaml，不含可执行代码。
    兼容旧 flag 文件（内容为 1 表示 security-audit/owasp-top-ten 已验证可用）。"""
    import logging
    import os
    if os.environ.get("AUDIT_OFFICIAL_RULES", "1") != "1":
        return []
    if tech not in OFFICIAL_LANG and tech not in ("python", "java", "javascript", "typescript", "go", "php", "csharp"):
        return []
    desired = list(dict.fromkeys(OFFICIAL_GENERIC + OFFICIAL_LANG.get(tech, [])))
    flag_file = DATA_DIR / "official_rules.flag"
    json_file = DATA_DIR / "official_rules.json"
    ok = set()
    try:
        if json_file.exists():
            import json as _json
            ok = set(_json.loads(json_file.read_text()).get("ok", []))
        elif flag_file.exists() and flag_file.read_text().strip() == "1":
            ok = set(OFFICIAL_GENERIC)  # 旧验证过的通用包视为可用，无需重探
    except (OSError, ValueError):
        ok = set()
    changed = False
    for pack in desired:
        if pack in ok:
            continue
        try:
            probe_dir = DATA_DIR / "_probe"
            probe_dir.mkdir(parents=True, exist_ok=True)
            _run_semgrep([pack], str(probe_dir), timeout=20)  # 离线时快速失败，避免首启阻塞近 10 分钟
            ok.add(pack)
            logging.getLogger("sast").info(f"官方规则包可用: {pack}")
        except Exception as e:
            logging.getLogger("sast").info(f"官方规则包不可用（已剔除）: {pack} -> {e}")
        changed = True
    if changed:
        try:
            json_file.write_text(json.dumps({"ok": sorted(ok), "probed_at": str(Path(__file__).stat().st_mtime)}))
        except OSError:
            pass
    return [p for p in desired if p in ok]


def _vuln_category(rule_id: str) -> str:
    """从 rule_id 提取漏洞类别，用于合并同位置重复命中（不同规则集可能命中同一行）"""
    rid = rule_id.lower()
    for cat, keys in (
        ("sql", ("sql", "sqli")),
        ("cmd", ("command", "os-system", "shell")),
        ("xss", ("xss",)),
        ("path", ("path", "traversal", "file")),
        ("ssrf", ("ssrf",)),
        ("xxe", ("xxe", "xml")),
        ("ssti", ("ssti", "template")),
        ("deser", ("deserialize", "pickle")),
        ("ldap", ("ldap",)),
        ("crypto", ("crypto", "md5", "sha1", "random")),
        ("auth", ("auth", "password", "jwt", "session", "csrf", "redirect")),
    ):
        if any(k in rid for k in keys):
            return cat
    return "misc"


def run_sast(workspace: str, techs: list[str] | str, log_fn=None) -> list[dict]:
    """执行 semgrep 多栈扫描，返回漏洞列表 [{rule_id, severity, file_path, line, code_snippet}]"""
    if isinstance(techs, str):
        techs = [techs] if techs != "unknown" else []
    techs = techs[:MAX_SCAN_STACKS]
    log = log_fn or (lambda m: None)
    pack_configs, pack_note = rule_packs.selected_configs()
    if rule_packs.mode() != "off":
        log(pack_note)

    all_results: list[dict] = []
    official = _official_configs(techs[0]) if techs else []

    for i, tech in enumerate(techs):
        rule_file = RULES_DIR / RULE_LANG_FILES.get(tech, "")
        local_configs: list[str] = []
        if rule_file.exists():
            local_configs.append(str(rule_file))
        framework_file = RULES_DIR / "framework.yaml"
        if framework_file.exists():
            local_configs.append(str(framework_file))
        configs = list(local_configs)
        if i == 0 and official:
            configs += official
        if i == 0 and pack_configs:
            configs += pack_configs
        if not configs:
            configs = ["auto"]  # 完全无规则时兜底 auto
        timeout = SAST_TIMEOUT_OFFICIAL
        try:
            all_results += _run_semgrep(configs, workspace, timeout=timeout)
        except RuntimeError as e:
            import logging
            logging.getLogger("sast").warning(f"扫描 {tech} 失败: {e}")
            if local_configs:
                log(f"semgrep {tech} 规则包失败（{e}），回退本地规则重扫")
                try:
                    all_results += _run_semgrep(local_configs, workspace, timeout=timeout)
                except RuntimeError as e2:
                    log(f"semgrep {tech} 本地规则也失败: {e2}")
            else:
                log(f"semgrep {tech} 失败: {e}")

    # 第一层去重（规则+文件+行）→ 第二层：同一文件同一行同一类别只保留严重性最高的一条
    _sev_rank = {"ERROR": 0, "HIGH": 0, "WARNING": 1, "MEDIUM": 1, "INFO": 2, "LOW": 2}
    all_results.sort(key=lambda r: _sev_rank.get((r.get("extra", {}).get("severity") or "").upper(), 3))
    return _drop_cross_engine_duplicates(_post_process(all_results, workspace))

def _clean_text(t: str) -> str:
    """清除 semgrep 官方规则包注入的页脚（如 'requires login'），避免污染展示与 Agent 上下文"""
    import re as _re
    if not t:
        return ""
    return _re.sub(r"\s*requires\s+login\b[^\n]*", "", t, flags=_re.IGNORECASE).strip()


def _post_process(all_results, workspace: str):
    vulns, seen = [], set()
    root = Path(workspace).resolve()
    for r in all_results:
        fp = r.get("path", "")
        try:
            fp = str(Path(fp).resolve().relative_to(root))
        except ValueError:
            pass
        line = r.get("start", {}).get("line", 0)
        check_id = r.get("check_id", "")
        key = (check_id, fp, line)
        if key in seen:
            continue
        seen.add(key)
        # 同位置同类别去重：不同规则集命中同一行时只保留严重性最高的
        cat_key = (_vuln_category(check_id), fp, line)
        if cat_key in seen:
            continue
        seen.add(cat_key)
        snippet = _clean_text(r.get("extra", {}).get("lines") or r.get("extra", {}).get("message") or "")[:1000]
        # semgrep 新版登录墙会把 extra.lines 打码成 "requires login"（含本地规则）——
        # 按位置自读源码兜底，保证报告里的代码片段是真实代码
        if not snippet or "requires login" in snippet.lower():
            try:
                src_lines = (Path(workspace) / fp).read_text(errors="ignore").splitlines()
                snippet = "\n".join(src_lines[max(0, line - 2): line + 1])[:1000]
            except Exception:
                pass
        meta = (r.get("extra") or {}).get("metadata") or {}
        cross_engine = str(meta.get("cross_engine") or "").strip()
        msg = _clean_text(r.get("extra", {}).get("message", ""))
        if cross_engine:
            msg = (msg + "；cross_engine=" + cross_engine)[:300]
        vulns.append({
            "rule_id": check_id,
            "cross_engine": cross_engine,
            "severity": (r.get("extra", {}).get("severity") or "").upper(),
            "file_path": fp,
            "line": line,
            "code_snippet": snippet,
            "message": msg,
        })
    return _aggregate_noisy(vulns)


def _drop_cross_engine_duplicates(vulns):
    others = {(v.get("file_path"), v.get("line")) for v in vulns
              if "site-" not in str(v.get("rule_id") or "")}
    out = []
    for v in vulns:
        rid = str(v.get("rule_id") or "")
        ce = str(v.get("cross_engine") or "")
        if "site-" in rid and ce.startswith("duplicate") and (v.get("file_path"), v.get("line")) in others:
            continue
        out.append(v)
    return out


# 高频低信噪规则：按“规则 + 文件”聚合，避免一个 HTML 文件里几百个 inline script
# 或每个 form 一条 CSRF，把报告淹没。保留首条位置与命中次数，明细仍可回源码。
AGGREGATE_RULE_MARKERS = (
    "html-inline-script", "html-form-no-csrf", "html-http-resource",
    "plaintext-http-link", "unrestricted-request-mapping",
)
MAX_SAST_FINDINGS = int(os.environ.get("AUDIT_MAX_SAST_FINDINGS", "8000"))


def _aggregate_noisy(vulns):
    out, groups = [], {}
    for v in vulns:
        rule = str(v.get("rule_id", "")).lower()
        noisy = (v.get("severity") in ("INFO", "LOW")
                 or any(m in rule for m in AGGREGATE_RULE_MARKERS))
        if noisy:
            key = (v.get("rule_id"), v.get("file_path"))
            if key in groups:
                groups[key]["_count"] = groups[key].get("_count", 1) + 1
                continue
            v = dict(v)
            v["_count"] = 1
            groups[key] = v
        out.append(v)
    for v in groups.values():
        count = v.pop("_count", 1)
        if count > 1:
            v["message"] = (v.get("message", "") + "；同文件共 %d 处命中" % count)[:300]
            v["code_snippet"] = (v.get("code_snippet", "") + "\n[聚合] 同文件 %d 处，仅展示首处" % count)[:1200]
    out.sort(key=lambda x: {"ERROR": 0, "HIGH": 0, "WARNING": 1, "MEDIUM": 1,
                            "INFO": 2, "LOW": 2}.get(x.get("severity"), 3))
    if len(out) > MAX_SAST_FINDINGS:
        import logging
        logging.getLogger("sast").warning(
            "semgrep 结果 %d 条，按严重性截取前 %d 条", len(out), MAX_SAST_FINDINGS)
        out = out[:MAX_SAST_FINDINGS]
    return out
