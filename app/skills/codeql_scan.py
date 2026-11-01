# -*- coding: utf-8 -*-
"""CodeQL 数据流推理引擎（阶段四，可选巨人）：小仓库自动建库+查询，SARIF → findings。

Java/Kotlin/C# 使用 build-mode=none；Python/JS/Ruby 无需构建。
大仓库（目标语言源码数 >AUDIT_CODEQL_MAX_FILES）或工具缺失/资源不足时自动跳过；
0 表示不限制文件数；实际执行前会按可用内存/磁盘做资源闸门，避免拖垮串行队列。
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.parse
from pathlib import Path

from app.audit_labels import vuln_label
from app.config import DATA_DIR

CODEQL_BIN = os.environ.get("AUDIT_CODEQL_BIN", "/opt/giants/codeql/codeql")
CODEQL_ROOT = Path(os.environ.get("AUDIT_CODEQL_ROOT", "/opt/giants/codeql"))
CODEQL_TMP_DIR = Path(os.environ.get("AUDIT_CODEQL_TMP_DIR", str(DATA_DIR / "codeql_tmp")))
MAX_FILES = int(os.environ.get("AUDIT_CODEQL_MAX_FILES", "10000"))
MAX_FINDINGS = int(os.environ.get("AUDIT_CODEQL_MAX_FINDINGS", "200"))
DB_TIMEOUT = int(os.environ.get("AUDIT_CODEQL_DB_TIMEOUT", "1800"))
ANALYZE_TIMEOUT = int(os.environ.get("AUDIT_CODEQL_ANALYZE_TIMEOUT", "1800"))
ANALYZE_RAM_MB = int(os.environ.get("AUDIT_CODEQL_RAM_MB", "4096"))
MIN_FREE_MB = int(os.environ.get("AUDIT_CODEQL_MIN_FREE_MB", "1024"))
MIN_DISK_MB = int(os.environ.get("AUDIT_CODEQL_MIN_DISK_MB", "2048"))
JAVA_BUILDLESS = os.environ.get("AUDIT_CODEQL_JAVA_BUILDLESS", "1") == "1"
JAVA_EXCLUDES = [x.strip() for x in os.environ.get(
    "AUDIT_CODEQL_JAVA_EXCLUDE",
    "**/decompiled_embedded/**,**/target/**,**/build/**").split(",") if x.strip()]
HIGH_VALUE_QUERIES = {
    "CWE-078/ExecTainted.ql", "CWE-078/ExecUnescaped.ql", "CWE-078/ExecTaintedEnvironment.ql",
    "CWE-089/SqlTainted.ql", "CWE-089/SqlConcatenated.ql",
    "CWE-094/TemplateInjection.ql", "CWE-094/GroovyInjection.ql",
    "CWE-094/SpelInjection.ql", "CWE-094/MvelInjection.ql", "CWE-094/JexlInjection.ql",
    "CWE-022/TaintedPath.ql", "CWE-022/ZipSlip.ql", "CWE-023/PartialPathTraversal.ql",
    "CWE-074/JndiInjection.ql", "CWE-074/XsltInjection.ql",
    "CWE-502/UnsafeDeserialization.ql", "CWE-601/UrlRedirect.ql",
    "CWE-611/Xxe.ql", "CWE-918/RequestForgery.ql",
    "CWE-643/XPathInjection.ql", "CWE-090/LdapInjection.ql", "CWE-117/LogInjection.ql",
}
SKIP_DIRS = {"node_modules", "vendor", "third_party", "thirdparty", "bower_components",
             ".git", ".svn", ".hg", "__pycache__", ".venv", "venv", "dist", "build",
             "target", "obj", "coverage", ".next", ".nuxt", "decompiled_embedded"}
LANG_MAP = {
    "java": ("java", True), "kotlin": ("java", True),
    "python": ("python", True),
    "javascript": ("javascript", True), "typescript": ("javascript", True),
    "csharp": ("csharp", True), "ruby": ("ruby", True),
    "go": ("go", False),
}
TECH_EXTS = {
    "java": (".java",), "kotlin": (".kt", ".kts"),
    "python": (".py",),
    "javascript": (".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte"),
    "typescript": (".ts", ".tsx"),
    "csharp": (".cs",), "ruby": (".rb",), "go": (".go",),
}


def _lang_exts(lang: str) -> set[str]:
    exts: set[str] = set()
    for tech, (mapped, _) in LANG_MAP.items():
        if mapped == lang:
            exts.update(TECH_EXTS.get(tech, ()))
    return exts


def _count_lang_files(root: Path, lang: str) -> int:
    """只统计 CodeQL 目标语言的源码文件，避免文档/图片/前端资源把熔断阈值撑爆。"""
    exts = _lang_exts(lang)
    if not exts:
        return 0
    n = 0
    for _, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
        for name in filenames:
            if os.path.splitext(name)[1].lower() in exts:
                n += 1
    return n


def _pick_source_root(root: Path, lang: str) -> Path:
    """源码包常把真实项目放在一层子目录里（decompiled_embedded/_sourcemap 是旁路产物）。
    选包含绝大多数目标语言源码的子目录作为 CodeQL source-root，减少 Maven/类路径扫描范围。"""
    exts = _lang_exts(lang)
    try:
        own = sum(1 for p in root.iterdir()
                  if p.is_file() and p.suffix.lower() in exts)
    except OSError:
        return root
    candidates = []
    try:
        for p in root.iterdir():
            if p.is_dir() and p.name.lower() not in SKIP_DIRS:
                candidates.append((p, _count_lang_files(p, lang)))
    except OSError:
        return root
    if not candidates:
        return root
    best, best_n = max(candidates, key=lambda x: x[1])
    total = own + sum(n for _, n in candidates)
    if best_n > 0 and total > 0 and best_n >= total * 0.8 and best_n > own:
        return best
    return root


def _available_mb() -> int | None:
    try:
        with open("/proc/meminfo", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def _disk_free_mb(path: str) -> int | None:
    try:
        return shutil.disk_usage(path).free // (1024 * 1024)
    except OSError:
        return None


def _pick_lang(root: Path, techs: list[str]) -> tuple[str | None, bool]:
    """按源码文件数选主语言，避免 examples 里的 TS/JS 抢走 Go/Java 项目的 CodeQL。"""
    supported = [t for t in techs if t in LANG_MAP]
    if not supported:
        return None, False
    counts = {t: 0 for t in supported}
    for _, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            for tech in supported:
                if ext in TECH_EXTS.get(tech, ()):
                    counts[tech] += 1
                    break
    backend = [t for t in supported if t in ("java", "kotlin", "python",
                                             "csharp", "ruby", "go")]
    frontend = [t for t in supported if t in ("javascript", "typescript")]
    # 全栈项目优先深挖后端；否则 Memos/Paperless 会被前端文件数带偏
    front_count = sum(counts.get(t, 0) for t in frontend)
    back_count = max((counts.get(t, 0) for t in backend), default=0)
    # 少量 Python/Go 辅助脚本不应把 Node 项目的 CodeQL 带偏
    use_backend = bool(backend and frontend and back_count >= 20
                       and back_count >= 0.2 * max(front_count, 1))
    pool = backend if use_backend else supported
    tech = max(pool, key=lambda t: counts.get(t, 0))
    if counts.get(tech, 0) == 0:
        tech = pool[0]
    return LANG_MAP[tech]


def _run(cmd: list[str], timeout: int, cwd: str | None = None) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd,
                           timeout=(None if timeout <= 0 else timeout))
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except (OSError, FileNotFoundError) as e:
        return 127, "", str(e)


def _count_files(root: Path) -> int:
    n = 0
    for _, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
        n += len(filenames)
    return n


def _find_suite(lang: str) -> Path | None:
    hits = sorted((CODEQL_ROOT / "qlpacks" / "codeql" / f"{lang}-queries").glob(
        "*/codeql-suites/*security-extended.qls"))
    return hits[-1] if hits else None


def _high_value_queries() -> list[str]:
    if not (CODEQL_ROOT / "qlpacks" / "codeql" / "java-queries").exists():
        return []
    hits = sorted((CODEQL_ROOT / "qlpacks" / "codeql" / "java-queries").rglob("*.ql"))
    out = []
    for p in hits:
        rel = f"{p.parent.name}/{p.name}"
        if rel in HIGH_VALUE_QUERIES:
            out.append(str(p))
    return out


def _rel_uri(uri: str, root: Path) -> str:
    u = urllib.parse.unquote(str(uri or ""))
    u = re.sub(r"^file://(?:/)?", "/", u).replace("\\", "/")
    try:
        p = Path(u)
        if p.is_absolute():
            return str(p.resolve().relative_to(root.resolve())).replace("\\", "/")
    except Exception:
        pass
    return u.lstrip("/")


def scan(workspace: str, log_fn=None, ram_mb: int | None = None,
         threads: int | None = None, max_files: int | None = None,
         db_timeout: int | None = None, analyze_timeout: int | None = None,
         min_free_mb: int | None = None, java_buildless: int | bool | None = None,
         high_value: int | bool | None = None) -> list[dict]:
    log = log_fn or (lambda m: None)
    if os.environ.get("AUDIT_CODEQL", "1") != "1" or not Path(CODEQL_BIN).exists():
        return []
    root = Path(workspace)
    if not root.is_dir():
        return []
    from app.skills.tech_detect import run_tech_detect_multi
    lang, build_none = _pick_lang(root, run_tech_detect_multi(workspace))
    if not lang:
        log("CodeQL：栈不在支持范围，跳过")
        return []

    cap = MAX_FILES if max_files is None else int(max_files)
    dbt = DB_TIMEOUT if db_timeout is None else int(db_timeout)
    ant = ANALYZE_TIMEOUT if analyze_timeout is None else int(analyze_timeout)
    min_free = MIN_FREE_MB if min_free_mb is None else int(min_free_mb)
    buildless = JAVA_BUILDLESS if java_buildless is None else bool(int(java_buildless))
    use_high = bool(int(high_value)) if high_value is not None else False

    n_total = _count_files(root)
    src_root = _pick_source_root(root, lang)
    n_src = _count_lang_files(src_root, lang)
    prefix = ""
    try:
        if src_root != root:
            prefix = src_root.relative_to(root).as_posix()
    except ValueError:
        prefix = ""
    cap_text = "不限制" if cap <= 0 else str(cap)
    if n_src == 0:
        log(f"CodeQL 跳过：未发现 {lang} 源文件（总文件 {n_total}）")
        return []
    if cap > 0 and n_src > cap:
        log(f"CodeQL 跳过：{lang} 源文件 {n_src} > 上限 {cap}（总文件 {n_total}；只计目标语言源码）")
        return []
    log(f"CodeQL 文件计数：{lang} 源文件 {n_src} / 总文件 {n_total} / 上限 {cap_text}"
        + (f"；源码根 {prefix}" if prefix else ""))

    suite = _find_suite(lang)
    if suite is None:
        log(f"CodeQL 跳过：缺少 {lang} 查询套件")
        return []

    avail = _available_mb()
    try:
        CODEQL_TMP_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        log(f"CodeQL 跳过：临时目录不可用 {CODEQL_TMP_DIR}: {e}")
        return []
    free_disk = _disk_free_mb(str(CODEQL_TMP_DIR))
    if min_free > 0 and avail is not None and avail < min_free:
        log(f"CodeQL 跳过：可用内存 {avail}MB < 安全线 {min_free}MB")
        return []
    if MIN_DISK_MB > 0 and free_disk is not None and free_disk < MIN_DISK_MB:
        log(f"CodeQL 跳过：临时目录 {CODEQL_TMP_DIR} 剩余 {free_disk}MB < {MIN_DISK_MB}MB")
        return []

    ram = int(ram_mb or ANALYZE_RAM_MB)
    if avail is not None and min_free > 0:
        ram_cap = max(1024, avail - min_free)
        if ram > ram_cap:
            log(f"CodeQL 内存下调：{ram}MB → {ram_cap}MB（可用 {avail}MB，安全线 {min_free}MB）")
            ram = ram_cap
    if ram < 1024:
        log(f"CodeQL 跳过：可用内存不足（{avail}MB）")
        return []

    use_buildless = (lang == "java" and buildless)
    mode_text = "buildless（跳过 Gradle/Maven autobuild）" if use_buildless else "标准建库"
    log(f"CodeQL 建库（{lang}，{n_src} 个源文件 / 总 {n_total}，上限 {cap_text}，{mode_text}）…")
    db = tempfile.mkdtemp(prefix="codeql_db_", dir=str(CODEQL_TMP_DIR))
    if use_buildless:
        try:
            os.rmdir(db)
        except OSError:
            pass
    sarif = Path(db) / "results.sarif"
    th = max(1, min(int(threads or 2), 8))
    try:
        if use_buildless:
            init_cmd = [CODEQL_BIN, "database", "init", db, "--language", "java",
                        "--source-root", str(src_root)]
            rc, _, err = _run(init_cmd, dbt)
            if rc != 0:
                log(f"CodeQL buildless init 失败（跳过）: {err[-160:]}")
                return []
            idx_cmd = [CODEQL_BIN, "database", "index-files", db, "--language", "java",
                       "--include-extension=.java",
                       "-j", str(th), "-M", str(ram), "-O", "java.buildless=true"]
            for pattern in JAVA_EXCLUDES:
                idx_cmd.append(f"--exclude={pattern}")
            rc, _, err = _run(idx_cmd, dbt, cwd=str(src_root))
            if rc != 0:
                log(f"CodeQL buildless index 失败（跳过）: {err[-160:]}")
                return []
            rc, _, err = _run([CODEQL_BIN, "database", "finalize", db], dbt)
            if rc != 0:
                log(f"CodeQL buildless finalize 失败（跳过）: {err[-160:]}")
                return []
        else:
            cmd = [CODEQL_BIN, "database", "create", db, "--language", lang,
                   "--source-root", str(src_root), "--overwrite",
                   f"--threads={th}", f"--ram={ram}"]
            if build_none:
                cmd += ["--build-mode", "none"]
            rc, _, err = _run(cmd, dbt)
            if rc != 0:
                log(f"CodeQL 建库失败（跳过）: {err[-160:]}")
                return []
        hq = _high_value_queries() if lang == "java" else []
        if use_high and hq:
            log(f"CodeQL 执行高价值 CWE 子集（{len(hq)} 条，省内存）…")
            targets = hq
            analyze_ram = max(2048, min(ram, 3072))
        else:
            log("CodeQL 执行 security-extended 查询…")
            targets = [str(suite)]
            analyze_ram = ram
        rc, _, err = _run([CODEQL_BIN, "database", "analyze", db] + targets +
                          ["--format=sarif-latest", "--output", str(sarif),
                           "--rerun", f"--threads={th}", f"--ram={analyze_ram}"],
                          ant)
        if (rc != 0 or not sarif.exists()) and not use_high and hq:
            log("CodeQL 全量查询失败/内存不足，回退高价值 CWE 子集…")
            try:
                sarif.unlink(missing_ok=True)
            except OSError:
                pass
            analyze_ram = max(2048, min(ram, 3072))
            rc, _, err = _run([CODEQL_BIN, "database", "analyze", db] + hq +
                              ["--format=sarif-latest", "--output", str(sarif),
                               "--rerun", f"--threads={th}", f"--ram={analyze_ram}"],
                              ant)
        if rc != 0 or not sarif.exists():
            log(f"CodeQL 查询失败（跳过）: {err[-160:]}")
            return []
        data = json.loads(sarif.read_text(encoding="utf-8", errors="ignore"))
    except Exception as e:
        log(f"CodeQL 异常（跳过）: {e}")
        return []
    finally:
        shutil.rmtree(db, ignore_errors=True)
    return _map_sarif(data, root, lang, n_src, log, prefix)


def _line_snippet(root: Path, rel: str, line: int) -> str:
    try:
        p = root / rel
        if not p.is_file() or p.stat().st_size > 2 * 1024 * 1024:
            return ""
        lines = p.read_text(errors="ignore").splitlines()
        if 1 <= line <= len(lines):
            return lines[line - 1].strip()[:120]
    except OSError:
        pass
    return ""


def _flow_summary(result: dict, root: Path, cache: dict | None = None,
                  prefix: str = "") -> str:
    """提取 SARIF codeFlows 的 source→sink 路径：去重连续重复点，每步带代码。"""
    cache = cache if cache is not None else {}
    for flow in (result.get("codeFlows") or []):
        for thread in (flow.get("threadFlows") or []):
            points = []
            last = None
            for item in (thread.get("locations") or []):
                loc = item.get("location") or {}
                phy = loc.get("physicalLocation") or {}
                fp = _rel_uri(phy.get("artifactLocation", {}).get("uri", ""), root)
                if prefix and fp and not fp.startswith(prefix + "/"):
                    fp = f"{prefix}/{fp}"
                line = int(phy.get("region", {}).get("startLine", 0) or 0)
                if not fp:
                    continue
                key = (fp, line)
                if key == last:
                    continue
                last = key
                if key not in cache:
                    cache[key] = _line_snippet(root, fp, line)
                code = cache[key]
                points.append("%s:%s%s" % (fp, line, (" `" + code + "`") if code else ""))
            if points:
                return " → ".join(points[:12])[:1600]
    return ""


def _map_sarif(data: dict, root: Path, lang: str, nfiles: int, log,
               prefix: str = "") -> list[dict]:
    run = (data.get("runs") or [{}])[0]
    rules = {str(r.get("id")): r for r in
             (run.get("tool", {}).get("driver", {}).get("rules") or [])}
    out, seen = [], set()
    line_cache = {}
    for res in (run.get("results") or []):
        rid = str(res.get("ruleId") or "")
        locs = res.get("locations") or []
        loc = (locs[0].get("physicalLocation") if locs else {}) or {}
        fp = _rel_uri(loc.get("artifactLocation", {}).get("uri", ""), root)
        if prefix and fp and not fp.startswith(prefix + "/"):
            fp = f"{prefix}/{fp}"
        line = int(loc.get("region", {}).get("startLine", 0) or 0)
        if not rid or not fp or (fp, line, rid) in seen:
            continue
        seen.add((fp, line, rid))
        meta = rules.get(rid) or {}
        props = meta.get("properties") or {}
        level = str(res.get("level") or
                    meta.get("defaultConfiguration", {}).get("level") or "warning").lower()
        try:
            sec = float(props.get("security-severity") or 0)
        except (TypeError, ValueError):
            sec = 0.0
        severity = ("ERROR" if level == "error" or sec >= 7
                    else "WARNING" if level == "warning" or sec >= 4 else "INFO")
        short = (meta.get("shortDescription") or {}).get("text") or rid
        label = vuln_label(rid)
        msg = str((res.get("message") or {}).get("text") or "")
        snippet = loc.get("contextRegion", {}).get("snippet", {}).get("text") or msg
        flow_text = _flow_summary(res, root, line_cache, prefix)
        if flow_text:
            snippet = (str(snippet) + "\nCodeQL flow: " + flow_text)[:1600]
        out.append({
            "source": "codeql",
            "rule_id": f"codeql:{rid}"[:128],
            "title": (label if label != "疑似漏洞" else short)[:120],
            "severity": severity,
            "file_path": fp[:512],
            "line": line,
            "code_snippet": str(snippet)[:1600],
            "message": msg[:300] or short,
            "agent_evidence": ("CodeQL 数据流: " + flow_text)[:1800] if flow_text else None,
        })
    out.sort(key=lambda x: {"ERROR": 0, "WARNING": 1, "INFO": 2}.get(x["severity"], 3))
    out = out[:MAX_FINDINGS]
    log(f"CodeQL 完成：{len(out)} 条（{lang}，{nfiles} 个源文件）")
    return out
