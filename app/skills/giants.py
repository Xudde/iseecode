"""巨人组合扫描（2026-10-25 集成）：把业界开源引擎接进平台流水线
- semgrep 授权/配置规则包（本地 YAML：giants_rules/authz-config.yaml）
- gitleaks 密钥熵扫描（docker: zricethezav/gitleaks）
- trivy 配置基线/密钥（docker: aquasec/trivy）
- 前端 JS 情报（mantra 服务商密钥 + 内置端点/sourcemap 提取）
全部离线、零 token；docker/工具缺失时逐项优雅跳过，不阻断任务。
结果以平台统一漏洞 dict 返回，自动进入既有落库/去重/命名/报告体系。
"""
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import urllib.parse
from collections import Counter
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from app.skills import codeql_scan
from app.skills.engines import (CUSTOM_RULES_DIR, EngineContext, EngineSpec,
                                all_specs, custom_rule_files, register)

GITLEAKS_IMAGE = "zricethezav/gitleaks:latest"
TRIVY_IMAGE = "aquasec/trivy:latest"
TRIVY_DB_REPOSITORY = os.environ.get("AUDIT_TRIVY_DB_REPOSITORY",
                                     "public.ecr.aws/aquasecurity/trivy-db")
TRIVY_CACHE_DIR = os.environ.get("AUDIT_TRIVY_CACHE", "/opt/giants/trivy-cache")
TRIVY_VULN_MAX = int(os.environ.get("AUDIT_TRIVY_VULN_MAX", "200"))
MANTRA_BIN = "/opt/giants/bin/mantra"
MANTRA_TIMEOUT = int(os.environ.get("AUDIT_MANTRA_TIMEOUT", "600"))
RULES_PACK = Path(__file__).resolve().parent / "giants_rules" / "authz-config.yaml"

TITLE_CN = {
    "shiro-anon-whitelist": "Shiro 匿名放行",
    "shiro-anon-high-risk": "Shiro 匿名放行（高危组件）",
    "commented-permission-annotation": "权限注解被注释（功能鉴权缺失）",
    "hardcoded-signing-secret": "配置文件硬编码密钥",
    "jimureport-vulnerable-version": "积木报表危险版本依赖",
    "default-nacos-secret": "Nacos 默认鉴权密钥",
    "gitleaks:jwt": "JWT 令牌泄露",
    "gitleaks:generic-api-key": "疑似硬编码 API 密钥",
    "gitleaks:private-key": "私钥泄露",
}
SEV_MAP = {"CRITICAL": "ERROR", "HIGH": "ERROR", "MEDIUM": "WARNING",
           "LOW": "INFO", "UNKNOWN": "INFO"}
# vendor 永久排除：第三方库里的"密钥"几乎都是库自身标识符；
# examples/samples/demo/docs 里的依赖清单是演示环境，CVE 噪声不应淹没主工程。
VENDOR_MARKERS = ("node_modules", "/vendor/", "thirdparty", "third_party",
                  "bower_components", "/examples/", "/example/", "/samples/",
                  "/demo/", "/docs/", "/test/", "/tests/")
# test/docs 目录：generic 熵命中多为示例值（噪声），但私钥/云厂商令牌提交进
# 仓库就是真实泄露（哪怕在测试夹具里）——这类高信号规则保留可见。
LOW_SIGNAL_PATHS = ("/test/", "/tests/", "/src/test/", "/spec/", "/docs/")
HIGH_SIGNAL_RULES = {"private-key", "aws-access-token", "github-pat", "github-oauth",
                     "github-app-token", "github-refresh-token", "gitlab-pat",
                     "slack-bot-token", "slack-webhook-url", "stripe-access-token",
                     "openai-api-key"}
PROVIDER_SIGS = (("AIzaSy", "Google"), ("AKIA", "AWS"), ("sk_test_", "Stripe"),
                 ("sk_live_", "Stripe"), ("xoxb-", "Slack"), ("ghp_", "GitHub"),
                 ("sk-", "OpenAI"))


def _log(fn, m):
    (fn or (lambda x: None))(m)


def _src_line(path, line):
    """semgrep 新版登录墙会把 extra.lines 打码成 requires login——按位置自读源码绕过"""
    try:
        lines = Path(path).read_text(errors="ignore").splitlines()
        return lines[line - 1] if 0 < line <= len(lines) else ""
    except Exception:
        return ""


def _run(cmd, timeout=300):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError as e:
        return 127, "", str(e)


def _ensure_image(image, log_fn) -> bool:
    rc, _, _ = _run(["docker", "image", "inspect", image], timeout=30)
    if rc == 0:
        return True
    _log(log_fn, f"拉取镜像 {image} …（首次较慢）")
    rc, _, err = _run(["docker", "pull", image], timeout=900)
    if rc != 0:
        _log(log_fn, f"镜像拉取失败: {err[-120:]}")
    return rc == 0


def _scan_semgrep_pack(workspace, log_fn) -> list[dict]:
    """内置授权/配置规则包 + data/rules 自定义 YAML（校验失败逐项跳过）"""
    semgrep = shutil.which("semgrep") or str(
        Path(__file__).resolve().parents[2] / ".venv" / "bin" / "semgrep")
    configs = []
    if RULES_PACK.exists():
        configs.append(str(RULES_PACK))
    else:
        _log(log_fn, f"内置规则包缺失: {RULES_PACK}")
    valid_custom = []
    for p in custom_rule_files():
        rc, out, err = _run([semgrep, "scan", "--validate", "--config", str(p)], timeout=60)
        if rc == 0:
            valid_custom.append(str(p))
        else:
            _log(log_fn, f"自定义规则包校验失败，跳过 {p.name}: {(err or out).strip()[-160:]}")
    if valid_custom:
        _log(log_fn, f"自定义规则包: {len(valid_custom)} 个（{CUSTOM_RULES_DIR}）")
        configs += valid_custom
    if not configs:
        return []
    cmd = [semgrep, "scan"]
    for c in configs:
        cmd += ["--config", c]
    cmd += ["--json", "--quiet", workspace]
    rc, out, err = _run(cmd, timeout=300)
    try:
        data = json.loads(out)
    except Exception:
        _log(log_fn, f"semgrep 规则包输出解析失败: {err[:100]}")
        return []
    vulns = []
    for r in data.get("results", []):
        fp = r.get("path", "")
        try:
            fp = str(Path(fp).resolve().relative_to(Path(workspace).resolve()))
        except Exception:
            pass
        line = r.get("start", {}).get("line", 0)
        rid = r.get("check_id", "").split(".")[-1]
        vulns.append({
            "source": "giants",
            "rule_id": f"giants:{rid}",
            "title": TITLE_CN.get(rid, rid),
            "severity": (r.get("extra", {}).get("severity") or "WARNING").upper(),
            "file_path": fp, "line": line,
            "code_snippet": _src_line(r.get("path", ""), line)[:500],
            "message": (r.get("extra", {}).get("message") or "")[:200],
        })
    return vulns


def _gitleaks_skip(fp: str, rid: str) -> bool:
    p = "/" + fp.lower().replace("\\", "/").lstrip("/")
    if any(m in p for m in VENDOR_MARKERS):
        return True
    return any(m in p for m in LOW_SIGNAL_PATHS) and rid not in HIGH_SIGNAL_RULES


def _scan_gitleaks(workspace, log_fn) -> list[dict]:
    if not _ensure_image(GITLEAKS_IMAGE, log_fn):
        return []
    with tempfile.TemporaryDirectory(prefix="giants_gl_") as td:
        out = Path(td) / "gitleaks.json"
        cmd = ["docker", "run", "--rm", "-v", f"{workspace}:/repo:ro", "-v", f"{td}:/out",
               GITLEAKS_IMAGE, "detect", "--source", "/repo", "--no-git",
               "--report-format", "json", "--report-path", "/out/gitleaks.json",
               "--exit-code", "0"]
        rc, _, err = _run(cmd, timeout=300)
        try:
            findings = json.loads(out.read_text())
        except Exception:
            _log(log_fn, f"gitleaks 输出解析失败: {err[-100:]}")
            return []
    vulns = []
    for f in findings:
        fp = str(f.get("File", "")).replace("/repo/", "").replace("/repo", "")
        rid = str(f.get("RuleID", "generic-api-key"))
        if _gitleaks_skip(fp, rid):
            continue  # vendor 噪声；test/docs 只保留私钥/令牌类高信号命中
        key = "gitleaks:" + rid
        vulns.append({
            "source": "giants",
            "rule_id": f"giants:{key}",
            "title": TITLE_CN.get(key, "疑似密钥泄露"),
            "severity": "ERROR" if rid in ("private-key", "aws-access-token") else "WARNING",
            "file_path": fp,
            "line": int(f.get("StartLine", 0) or 0),
            "code_snippet": f"[密钥熵匹配] {str(f.get('Description', ''))[:150]}",
            "message": f"gitleaks 规则 {rid}",
        })
    return vulns


def _scan_trivy(workspace, log_fn) -> list[dict]:
    if not _ensure_image(TRIVY_IMAGE, log_fn):
        return []
    with tempfile.TemporaryDirectory(prefix="giants_tv_") as td:
        out = Path(td) / "trivy.json"
        cmd = ["docker", "run", "--rm", "-v", f"{workspace}:/src:ro", "-v", f"{td}:/out",
               TRIVY_IMAGE, "fs", "--offline-scan", "--scanners", "secret,misconfig",
               "--format", "json", "--output", "/out/trivy.json", "/src"]
        rc, _, err = _run(cmd, timeout=600)
        try:
            data = json.loads(out.read_text())
        except Exception:
            _log(log_fn, f"trivy 输出解析失败: {err[-100:]}")
            return []
    vulns = []
    for r in data.get("Results", []):
        target = str(r.get("Target", ""))
        if any(mk in target.lower() for mk in ("node_modules", "/vendor/", "test/", "docs/")):
            continue
        for m in (r.get("Misconfigurations") or []):
            vulns.append({
                "source": "giants",
                "rule_id": f"giants:trivy:{m.get('ID', '?')}",
                "title": (str(m.get("Title", ""))[:100] or "配置基线问题"),
                "severity": SEV_MAP.get((m.get("Severity") or "UNKNOWN").upper(), "WARNING"),
                "file_path": target,
                "line": int(m.get("StartLineNumber", 0) or 0),
                "code_snippet": str(m.get("Description", ""))[:300],
                "message": str(m.get("Message", ""))[:200],
            })
        for s in (r.get("Secrets") or []):
            vulns.append({
                "source": "giants",
                "rule_id": f"giants:trivy-secret:{s.get('RuleID', '?')}",
                "title": "疑似密钥泄露（trivy）",
                "severity": SEV_MAP.get((s.get("Severity") or "UNKNOWN").upper(), "WARNING"),
                "file_path": target,
                "line": int(s.get("StartLine", 0) or 0),
                "code_snippet": str(s.get("Match", ""))[:200],
                "message": str(s.get("Category", "")),
            })
    return vulns


def _scan_trivy_vuln(workspace, log_fn) -> list[dict]:
    """trivy 依赖 CVE 扫描（SCA）：需要 CVE DB；首次下载后缓存在 TRIVY_CACHE_DIR。
    离线/DB 不可用时跳过，不影响其他引擎。"""
    if os.environ.get("AUDIT_TRIVY_VULN", "1") != "1":
        _log(log_fn, "trivy 依赖 CVE 扫描已关闭（AUDIT_TRIVY_VULN=0）")
        return []
    if not _ensure_image(TRIVY_IMAGE, log_fn):
        return []
    try:
        Path(TRIVY_CACHE_DIR).mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    with tempfile.TemporaryDirectory(prefix="giants_tv_cve_") as td:
        out = Path(td) / "trivy-vuln.json"
        cmd = ["docker", "run", "--rm", "-v", f"{workspace}:/src:ro",
               "-v", f"{td}:/out", "-v", f"{TRIVY_CACHE_DIR}:/root/.cache/trivy",
               "-e", f"TRIVY_DB_REPOSITORY={TRIVY_DB_REPOSITORY}",
               TRIVY_IMAGE, "fs", "--scanners", "vuln", "--quiet",
               "--format", "json", "--output", "/out/trivy-vuln.json", "/src"]
        rc, _, err = _run(cmd, timeout=600)
        try:
            data = json.loads(out.read_text())
        except Exception:
            _log(log_fn, f"trivy CVE 扫描不可用（跳过）: {err[-160:]}")
            return []
    vulns = []
    seen = set()
    for r in data.get("Results", []):
        target = str(r.get("Target", "")).replace("/src/", "").replace("/src", "")
        tlow = "/" + target.lower().strip("/") + "/"
        if any(m in tlow for m in VENDOR_MARKERS):
            continue
        for v in (r.get("Vulnerabilities") or []):
            vid = str(v.get("VulnerabilityID") or "")
            if not vid:
                continue
            key = (target, vid)
            if key in seen:
                continue
            seen.add(key)
            pkg = str(v.get("PkgName") or "")
            installed = str(v.get("InstalledVersion") or "")
            fixed = str(v.get("FixedVersion") or "")
            sev = SEV_MAP.get(str(v.get("Severity") or "").upper(), "WARNING")
            title = f"{pkg}: {vid}"[:120] if pkg else vid[:120]
            desc = str(v.get("Title") or v.get("Description") or "")[:300]
            vulns.append({
                "source": "giants",
                "rule_id": f"giants:trivy-cve:{vid}"[:128],
                "title": title,
                "severity": sev,
                "file_path": target,
                "line": 0,
                "code_snippet": (f"{pkg} {installed} → 修复 {fixed or '暂无'}"
                                 + (f"；{desc}" if desc else ""))[:500],
                "message": str(v.get("PrimaryURL") or "trivy 依赖 CVE 命中")[:300],
            })
    vulns.sort(key=lambda x: {"ERROR": 0, "WARNING": 1, "INFO": 2}.get(x["severity"], 3))
    if len(vulns) > TRIVY_VULN_MAX:
        _log(log_fn, f"trivy CVE 命中 {len(vulns)} 条，按严重性截取前 {TRIVY_VULN_MAX} 条")
        vulns = vulns[:TRIVY_VULN_MAX]
    _log(log_fn, f"trivy 依赖 CVE: {len(vulns)} 条（DB: {TRIVY_DB_REPOSITORY}）")
    return vulns


# ============================================================
# 第四引擎：前端 JS 情报
# ============================================================
JS_EXTS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte", ".html", ".htm"}
# 接口提取不再限定 /api /admin 等白名单前缀：多数站点用 /w/ /prod-api/ /rest/ 等自有前缀，
# 老白名单在非 jeecg 类项目上几乎零命中。
_JS_ENDPOINT_RE = re.compile(
    r'''["'`](?P<ep>/(?!/)[a-zA-Z0-9_\-./{}$:]{2,120}(?:\?[a-zA-Z0-9_\-=&.%]{0,80})?)["'`]''')
_JS_ENDPOINT_REL_RE = re.compile(
    r'''["'`](?P<ep>(?:api|prod-api|rest|service|graphql|v[12])/[a-zA-Z0-9_\-./{}$:]{1,100})["'`]''')
_JS_STATIC_EXT_RE = re.compile(
    r'\.(?:js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|webp|mp4|mp3|pdf|html?|json|xml|txt)$',
    re.I)
_JS_MIME_RE = re.compile(r'^(?:text|application|image|font|audio|video|multipart)/', re.I)
_JS_SMAP_RE = re.compile(r'sourceMappingURL=(\S+?\.map)')


def _iter_js_endpoints(text: str):
    """从 JS/HTML 文本抽接口路径：过滤静态资源、MIME、base64 串，query 只用于去重"""
    for m in _JS_ENDPOINT_RE.finditer(text):
        ep = m.group("ep").split("?", 1)[0].rstrip("/")
        if len(ep) < 3 or _JS_STATIC_EXT_RE.search(ep) or _JS_MIME_RE.search(ep):
            continue
        if re.fullmatch(r"/[A-Za-z0-9+/]{32,}={0,2}", ep):
            continue
        yield ep
    for m in _JS_ENDPOINT_REL_RE.finditer(text):
        ep = "/" + m.group("ep").split("?", 1)[0].rstrip("/")
        if _JS_STATIC_EXT_RE.search(ep):
            continue
        yield ep


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _collect_js_files(workspace: str, cap=3000) -> list[Path]:
    ws = Path(workspace)
    out = []
    if not ws.is_dir():
        return out
    for p in ws.rglob("*"):
        if p.is_file() and p.suffix.lower() in JS_EXTS:
            out.append(p)
            if len(out) >= cap:
                break
    return out


def _scan_mantra(workspace, js_files, log_fn) -> list[dict]:
    """mantra 只吃 URL（自带 http 抓取）：起本地 http.server 供弹，stdin 喂 URL 清单"""
    if not Path(MANTRA_BIN).exists():
        _log(log_fn, "mantra 未安装（/opt/giants/bin/mantra），跳过服务商密钥扫描")
        return []
    port = _free_port()

    class _QuietHandler(SimpleHTTPRequestHandler):
        def log_message(self, *a, **kw):  # 静音访问日志，避免污染任务日志
            pass

    server = ThreadingHTTPServer(
        ("127.0.0.1", port),
        lambda *a, **kw: _QuietHandler(*a, directory=str(workspace), **kw))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        urls = "\n".join(
            f"http://127.0.0.1:{port}/"
            + urllib.parse.quote(str(p.relative_to(workspace)).replace("\\", "/"))
            for p in js_files)
        proc = subprocess.Popen([MANTRA_BIN, "-s"], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, _ = proc.communicate(input=urls + "\n", timeout=MANTRA_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        _log(log_fn, "mantra 扫描超时（部分结果可能截断）")
        out = proc.stdout.read() if proc.stdout else ""
    except Exception as e:
        _log(log_fn, f"mantra 执行失败（跳过）: {e}")
        return []
    finally:
        server.shutdown()

    vulns = []
    ansi = re.compile(r"\x1b\[[0-9;]*m")
    for raw in (out or "").splitlines():
        line = ansi.sub("", raw).strip()
        m = re.match(r"\[\+\]\s+(\S+)\s+\[(.+)\]", line)
        if not m:
            continue
        url, match = m.group(1), m.group(2)
        # 源码模式 FP 过滤：值为裸标识符（config/process/undefined/req…）说明
        # 该行只是"从配置读取密钥"的代码，不是泄露的密钥字面量
        val = re.split(r":\s*|=\s*", match, 1)[-1].strip().strip("\"'")
        if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]{0,15}", val) or val in (
                "undefined", "config", "process", "module", "null"):
            continue
        rel = urllib.parse.unquote(url.split("/", 3)[-1] if url.count("/") > 2 else url)
        provider = next((name for sig, name in PROVIDER_SIGS if sig in match), "未知服务商")
        vulns.append({
            "source": "giants",
            "rule_id": "giants:js-intel:mantra",
            "title": f"前端 JS 疑似 {provider} 密钥泄露（mantra）",
            "severity": "ERROR",
            "file_path": rel, "line": 0,
            "code_snippet": f"[mantra] {match[:150]}",
            "message": "mantra 服务商密钥签名命中，建议确认并从 JS 中移除",
        })
    return vulns


def _scan_js_static(workspace, js_files, log_fn) -> list[dict]:
    """端点清单 + sourcemap 泄露（内置单遍扫描，兼容压缩 JS）"""
    ws = Path(workspace)
    endpoints = Counter()
    smaps = []
    for p in js_files[:2000]:
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for ep in _iter_js_endpoints(text):
            endpoints[ep] += 1
        for m in _JS_SMAP_RE.finditer(text):
            smaps.append((str(p.relative_to(ws)).replace("\\", "/"), m.group(1)))
        if len(endpoints) > 3000:
            break

    vulns = []
    if endpoints:
        top = "\n".join(f"{n:3d}  {ep}" for ep, n in endpoints.most_common(30))
        vulns.append({
            "source": "giants",
            "rule_id": "giants:js-intel:endpoints",
            "title": f"前端 JS 接口清单（{len(endpoints)} 条，供人工 fuzz）",
            "severity": "INFO",
            "file_path": "(前端 JS 全局)", "line": 0,
            "code_snippet": top[:1800],
            "message": "从前端 JS 提取的接口路径，建议做未授权访问测试与 fuzz",
        })
    for rel, sm in smaps[:10]:
        vulns.append({
            "source": "giants",
            "rule_id": "giants:js-intel:sourcemap",
            "title": "SourceMap 泄露（可还原完整前端源码）",
            "severity": "HIGH",
            "file_path": rel, "line": 0,
            "code_snippet": f"sourceMappingURL={sm}",
            "message": "生产环境暴露 .map 文件，可直接还原原始前端代码",
        })
    return vulns


def _recover_sourcemaps(workspace: str, log_fn) -> list[str]:
    """解析 .map 的 sourcesContent，把原始 TS/Vue/JSX 源码还原成真实文件。
    产物写入 workspace/_sourcemap_recovered/（后续引擎可直接审计真实源码）。
    返回还原文件的相对路径列表。"""
    ws = Path(workspace)
    out_root = (ws / "_sourcemap_recovered").resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    recovered = []
    total_bytes = 0
    maps = [p for p in ws.rglob("*.map") if p.is_file()][:200]
    for mp in maps:
        try:
            data = json.loads(mp.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        sources = data.get("sources") or []
        contents = data.get("sourcesContent") or []
        if not contents:
            continue
        stem = re.sub(r"[^A-Za-z0-9._\-]", "_", mp.name.replace(".map", "")) or "map"
        base = out_root / stem
        for i, src in enumerate(sources):
            if i >= len(contents) or not contents[i]:
                continue
            if len(recovered) >= 500 or total_bytes > 50 * 1024 * 1024:
                break
            # 安全路径：sources 常见 webpack://、../、盘符——全部中和在还原目录内
            rel = str(src).replace("\\", "/")
            rel = re.sub(r"^[A-Za-z]:/", "", rel)
            rel = re.sub(r"^(webpack|ng|blob)://[^/]*/?", "", rel)
            parts = [seg for seg in rel.split("/") if seg not in ("..", ".", "")]
            if not parts:
                continue
            fname = parts[-1]
            if "." not in fname:
                fname += ".txt"
            try:
                dest_dir = base.joinpath(*parts[:-1])
                dest_dir.resolve().relative_to(out_root.resolve())  # 防逃逸
                dest_dir.mkdir(parents=True, exist_ok=True)
                content = contents[i]
                total_bytes += len(content)
                (dest_dir / fname).write_text(content, encoding="utf-8")
                recovered.append(str((dest_dir / fname).relative_to(ws)).replace("\\", "/"))
            except Exception:
                continue
    if recovered:
        _log(log_fn, f"SourceMap 还原出 {len(recovered)} 个原始源码文件（{total_bytes // 1024}KB）"
                     f"→ {out_root.name}/（后续引擎将直接审计真实源码）")
    return recovered


def _scan_js_intel(workspace: str, log_fn) -> list[dict]:
    """第四引擎总入口：sourcemap 源码还原 + mantra 服务商密钥 + 端点清单"""
    js_files = _collect_js_files(workspace)
    if not js_files:
        return []
    _log(log_fn, f"前端 JS 文件 {len(js_files)} 个")
    vulns = []

    # 0) sourcemap 原码还原（先执行：还原出的真实源码会被后续引擎直接审计）
    try:
        recovered = _recover_sourcemaps(workspace, log_fn)
        if recovered:
            exts = Counter(Path(f).suffix.lower() for f in recovered)
            kinds = "、".join(f"{k}×{n}" for k, n in exts.most_common(5))
            vulns.append({
                "source": "giants",
                "rule_id": "giants:js-intel:sourcemap-recovered",
                "title": f"SourceMap 还原出 {len(recovered)} 个原始源码文件（{kinds}）",
                "severity": "HIGH",
                "file_path": "_sourcemap_recovered/", "line": 0,
                "code_snippet": "\n".join(recovered[:20]),
                "message": "生产环境泄露 sourcemap，已自动还原原始 TS/Vue/JSX 源码并纳入审计",
            })
    except Exception as e:
        _log(log_fn, f"sourcemap 还原异常（跳过）: {e}")

    try:
        hits = _scan_mantra(workspace, js_files, log_fn)
        _log(log_fn, f"mantra 服务商密钥: {len(hits)} 条")
        vulns += hits
    except Exception as e:
        _log(log_fn, f"mantra 异常（跳过）: {e}")
    try:
        static_v = _scan_js_static(workspace, js_files, log_fn)
        _log(log_fn, f"端点/SourceMap 情报: {len(static_v)} 条")
        vulns += static_v
    except Exception as e:
        _log(log_fn, f"JS 静态情报异常（跳过）: {e}")
    return vulns


def _engine_jsintel(ctx: EngineContext) -> list[dict]:
    return _scan_js_intel(ctx.workspace, ctx.log_fn)


def _engine_codeql(ctx: EngineContext) -> list[dict]:
    return codeql_scan.scan(ctx.workspace, ctx.log_fn,
                            ram_mb=ctx.settings.get("codeql_ram_mb"),
                            threads=ctx.settings.get("codeql_threads"),
                            max_files=ctx.settings.get("codeql_max_files"),
                            db_timeout=ctx.settings.get("codeql_db_timeout"),
                            analyze_timeout=ctx.settings.get("codeql_analyze_timeout"),
                            min_free_mb=ctx.settings.get("codeql_min_free_mb"),
                            java_buildless=ctx.settings.get("codeql_java_buildless"),
                            high_value=ctx.settings.get("codeql_high_value"))


def _engine_semgrep(ctx: EngineContext) -> list[dict]:
    return _scan_semgrep_pack(ctx.workspace, ctx.log_fn)


def _engine_gitleaks(ctx: EngineContext) -> list[dict]:
    return _scan_gitleaks(ctx.workspace, ctx.log_fn)


def _engine_trivy(ctx: EngineContext) -> list[dict]:
    return _scan_trivy(ctx.workspace, ctx.log_fn)


def _engine_trivy_cve(ctx: EngineContext) -> list[dict]:
    return _scan_trivy_vuln(ctx.workspace, ctx.log_fn)


def _engine_self_cve(ctx: EngineContext) -> list[dict]:
    from app.skills import self_cve
    return self_cve.scan(ctx.workspace, task_name=ctx.task_name, log_fn=ctx.log_fn)


ENGINE_SPECS = [
    EngineSpec("jsintel", "前端 JS 情报", _engine_jsintel, order=10,
               setting_key="engine_jsintel", description="mantra 密钥 + 端点/sourcemap"),
    EngineSpec("codeql", "CodeQL 数据流", _engine_codeql, order=20,
               setting_key="engine_codeql", description="security-extended 数据流"),
    EngineSpec("semgrep", "授权/配置规则包", _engine_semgrep, order=30,
               description="内置 authz-config + framework + data/rules 自定义规则"),
    EngineSpec("gitleaks", "gitleaks 密钥", _engine_gitleaks, order=40,
               setting_key="engine_gitleaks", requires_docker=True,
               description="密钥熵扫描（Docker）"),
    EngineSpec("trivy", "trivy 配置基线/密钥", _engine_trivy, order=50,
               setting_key="engine_trivy", requires_docker=True,
               description="配置/密钥（Docker）"),
    EngineSpec("trivy_cve", "trivy 依赖 CVE", _engine_trivy_cve, order=60,
               setting_key="engine_trivy_cve", requires_docker=True,
               description="依赖漏洞（Docker）"),
    EngineSpec("self_cve", "项目自身版本 CVE（OSV）", _engine_self_cve, order=70,
               setting_key="engine_self_cve", description="OSV 包级查询"),
]
for _spec in ENGINE_SPECS:
    register(_spec)


def run_giants(workspace: str, log_fn=None, task_name: str = "",
               settings: dict | None = None) -> list[dict]:
    """巨人组合总入口：按注册表顺序执行 EngineSpec，返回统一漏洞 dict 列表。
    JS 情报/授权规则包/CodeQL 不依赖 Docker；Docker 缺失只跳过 gitleaks/trivy。
    settings 来自平台设置页（引擎开关/CodeQL 内存线程），None 表示全开默认值。
    """
    log_fn = log_fn or (lambda m: None)
    if os.environ.get("AUDIT_GIANTS", "1") != "1":
        _log(log_fn, "AUDIT_GIANTS=0，巨人组合扫描关闭")
        return []
    settings = settings or {}

    def enabled(key, default=1):
        try:
            return int(settings.get(key, default)) == 1
        except (TypeError, ValueError):
            return bool(default)

    docker_ok = shutil.which("docker") is not None
    if not docker_ok:
        _log(log_fn, "docker 不可用：跳过 gitleaks/trivy，JS 情报/规则包/CodeQL 继续")
    ctx = EngineContext(workspace, log_fn, settings, task_name)
    all_v = []
    for spec in all_specs():
        if spec.setting_key and not enabled(spec.setting_key):
            continue
        if spec.requires_docker and not docker_ok:
            continue
        try:
            got = spec.run(ctx)
            _log(log_fn, f"{spec.name}: {len(got)} 条")
            all_v += got
        except Exception as e:
            _log(log_fn, f"{spec.name} 执行失败（跳过）: {e}")
    seen, out = set(), []
    for v in all_v:
        key = (v["file_path"], v["line"], v["rule_id"])
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
    return out
