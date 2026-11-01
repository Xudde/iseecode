# -*- coding: utf-8 -*-
"""框架级鉴权语义 v1（阶段 1）：
- Express/Nest：任意 router 变量、app.use/router.use 中间件链、secureEnabled 条件放行
- Django/DRF：MIDDLEWARE、urlpatterns/include、login_required/permission_classes
- Spring：SecurityFilterChain matcher、@PreAuthorize/@Secured
输出标签：anonymous / authenticated / role:<x> / conditional / unknown + 中间件证据。
只做静态语义，不把“没看到注解”直接当未授权。
"""
import json
import os
import re
from pathlib import Path
from app.skills.route_paths import normalize_path as normalize_route

SKIP_DIRS = {"node_modules", "vendor", "third_party", "thirdparty", "bower_components",
             ".git", ".svn", ".hg", "__pycache__", ".venv", "venv", "dist", "build",
             "target", "obj", "coverage", ".next", ".nuxt", "test", "tests",
             "test-cli", "testing", "e2e", "cypress", "spec", "specs",
             "__tests__", "docs", "examples", "example", "samples"}
CODE_EXTS = {".py", ".java", ".kt", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs"}
MAX_FILES = int(os.environ.get("AUDIT_AUTHZ_MAX_FILES", "6000"))  # 0=不限制
MAX_FILE_SIZE = 2 * 1024 * 1024

PUBLIC_HINTS = ("login", "logout", "register", "signup", "health", "ready", "metrics",
                "swagger", "openapi", "docs", "static", "favicon", "public",
                ".well-known", "captcha", "oauth/callback")
AUTH_WORDS = re.compile(r"(auth|login|jwt|session|token|permission|role|admin|secure|guard|passport|require|verify)", re.I)
ADMIN_WORDS = re.compile(r"(admin|role|permission|superuser|manage)", re.I)

JS_ROUTE = re.compile(
    r"(?P<var>[A-Za-z_$][\w$]*)\s*\.\s*(?P<kind>get|post|put|delete|patch|all)\s*\(\s*"
    r"['\"`](?P<path>[^'\"`]+)['\"`]\s*(?P<rest>,?[^;]*)", re.I)
JS_USE = re.compile(
    r"(?P<var>[A-Za-z_$][\w$]*)\s*\.\s*use\s*\(\s*"
    r"(?:(?P<q>['\"`])(?P<path>[^'\"`]+)(?P=q)\s*,\s*)?(?P<args>[^)]*)\)")
JS_ROUTER = re.compile(
    r"(?:const|let|var)\s+(?P<var>[A-Za-z_$][\w$]*)\s*=\s*"
    r"(?:express\s*\.\s*Router\(\)|Router\(\)|require\(['\"]express['\"]\)\s*\.\s*Router\(\))")
JS_MW_DEF = re.compile(
    r"(?:function\s+(?P<name>[A-Za-z_$][\w$]*)\s*\(|(?:const|let|var)\s+(?P<name2>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)")

PY_ROUTE = re.compile(
    r"(?:path|re_path)\s*\(\s*r?['\"](?P<path>[^'\"]+)['\"]\s*,\s*(?P<view>[A-Za-z_][\w.]*)")
PY_INCLUDE = re.compile(
    r"include\s*\(\s*['\"](?P<mod>[A-Za-z_][\w.]*)['\"]")
PY_DEF = re.compile(r"^\s*(?:async\s+)?def\s+(?P<name>[A-Za-z_]\w*)\s*\(")
PY_CLASS = re.compile(r"^\s*class\s+(?P<name>[A-Za-z_]\w*)\s*(?:\((?P<bases>[^)]*)\))?\s*:")
JAVA_METHOD = re.compile(
    r"@(?P<kind>Get|Post|Put|Delete|Patch|Request)Mapping\b(?P<rest>[^)]*\)?)")
JAVA_CLASS_MAP = re.compile(r"@RequestMapping\b(?P<rest>[^)]*\)?)")
JAVA_CLASS = re.compile(r"\bclass\s+(?P<name>[A-Za-z_]\w*)")
JAVA_PATH = re.compile(r'["\'](?P<p>[^"\']+)["\']')


def _iter_files(root: Path):
    n = 0
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part.lower() in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() not in CODE_EXTS:
            continue
        try:
            if p.stat().st_size > MAX_FILE_SIZE:
                continue
        except OSError:
            continue
        n += 1
        if MAX_FILES > 0 and n > MAX_FILES:
            break
        yield p


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _split_args(s: str) -> list[str]:
    """按顶层逗号切分参数，忽略括号/引号内的逗号。"""
    out, buf, depth, quote = [], [], 0, ""
    for ch in s or "":
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            buf.append(ch)
        elif ch in "([{":
            depth += 1
            buf.append(ch)
        elif ch in ")]}":
            depth = max(0, depth - 1)
            buf.append(ch)
        elif ch == "," and depth == 0:
            item = "".join(buf).strip()
            if item:
                out.append(item)
            buf = []
        else:
            buf.append(ch)
    item = "".join(buf).strip()
    if item:
        out.append(item)
    return out


def _arg_name(arg: str) -> str:
    """从 middleware 参数提取名称：secureFnc / auth('x') / passport.authenticate(...)"""
    a = (arg or "").strip()
    m = re.match(r"(?:await\s+)?([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)", a)
    return m.group(1) if m else ""


VERSION_ROOT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*[-_]v?\d+(?:\.\d+)+$")


def _strip_version_root(path: str) -> str:
    parts = [x for x in (path or "").split("/") if x]
    if len(parts) > 1 and VERSION_ROOT.match(parts[0]):
        return "/" + "/".join(parts[1:])
    return path or "/"


def _normalize_path(*parts: str) -> str:
    segs = []
    for p in parts:
        for s in str(p or "").split("/"):
            if s:
                segs.append(s)
    return "/" + "/".join(segs)


def _label_for(names: list[str], secure_default_false: bool) -> tuple[str, str, str]:
    """返回 (label, reason, confidence)。"""
    joined = " ".join(names)
    if any(ADMIN_WORDS.search(n or "") for n in names):
        return "role:admin", "检测到 admin/role/permission 类中间件", "medium"
    if secure_default_false and any(re.search(r"(secure|auth)", n or "", re.I) for n in names):
        return "conditional", "鉴权中间件受 secureEnabled 控制，项目默认 secureEnabled=false → 实际匿名可达", "high"
    if any(AUTH_WORDS.search(n or "") for n in names):
        return "authenticated", "检测到登录/会话/JWT/权限中间件", "medium"
    return "anonymous", "路由链中未检测到鉴权中间件", "medium"


def _secure_default_false(texts: dict[Path, str]) -> bool:
    for p, t in texts.items():
        if p.name in ("settings.default.js", "settings.js", "config.js", "config.ts"):
            if re.search(r"^\s*//\s*['\"]?secureEnabled['\"]?\s*:\s*true", t, re.M):
                return True
            if re.search(r"secureEnabled\s*[:=]\s*false", t):
                return True
    return False


# ---------------- Express / Nest ----------------

def _scan_express(root: Path, files: list[Path]) -> list[dict]:
    js = [p for p in files if p.suffix.lower() in (".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs")]
    if not js:
        return []
    texts = {p: _read(p) for p in js}
    secure_false = _secure_default_false(texts)
    routers, mounts, globals_ = set(), {}, []
    for p, t in texts.items():
        for m in JS_ROUTER.finditer(t):
            routers.add(m.group("var"))
        for m in JS_USE.finditer(t):
            var = m.group("var")
            prefix = m.group("path") or ""
            args = _split_args(m.group("args"))
            if var in routers:
                mounts[var] = (prefix, args, p, t[:m.start()].count("\n") + 1)
            else:
                globals_.append((prefix, args, p, t[:m.start()].count("\n") + 1))
    out = []
    for p, t in texts.items():
        for m in JS_ROUTE.finditer(t):
            var = m.group("var")
            path = m.group("path")
            if not path.startswith("/"):
                continue
            # 只接受 express router/app 风格：router 集合、常见 app 变量或同文件有 Router()/express()
            if var not in routers and var not in ("app", "server", "router", "api", "route") \
                    and not re.search(r"\b%s\s*=\s*(?:express|Router|require\(['\"]express)" % re.escape(var), t):
                continue
            args = _split_args(m.group("rest").lstrip(","))
            if not args:
                continue
            mw, handler = args[:-1], args[-1]
            prefix, parent_mw, _, _ = mounts.get(var, ("", [], p, 0))
            global_mw = []
            for gp, ga, _, _ in globals_:
                if not gp or path.startswith(gp):
                    global_mw += ga
            chain = parent_mw + mw + global_mw
            names = [_arg_name(a) for a in chain if _arg_name(a)]
            auth_names = [n for n in names if AUTH_WORDS.search(n) or ADMIN_WORDS.search(n)]
            label, reason, conf = _label_for(auth_names, secure_false)
            shown = auth_names or names[:6]
            if any(h in path.lower() for h in PUBLIC_HINTS) and label == "anonymous":
                conf = "low"
            rel = str(p.relative_to(root)).replace("\\", "/")
            out.append({
                "method": m.group("kind").upper(),
                "path": _normalize_path(prefix, path),
                "labels": label, "middleware_chain": shown,
                "evidence_file": rel, "evidence_line": t[:m.start()].count("\n") + 1,
                "confidence": conf, "framework": "express",
                "note": reason + (f"；handler={handler[:60]}" if handler else ""),
            })
    return out


# ---------------- Django / DRF ----------------

def _django_view_markers(texts: dict[Path, str]) -> dict[str, set[str]]:
    markers = {}
    for p, t in texts.items():
        lines = t.splitlines()
        pending = []
        for i, line in enumerate(lines):
            s = line.strip()
            if s.startswith("@"):
                pending.append(s)
                continue
            m = PY_DEF.match(line)
            c = PY_CLASS.match(line)
            if m or c:
                name = (m or c).group("name")
                marks = set()
                joined = " ".join(pending)
                if re.search(r"login_required|login_optionally_required|LoginRequiredMixin", joined):
                    marks.add("login")
                if re.search(r"permission_required|user_passes_test|staff_member_required|IsAdminUser|IsAuthenticated", joined):
                    marks.add("permission")
                if re.search(r"LoginRequiredMixin", c.group("bases") or "" if c else ""):
                    marks.add("login")
                if marks:
                    markers.setdefault(name, set()).update(marks)
                pending = []
            elif s and not s.startswith("#"):
                pending = []
    return markers


def _django_middleware(texts: dict[Path, str]) -> bool:
    for p, t in texts.items():
        if p.name != "settings.py":
            continue
        m = re.search(r"MIDDLEWARE\s*=\s*\[(.*?)\]", t, re.S)
        if m and re.search(r"LoginRequiredMiddleware|LoginRequired|AuthRequired", m.group(1), re.I):
            return True
    return False


def _scan_django(root: Path, files: list[Path]) -> list[dict]:
    py = [p for p in files if p.suffix == ".py"]
    if not py:
        return []
    texts = {p: _read(p) for p in py}
    markers = _django_view_markers(texts)
    global_login = _django_middleware(texts)
    urls = [p for p in py if p.name == "urls.py" or p.name.endswith("_urls.py")]
    out, visited = [], set()

    def walk(url_file: Path, prefix: str):
        if url_file in visited or not url_file.is_file():
            return
        visited.add(url_file)
        t = texts.get(url_file) or _read(url_file)
        base_dir = url_file.parent
        for m in re.finditer(r"(?:path|re_path)\s*\(\s*r?['\"]([^'\"]+)['\"]\s*,\s*([^)]+)\)", t):
            sub, view = m.group(1), m.group(2).strip()
            line = t[:m.start()].count("\n") + 1
            inc = PY_INCLUDE.search(view)
            if inc:
                mod = inc.group("mod")
                target = root / (mod.replace(".", "/") + ".py")
                walk(target, _normalize_path(prefix, sub))
                continue
            name = re.split(r"[.()]", view)[0].split(".")[-1]
            if ".as_view" in view:
                name = re.match(r"([A-Za-z_]\w*)", view).group(1)
            else:
                name = view.split("(")[0].strip().split(".")[-1]
            marks = markers.get(name, set())
            if re.search(r"permission|admin", " ".join(marks), re.I):
                label, conf = "role:admin", "medium"
            elif "login" in marks:
                label, conf = "authenticated", "medium"
            elif global_login:
                label, conf = "authenticated", "low"
            elif any(h in sub.lower() for h in PUBLIC_HINTS):
                label, conf = "anonymous", "low"
            else:
                label, conf = "anonymous", "low"
            method = "ANY"
            out.append({
                "method": method, "path": _normalize_path(prefix, sub),
                "labels": label, "middleware_chain": sorted(marks) + (["global:LoginRequiredMiddleware"] if global_login else []),
                "evidence_file": str(url_file.relative_to(root)).replace("\\", "/"),
                "evidence_line": line, "confidence": conf, "framework": "django",
                "note": ("视图装饰器：" + ",".join(sorted(marks))) if marks else
                        ("全局 LoginRequiredMiddleware" if global_login else "未发现视图级鉴权标记；需结合中间件确认"),
            })
    for u in urls:
        walk(u, "")
    return out


# ---------------- Spring ----------------

def _match_ant(pattern: str, path: str) -> bool:
    pat = re.escape(pattern).replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
    return re.fullmatch(pat, path) is not None


def _scan_spring(root: Path, files: list[Path]) -> list[dict]:
    java = [p for p in files if p.suffix.lower() in (".java", ".kt")]
    if not java:
        return []
    texts = {p: _read(p) for p in java}
    rules = []  # (pattern, access)
    for p, t in texts.items():
        if "authorizeHttpRequests" not in t and "SecurityFilterChain" not in t:
            continue
        for m in re.finditer(r"requestMatchers\s*\(([^)]*)\)\s*\.\s*(permitAll|authenticated|hasRole|hasAuthority|hasAnyRole|denyAll)\s*\(([^)]*)\)", t):
            pats = JAVA_PATH.findall(m.group(1))
            access = m.group(2) + (("(" + m.group(3) + ")") if m.group(3).strip() else "()")
            for pat in pats:
                rules.append((pat, access))
        m = re.search(r"anyRequest\s*\(\s*\)\s*\.\s*(permitAll|authenticated|hasRole|hasAuthority|denyAll)\s*\(([^)]*)\)", t)
        if m:
            rules.append(("/**", m.group(1) + (("(" + m.group(2) + ")") if m.group(2).strip() else "()")))
    out = []
    for p, t in texts.items():
        if "@RestController" not in t and "@Controller" not in t:
            continue
        lines = t.splitlines()
        class_idx = next((i for i, l in enumerate(lines) if JAVA_CLASS.search(l)), len(lines))
        base = ""
        for i in range(max(0, class_idx - 30), class_idx):
            m = JAVA_CLASS_MAP.search(lines[i])
            if m:
                q = JAVA_PATH.search(lines[i])
                base = q.group("p") if q else ""
        class_pre = ""
        for i in range(max(0, class_idx - 12), class_idx):
            if "@PreAuthorize" in lines[i] or "@Secured" in lines[i] or "@RolesAllowed" in lines[i]:
                class_pre += lines[i]
        for i, line in enumerate(lines):
            if class_idx < len(lines) and i < class_idx:
                continue
            m = JAVA_METHOD.search(line)
            if not m:
                continue
            q = JAVA_PATH.search(line)
            sub = q.group("p") if q else ""
            methods = [m.group("kind").upper()] if m.group("kind") != "Request" else ["ANY"]
            path = _normalize_path(base, sub)
            pre = class_pre + line
            label, conf, note = "unknown", "low", "未匹配到 SecurityFilterChain 规则"
            if re.search(r"hasRole|hasAuthority|RolesAllowed|PreAuthorize.*(ADMIN|ROLE_)", pre, re.I):
                label, conf, note = "role:admin", "medium", "方法/类级角色注解"
            elif re.search(r"PreAuthorize|Secured|authenticated", pre, re.I):
                label, conf, note = "authenticated", "medium", "方法/类级鉴权注解"
            else:
                matched = False
                for pat, access in rules:
                    if _match_ant(pat, path):
                        matched = True
                        if "permitAll" in access:
                            label, conf, note = "anonymous", "medium", f"SecurityFilterChain {pat} permitAll"
                        elif "hasRole" in access or "hasAuthority" in access or "hasAnyRole" in access:
                            label, conf, note = "role:admin", "medium", f"SecurityFilterChain {pat} {access}"
                        else:
                            label, conf, note = "authenticated", "medium", f"SecurityFilterChain {pat} {access}"
                        break
                if not matched and rules:
                    label, conf, note = "unknown", "low", "未命中明确 matcher，沿用框架默认"
            for method in methods:
                out.append({
                    "method": method, "path": path, "labels": label,
                    "middleware_chain": [note],
                    "evidence_file": str(p.relative_to(root)).replace("\\", "/"),
                    "evidence_line": i + 1, "confidence": conf, "framework": "spring",
                    "note": note,
                })
    return out


def _fallback_inventory(root: Path) -> list[dict]:
    """框架语义未覆盖时的兜底：复用未授权清单的启发式结果，低置信度标注。"""
    try:
        from app.skills import authz_inventory
        inv = authz_inventory.scan(str(root))
    except Exception:
        return []
    out = []
    for e in (inv.get("items") or []):
        markers = e.get("auth_markers") or []
        protected = bool(e.get("protected"))
        out.append({
            "method": e.get("method") or "ANY",
            "path": e.get("path") or "/",
            "labels": "authenticated" if protected else "anonymous",
            "middleware_chain": markers,
            "evidence_file": e.get("file") or "",
            "evidence_line": int(e.get("line") or 0),
            "confidence": "low", "framework": "heuristic",
            "note": ("启发式：发现鉴权标记" if protected else
                     "启发式：未发现鉴权标记；需人工/动态确认全局中间件"),
        })
    return out


def scan(workspace: str) -> dict:
    root = Path(workspace)
    files = list(_iter_files(root))
    items = []
    if any(p.suffix.lower() in (".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs") for p in files):
        items += _scan_express(root, files)
    if any(p.suffix == ".py" for p in files):
        items += _scan_django(root, files)
    if any(p.suffix.lower() in (".java", ".kt") for p in files):
        items += _scan_spring(root, files)
    # 兜底：Flask/FastAPI/Go/PHP 等暂未做框架语义的栈，用启发式清单补齐未覆盖路径
    for it in items:
        if it.get("path"):
            it["path"] = _strip_version_root(it["path"])
    covered = {(it["method"], normalize_route(it["path"])) for it in items}
    for it in _fallback_inventory(root):
        key = (it["method"], normalize_route(it["path"]))
        if key not in covered:
            items.append(it)
            covered.add(key)
    seen, uniq = set(), []
    for it in items:
        key = (it["method"], it["path"], it["evidence_file"], it["evidence_line"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(it)
    counts = {}
    for it in uniq:
        counts[it["labels"]] = counts.get(it["labels"], 0) + 1
    return {"summary": {"endpoints": len(uniq), "by_label": counts,
                        "note": "框架级静态语义；conditional=受运行时配置控制，必须动态验证"},
            "items": uniq[:int(os.environ.get("AUDIT_AUTHZ_SEMANTIC_MAX", "2000"))]}


def to_markdown(data: dict, task=None) -> str:
    s = data.get("summary") or {}
    lines = ["# 鉴权语义清单（框架级）", ""]
    if task is not None:
        lines.append(f"- 任务：#{task.id} {task.filename}")
    lines += [f"- 识别接口：{s.get('endpoints', 0)}；标签分布：{json.dumps(s.get('by_label') or {}, ensure_ascii=False)}",
              f"> {s.get('note', '')}", ""]
    items = data.get("items") or []
    for label in ("anonymous", "conditional", "authenticated", "role:admin", "unknown"):
        rows = [x for x in items if x["labels"] == label]
        if not rows:
            continue
        lines += [f"## {label}（{len(rows)}）", "",
                  "| 方法 | 路径 | 框架 | 位置 | 证据 |", "| --- | --- | --- | --- | --- |"]
        for x in rows[:60]:
            lines.append(f"| {x['method']} | `{x['path']}` | {x['framework']} | "
                         f"`{x['evidence_file']}:{x['evidence_line']}` | {x['note'][:120]} |")
        lines.append("")
    return "\n".join(lines) + "\n"


def store(db, task_id: int, data: dict) -> int:
    """把扫描结果写入 authz_endpoints（覆盖式）。"""
    from app.models import AuthzEndpoint
    db.query(AuthzEndpoint).filter(AuthzEndpoint.task_id == task_id).delete()
    n = 0
    for it in (data.get("items") or []):
        db.add(AuthzEndpoint(
            task_id=task_id,
            framework=str(it.get("framework") or "")[:32],
            method=str(it.get("method") or "ANY")[:16],
            path=str(it.get("path") or "")[:512],
            labels=str(it.get("labels") or "unknown")[:32],
            middleware_chain=json.dumps(it.get("middleware_chain") or [], ensure_ascii=False)[:4000],
            evidence_file=str(it.get("evidence_file") or "")[:512],
            evidence_line=int(it.get("evidence_line") or 0),
            confidence=str(it.get("confidence") or "low")[:8],
            note=str(it.get("note") or "")[:512],
        ))
        n += 1
    db.commit()
    return n


def rows_to_data(rows) -> dict:
    items = []
    for r in rows:
        try:
            chain = json.loads(r.middleware_chain or "[]")
        except Exception:
            chain = []
        items.append({
            "method": r.method, "path": r.path, "labels": r.labels,
            "middleware_chain": chain, "evidence_file": r.evidence_file,
            "evidence_line": r.evidence_line, "confidence": r.confidence,
            "framework": r.framework, "note": r.note,
        })
    counts = {}
    for it in items:
        counts[it["labels"]] = counts.get(it["labels"], 0) + 1
    return {"summary": {"endpoints": len(items), "by_label": counts,
                        "note": "框架级静态语义；conditional=受运行时配置控制，必须动态验证"},
            "items": items}
