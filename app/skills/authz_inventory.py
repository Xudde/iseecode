# -*- coding: utf-8 -*-
"""未授权/越权接口静态清单：从源码提取路由、鉴权标记、敏感路径，
生成无凭证 POC 请求。只做候选，不把“没看到鉴权注解”当成已确认漏洞。"""
import json
import os
import re
from pathlib import Path

from app.skills.route_paths import normalize_path

SKIP_DIRS = {"node_modules", "vendor", "third_party", "thirdparty", "bower_components",
             ".git", ".svn", ".hg", "__pycache__", ".venv", "venv", "dist", "build",
             "target", "obj", "coverage", ".next", ".nuxt", "test", "tests",
             "test-cli", "testing", "e2e", "cypress", "spec", "specs",
             "__tests__", "docs", "examples", "example", "samples"}
CODE_EXTS = {".py", ".java", ".kt", ".js", ".ts", ".tsx", ".jsx", ".go", ".php"}
MAX_FILES = int(os.environ.get("AUDIT_AUTHZ_MAX_FILES", "6000"))  # 0=不限制
MAX_ITEMS = int(os.environ.get("AUDIT_AUTHZ_MAX_ITEMS", "2000"))  # 0=不限制
MAX_FILE_SIZE = 2 * 1024 * 1024
STATIC_SUFFIX = (".html", ".htm", ".css", ".js", ".mjs", ".map", ".png",
                 ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
                 ".ttf", ".eot", ".json", ".xml", ".txt", ".webp", ".avif")

AUTH_MARKERS = re.compile(
    r"(login_required|login_optionally_required|jwt_required|fresh_jwt_required|"
    r"permission_required|token_required|api_key_required|roles_allowed|"
    r"roles_required|admin_required|requires_auth|auth_required|current_user|"
    r"verifyUser|verifyToken|verifyAuth|verifySession|getServerSession|"
    r"getToken\s*\(|check\w*Permission|hasPermission|"
    r"\bauth\s*\(|withAuth|withAdmin|requireAdmin|requireUser|checkAuth|"
    r"getCurrentUser|getSession|isAdmin|requireRole|parseRequest|canEnforce|"
    r"requirePermission|checkPermission|validateSession|requireSession|"
    r"Base\w*Admin\w*Controller|Base\w*User\w*Controller|Base\w*Controller|"
    r"AdminController|"
    r"Security\s*\(|Depends\s*\(|requireAuth|require_auth|isAuthenticated|"
    r"passport\.authenticate|PreAuthorize|Secured|RolesAllowed|PermitAll|"
    r"RequiresPermissions|RequiresRoles|Authorize\s*\(|"
    r"session_start|is_logged_in|check_login|require_login|Auth::check|"
    r"admin_required|login_check|authenticated)", re.I)
PUBLIC_HINTS = ("login", "logout", "register", "signup", "health", "ready",
                "metrics", "swagger", "openapi", "docs", "static", "favicon",
                "public", ".well-known", "captcha", "oauth/callback")
SENSITIVE_HINTS = ("admin", "manage", "system", "config", "setting", "user",
                   "account", "order", "pay", "file", "upload", "download",
                   "export", "backup", "list", "search", "query", "debug",
                   "internal", "token", "key", "secret", "log", "code", "exec",
                   "validate", "run", "eval", "import", "proxy", "fetch", "url",
                   "sql", "db", "database", "report", "stat", "monitor")

PY_ROUTE = re.compile(
    r'^\s*@(?P<var>[A-Za-z_]\w*)\.(?P<kind>route|get|post|put|delete|patch)\(\s*'
    r'[\'"](?P<path>[^\'"]+)[\'"](?P<rest>.*)$')
PY_DEF = re.compile(r'^\s*(?:async\s+)?def\s+(?P<name>[A-Za-z_]\w*)\s*\(')
JAVA_METHOD = re.compile(
    r'^\s*@(?P<kind>Get|Post|Put|Delete|Patch|Request)Mapping\b(?P<rest>.*)$')
JAVA_CLASS_MAP = re.compile(r'^\s*@RequestMapping\b(?P<rest>.*)$')
JAVA_CLASS = re.compile(r'\b(class|interface)\s+(?P<name>[A-Za-z_]\w*)')
JS_ROUTE = re.compile(
    r'\b(?P<var>[A-Za-z_]\w*)\.(?P<kind>get|post|put|delete|patch|all)'
    r'\s*\(\s*[\'"`](?P<path>[^\'"`]+)[\'"`](?P<rest>[^\n]*)')
JS_ROUTER = re.compile(
    r'(?:\bexport\s+)?(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*'
    r'(?:new\s+)?(?:express\s*\.\s*)?(?:Router|Fastify|KoaRouter)\s*\(')
NEST_CTRL = re.compile(
    r'@Controller\s*\(\s*(?:'
    r'[\'"](?P<path>[^\'"]*)[\'"]'
    r'|(?:\{[^}]*?path\s*:\s*[\'"](?P<path2>[^\'"]*)[\'"][^}]*\})'
    r')?\s*\)')
NEST_METHOD = re.compile(
    r'@(?P<kind>Get|Post|Put|Delete|Patch|Options|Head|All)'
    r'\s*\(\s*(?:[\'"](?P<path>[^\'"]*)[\'"])?\s*\)')
GO_ROUTE = re.compile(
    r'\b(?P<var>[A-Za-z_]\w*)\.(?P<kind>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Any)'
    r'\(\s*"(?P<path>[^"]+)"\s*(?:,\s*(?P<args>[^)]*))?\)')
GO_GROUP = re.compile(
    r'\b(?P<var>[A-Za-z_]\w*)\s*:?=\s*(?P<parent>[A-Za-z_]\w*)\.Group'
    r'\(\s*"(?P<path>[^"]+)"\s*(?:,\s*(?P<args>[^)]*))?\)')
# Go 组合式：chi/fiber 的 Route/Mount/Handle/HandleFunc 与小写方法（chi Get/Post…）
GO_CALL = re.compile(
    r'\b(?P<var>[A-Za-z_]\w*)\.(?P<kind>'
    r'Get|Post|Put|Delete|Patch|Head|Options|All|'
    r'Handle|HandleFunc|Route|Mount)'
    r'\s*\(\s*(?P<arg>"(?:[^"\\]|\\.)*"|`[^`]*`|(?:[A-Za-z_]\w*|"|\+|\s|[./:{}*-])+)')
GO_CONST = re.compile(
    r'^\s*(?:const\s+)?(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*'
    r'(?P<val>"(?:[^"\\]|\\.)*"|`[^`]*`)\s*$')
GO_ROUTER_NEW = re.compile(
    r'\b(?P<var>[A-Za-z_]\w*)\s*:?=\s*'
    r'(?:chi|gin|echo|fiber|mux|http|httprouter|restful)\.(?:New|NewRouter|Default)\s*\(')
GO_ROUTER_NAMES = {"r", "router", "mux", "rg", "api", "srv", "srvr", "server",
                   "app", "e", "g", "route"}
GO_SKIP_VARS = {"slog", "log", "logger", "zap", "logrus", "fmt", "errors",
                "context", "json", "yaml", "toml", "time", "strings", "bytes",
                "path", "filepath", "os", "http", "url", "viper", "flag", "cobra"}


def _iter_files(root: Path):
    n = 0
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part.lower() in SKIP_DIRS for part in p.parts):
            continue
        lname = p.name.lower()
        is_route_yml = (lname in ("routing.yml", "routing.yaml")
                        or lname.endswith(".routing.yml")
                        or lname.endswith(".routing.yaml"))
        if p.suffix.lower() not in CODE_EXTS and not is_route_yml:
            continue
        if (lname.endswith(("_test.go", "_test.py", ".test.ts", ".test.tsx",
                            ".spec.ts", ".spec.tsx", "test.php", "test.java"))
                or "/test-cli/" in str(p).replace("\\", "/").lower()):
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


def _segment(lines, start: int, size: int = 70) -> str:
    return "\n".join(lines[max(0, start - 8):start + size])


def _markers(text: str) -> list[str]:
    hits = []
    for m in AUTH_MARKERS.finditer(text or ""):
        name = m.group(1)
        if name not in hits:
            hits.append(name)
    return hits


def _path_score(path: str, method: str, markers: list[str]) -> tuple[int, list[str]]:
    low = path.lower()
    reasons, score = [], 0
    if any(h in low for h in PUBLIC_HINTS):
        score -= 6
        reasons.append("公开/登录类路径")
    if any(h in low for h in SENSITIVE_HINTS):
        score += 6
        reasons.append("敏感路径")
    if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
        score += 2
        reasons.append("写操作")
    if not markers:
        score += 4
        reasons.append("未发现鉴权标记")
    return score, reasons


def _make_endpoint(root: Path, p: Path, method: str, path: str, line: int,
                   handler: str, markers: list[str], extra: str = "") -> dict | None:
    # 前端 API 客户端里的 ${BASE_URL}/getURL(...) 不是后端路由
    if (not path or not path.startswith("/") or "${" in path
            or "getURL(" in path or path.startswith("http") or "*" in path):
        return None
    if path.lower().endswith(STATIC_SUFFIX) or "^" in path or "$" in path:
        return None
    method = method.upper()
    markers = list(dict.fromkeys(markers))
    try:
        top = p.relative_to(root).parts[0]
    except Exception:
        top = ""
    path = _strip_version_root(normalize_path(path, (root.name, top)))
    if not path:
        return None
    score, reasons = _path_score(path, method, markers)
    rel = str(p.relative_to(root)).replace("\\", "/")
    sample_path = re.sub(r"\{[^}]+\}|:[A-Za-z_]\w*|<[^>]+>", "1", path)
    if not sample_path.startswith("/"):
        sample_path = "/" + sample_path
    body = "{}" if method in ("POST", "PUT", "PATCH") else ""
    headers = {"Accept": "application/json"}
    if body:
        headers["Content-Type"] = "application/json"
    curl = f"curl -i -X {method} '{{BASE_URL}}{sample_path}'"
    if body:
        curl += " -H 'Content-Type: application/json' -d '{}'"
    return {
        "method": method, "path": path, "file": rel, "line": line,
        "handler": handler, "auth_markers": markers,
        "protected": bool(markers), "expected_role":
            "admin" if any(k in " ".join(markers).lower() for k in ("admin", "role", "permission")) else
            ("user" if markers else "anonymous"),
        "sensitive": score >= 6,
        "score": score, "reasons": reasons + ([extra] if extra else []),
        "poc": {"method": method, "path": sample_path, "headers": headers,
                "body": body, "curl": curl},
        "note": ("发现鉴权标记，仍需测试绕过/低权限越权" if markers else
                 "未发现鉴权标记；可能由全局中间件保护，必须沙箱无凭证验证"),
    }


def _scan_python(root: Path, p: Path, text: str) -> list[dict]:
    lines = text.splitlines()
    prefixes, router_deps = {}, {}
    for line in lines:
        pm = re.search(r"([A-Za-z_]\w*)\s*=\s*(?:APIRouter|Blueprint)\([^)]*"
                       r"(?:prefix|url_prefix)\s*=\s*[\"']([^\"']+)", line)
        if pm:
            prefixes[pm.group(1)] = pm.group(2)
        dm = re.search(r"([A-Za-z_]\w*)\s*=\s*APIRouter\([^)]*dependencies\s*=\s*\[([^\]]*)\]", line)
        if dm:
            router_deps[dm.group(1)] = dm.group(2)
    out = []
    for i, line in enumerate(lines):
        m = PY_ROUTE.match(line)
        if not m:
            continue
        path = prefixes.get(m.group("var"), "") + m.group("path")
        rel = str(p.relative_to(root)).replace("\\", "/")
        if "/api/v1/" in rel and not path.startswith("/api/v1"):
            path = "/api/v1" + path
        elif "/api/v2/" in rel and not path.startswith("/api/v2"):
            path = "/api/v2" + path
        kind = m.group("kind").lower()
        methods = ["GET"]
        if kind != "route":
            methods = [kind.upper()]
        else:
            mm = re.search(r"methods\s*=\s*\[([^\]]+)\]", m.group("rest") or "", re.I)
            if mm:
                methods = [x.strip("'\" ").upper() for x in mm.group(1).split(",") if x.strip()]
        handler = ""
        for j in range(i + 1, min(len(lines), i + 12)):
            dm = PY_DEF.match(lines[j])
            if dm:
                handler = dm.group("name")
                break
        seg = _segment(lines, i, 90)
        file_markers = [x for x in _markers(text[:8000])
                        if x.lower().startswith("base") or x.lower().endswith("controller")]
        markers = (_markers(seg) + _markers(router_deps.get(m.group("var"), ""))
                   + file_markers)
        for method in methods:
            out.append(_make_endpoint(root, p, method, path, i + 1, handler, markers))
    # Flask add_url_rule('/x', view_func, methods=['GET'])
    for i, line in enumerate(lines):
        m = re.search(
            r"([A-Za-z_]\w*)\.add_url_rule\(\s*['\"]([^'\"]+)['\"](?P<rest>.*)",
            line)
        if not m:
            continue
        var = m.group(1)
        path = prefixes.get(var, "") + m.group(2)
        methods = ["GET"]
        mm = re.search(r"methods\s*=\s*\[([^\]]+)\]", m.group("rest") or "", re.I)
        if mm:
            methods = [x.strip("'\" ").upper() for x in mm.group(1).split(",") if x.strip()]
        handler = ""
        for j in range(i + 1, min(len(lines), i + 12)):
            dm = PY_DEF.match(lines[j])
            if dm:
                handler = dm.group("name")
                break
        markers = _markers(_segment(lines, i, 50))
        for method in methods:
            out.append(_make_endpoint(root, p, method, path, i + 1, handler, markers,
                                      "Flask add_url_rule；prefix 已解析"))
    return out


VERSION_ROOT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*[-_]v?\d+(?:\.\d+)+$")


def _strip_version_root(path: str) -> str:
    parts = [x for x in (path or "").split("/") if x]
    if len(parts) > 1 and VERSION_ROOT.match(parts[0]):
        return "/" + "/".join(parts[1:])
    return path or "/"


def _join_url(prefix: str, sub: str) -> str:
    seg = [x.strip("/") for x in (prefix, sub) if x and x.strip("/")]
    return "/" + "/".join(seg) if seg else "/"


DJANGO_PATH = re.compile(r"(?:path|re_path)\s*\(\s*r?['\"]([^'\"]+)['\"]\s*,\s*([^)]+)\)")
DJANGO_INCLUDE = re.compile(r"include\s*\(\s*['\"]([A-Za-z_][\w.]*)['\"]")


def _scan_django(root: Path, py_paths: list[Path]) -> list[dict]:
    texts = {p: _read(p) for p in py_paths}
    urls = [p for p in py_paths if p.name == "urls.py" or p.name.endswith("_urls.py")]
    out, visited = [], set()

    def walk(url_file: Path, prefix: str):
        if url_file in visited or not url_file.is_file():
            return
        visited.add(url_file)
        text = texts.get(url_file) or _read(url_file)
        for m in DJANGO_PATH.finditer(text):
            sub, view = m.group(1), m.group(2).strip()
            inc = DJANGO_INCLUDE.search(view)
            line = text[:m.start()].count("\n") + 1
            if inc:
                mod = inc.group(1)
                target = root / (mod.replace(".", "/") + ".py")
                if not target.is_file():
                    target = root / mod.replace(".", "/") / "urls.py"
                walk(target, _join_url(prefix, sub))
                continue
            if ".as_view" in view:
                handler = re.match(r"([A-Za-z_]\w*)", view)
                handler = handler.group(1) if handler else ""
            else:
                handler = view.split("(")[0].strip().split(".")[-1]
            markers = _markers(text[max(0, m.start() - 300):m.end() + 600])
            endpoint = _make_endpoint(root, url_file, "ANY", _join_url(prefix, sub),
                                      line, handler, markers, "Django URLconf")
            if endpoint:
                out.append(endpoint)

    for u in urls:
        walk(u, "")
    return out


def _scan_java(root: Path, p: Path, text: str) -> list[dict]:
    rel = str(p.relative_to(root)).replace("\\", "/").lower()
    if "/annotation/" in rel or p.name in ("WebServlet.java", "MultipartConfig.java"):
        return []
    lines = text.splitlines()
    base, class_markers = "", []
    class_idx = next((i for i, l in enumerate(lines) if JAVA_CLASS.search(l)), len(lines))
    for i in range(max(0, class_idx - 20), class_idx):
        m = JAVA_CLASS_MAP.search(lines[i])
        if m:
            q = re.search(r'[\'"]([^\'"]+)', m.group("rest") or "")
            base = q.group(1) if q else ""
        class_markers += _markers(lines[i])
    out = []
    # Servlet 3+：@WebServlet("/path")
    for i, line in enumerate(lines):
        sm = re.search(r'@WebServlet\s*\(\s*(?:value\s*=\s*)?\{?\s*"([^"]+)"', line)
        if sm:
            out.append(_make_endpoint(
                root, p, "ANY", sm.group(1), i + 1, "", _markers(_segment(lines, i, 40)),
                "Servlet 映射；容器/Filter 鉴权未解析"))
    for i, line in enumerate(lines):
        if class_idx < len(lines) and i < class_idx:
            continue
        m = JAVA_METHOD.match(line)
        if not m:
            continue
        kind = m.group("kind")
        rest = m.group("rest") or ""
        q = re.search(r'[\'"]([^\'"]+)', rest)
        sub = q.group(1) if q else ""
        methods = [kind.upper()] if kind != "Request" else []
        mm = re.search(r"method\s*=\s*\{?([^}]+)\}?", rest)
        if mm:
            methods = re.findall(r"RequestMethod\.([A-Z]+)", mm.group(1)) or methods
        if not methods:
            methods = ["ANY"]
        path = "/" + "/".join(x.strip("/") for x in (base, sub) if x.strip("/"))
        handler = ""
        for j in range(i + 1, min(len(lines), i + 15)):
            if re.search(r"\b(public|private|protected)\b.*\(", lines[j]) and \
                    not lines[j].strip().startswith("@"):
                handler = re.search(r"\b([A-Za-z_]\w*)\s*\(", lines[j]).group(1) \
                    if re.search(r"\b([A-Za-z_]\w*)\s*\(", lines[j]) else ""
                break
        markers = class_markers + _markers(_segment(lines, i, 45))
        for method in methods:
            out.append(_make_endpoint(root, p, method, path, i + 1, handler, markers,
                                      "Spring 全局 Security 配置未在方法上体现"))
    return out


def _next_file_route(root: Path, p: Path, text: str) -> list[dict]:
    rel = str(p.relative_to(root)).replace("\\", "/")
    low = rel.lower()
    if not (("/pages/api/" in low) or ("/app/api/" in low and p.name.startswith("route."))):
        return []
    if "/pages/api/" in low:
        route = low.split("/pages/api/", 1)[1]
        route = re.sub(r"\.(js|ts|jsx|tsx)$", "", route)
    else:
        route = low.split("/app/api/", 1)[1]
        route = re.sub(r"/route\.(js|ts|jsx|tsx)$", "", route)
    route = "/api/" + route.replace("[", "{").replace("]", "}").strip("/")
    markers = _markers(text[:4000])
    methods = re.findall(r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH)", text)
    if not methods:
        return []
    out = []
    for method in methods:
        line = next((i + 1 for i, l in enumerate(text.splitlines())
                     if re.search(rf"\b{method}\b", l)), 1)
        out.append(_make_endpoint(root, p, method, route, line, p.name, markers,
                                  "Next.js 文件路由"))
    return out


def _scan_js(root: Path, p: Path, text: str) -> list[dict]:
    rel = str(p.relative_to(root)).replace("\\", "/").lower()
    rel_norm = "/" + rel.strip("/") + "/"
    # 前端 API 客户端不是服务端路由；只放过 pages/api、app/api、server 目录
    frontend_client = bool(re.search(r"(?:^|/)[A-Za-z0-9_.-]*frontend(?:/|$)", rel_norm)) or "/client/src/" in rel_norm
    if (frontend_client or any(seg in rel_norm for seg in ("/web/src/", "/resources/assets/")))             and not any(seg in rel_norm for seg in ("/pages/api/", "/app/api/", "/server/src/")):
        return []
    global_auth = bool(re.search(
        r"\.use\s*\([^)]*(auth|session|token|login|permission)[^)]*\)",
        text, re.I))
    mounts = {}
    for mm in re.finditer(
            r"([A-Za-z_]\w*)\.use\(\s*['\"]([^'\"]+)['\"]\s*,\s*([A-Za-z_]\w*)", text):
        mounts[mm.group(3)] = mm.group(2)
    out = _next_file_route(root, p, text)
    if not out and "/pages/api/" in rel:
        # Next.js pages/api 使用 export default handler，方法在函数内判断
        if re.search(r"export\s+default\s+(?:async\s+)?function", text) or                 re.search(r"export\s+default\s+\w+", text):
            path = "/api/" + rel.split("/pages/api/", 1)[1].rsplit(".", 1)[0]
            path = path.replace("[", "{").replace("]", "}")
            line = next((i + 1 for i, l in enumerate(text.splitlines())
                         if "export default" in l), 1)
            out.append(_make_endpoint(root, p, "ANY", path, line, p.name,
                                      _markers(text[:6000]), "Next pages/api 默认 handler"))
    router_vars = {"app", "router", "server", "api", "route", "fastify", "express"}
    router_vars.update(m.group(1) for m in JS_ROUTER.finditer(text))
    router_vars.update(m.group(1) for m in re.finditer(r"\b([A-Za-z_]\w*Router)\b", text))
    lines = text.splitlines()
    for m in JS_ROUTE.finditer(text):
        var = m.group("var")
        if var not in router_vars:
            continue
        path = m.group("path")
        prefix = mounts.get(var, "")
        if prefix:
            path = "/" + "/".join(x.strip("/") for x in (prefix, path) if x.strip("/"))
        method = m.group("kind").upper()
        if method == "ALL":
            method = "ANY"
        line_no = text[:m.start()].count("\n") + 1
        rest = m.group("rest") or ""
        markers = _markers(_segment(lines, line_no - 1, 50)) + _markers(rest)
        if global_auth:
            markers.append("global auth middleware")
        out.append(_make_endpoint(root, p, method, path, line_no, "", markers,
                                  "Express/Koa 路由；全局中间件已尽力识别"))
    return out


def _go_braces(line: str) -> int:
    depth, i, n, quote, esc = 0, 0, len(line), "", False
    while i < n:
        ch = line[i]
        if quote:
            if quote == "`":
                if ch == "`":
                    quote = ""
            elif esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == quote:
                quote = ""
        elif ch in ('"', "'", "`"):
            quote = ch
        elif ch == "/" and i + 1 < n and line[i + 1] == "/":
            break
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        i += 1
    return depth


def _go_join(*parts) -> str:
    seg = [p.strip("/") for p in parts if p and p.strip("/")]
    return "/" + "/".join(seg) if seg else "/"


def _go_string(expr: str, consts: dict) -> str | None:
    """解析 "/x"、`/x`、prefix+"/v1" 这类路由表达式；无法解析返回 None。"""
    parts = [p.strip() for p in (expr or "").strip().split("+")]
    if not parts or not any(parts):
        return None
    out = []
    for part in parts:
        if len(part) >= 2 and part[0] == part[-1] and part[0] in ('"', "`"):
            out.append(part[1:-1])
        elif re.fullmatch(r"[A-Za-z_]\w*", part) and part in consts:
            out.append(consts[part])
        else:
            return None
    return "".join(out)


def _scan_nest(root: Path, p: Path, text: str) -> list[dict]:
    if "@Controller" not in text:
        return []
    lines = text.splitlines()
    ctrl, ctrl_idx = None, 0
    for i, line in enumerate(lines):
        m = NEST_CTRL.search(line)
        if m:
            ctrl = m.group("path") if m.group("path") is not None else (m.group("path2") or "")
            ctrl_idx = i
            break
    if ctrl is None:
        return []
    class_markers = _markers("\n".join(lines[max(0, ctrl_idx - 15):ctrl_idx + 6]))
    out = []
    for i in range(ctrl_idx, len(lines)):
        m = NEST_METHOD.search(lines[i])
        if not m:
            continue
        kind, sub = m.group("kind"), (m.group("path") or "")
        path = _go_join(ctrl, sub)
        handler = ""
        for j in range(i + 1, min(len(lines), i + 8)):
            hm = re.search(r"(?:async\s+)?(?P<name>[A-Za-z_]\w*)\s*\(", lines[j])
            if hm and "constructor" not in lines[j]:
                handler = hm.group("name")
                break
        markers = _markers("\n".join(lines[max(0, i - 2):i + 6])) + class_markers
        out.append(_make_endpoint(
            root, p, "ANY" if kind == "All" else kind.upper(), path, i + 1, handler,
            markers, "NestJS 装饰器；全局 prefix/guard 未解析"))
    return out


def _scan_go(root: Path, p: Path, text: str) -> list[dict]:
    lines = text.splitlines()
    consts = {}
    for line in lines:
        cm = GO_CONST.match(line)
        if cm:
            consts[cm.group("name")] = cm.group("val")[1:-1]
    router_vars = set(GO_ROUTER_NAMES)
    for line in lines:
        rm = GO_ROUTER_NEW.search(line)
        if rm:
            router_vars.add(rm.group("var"))
    groups = {}      # var -> (定义深度, 完整前缀, 中间件参数)
    stack = []       # [(Route 开括号前的深度, 前缀)]
    depth, out = 0, []
    for i, line in enumerate(lines):
        while stack and depth <= stack[-1][0]:
            stack.pop()
        for var in [v for v, g in groups.items() if g[0] > depth]:
            groups.pop(var, None)
        cur = _go_join(*[prefix for _d, prefix in stack])

        gm = GO_GROUP.search(line)
        if gm:
            parent = gm.group("parent")
            base = groups[parent][1] if parent in groups else cur
            groups[gm.group("var")] = (depth, _go_join(base, gm.group("path")),
                                       gm.group("args") or "")
            depth += _go_braces(line)
            continue

        um = GO_ROUTE.search(line)
        if um and um.group("var").lower() not in GO_SKIP_VARS:
            var, path = um.group("var"), um.group("path")
            base = groups[var][1] if var in groups else cur
            markers = _markers((gm.group("args") if gm else "") + " " + _segment(lines, i, 80))
            out.append(_make_endpoint(
                root, p, um.group("kind").upper(), _go_join(base, path), i + 1, "",
                markers, "Gin/Go 路由；全局中间件未解析"))

        cm2 = GO_CALL.search(line)
        if cm2:
            var, kind = cm2.group("var"), cm2.group("kind")
            arg = (cm2.group("arg") or "").strip()
            base = groups[var][1] if var in groups else cur
            gargs = groups[var][2] if var in groups else ""
            raw = _go_string(arg, consts)
            if var.lower() not in GO_SKIP_VARS and raw:
                method = ""
                if kind in ("Handle", "HandleFunc"):
                    method = "ANY"
                    mm = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)$", raw)
                    if mm:
                        method, raw = mm.group(1), mm.group(2)
                elif kind == "Route":
                    if "func" in line and var in router_vars:
                        stack.append((depth, _go_join(base, raw)))
                elif kind == "Mount":
                    pass  # 挂载子应用，被挂载路由在别的文件里，不能凭空生成端点
                elif var in router_vars:
                    method = "ANY" if kind == "All" else kind.upper()
                if method and raw.startswith("/"):
                    markers = _markers(gargs + " " + _segment(lines, i, 80))
                    out.append(_make_endpoint(
                        root, p, method, _go_join(base, raw), i + 1, "", markers,
                        "Go 组合式路由（chi/fiber/net/http）；全局中间件未解析"))
        depth += _go_braces(line)
    return out


def _scan_routing_yml(root: Path, p: Path, text: str) -> list[dict]:
    """Drupal 8/9 routing.yml：path + methods + _permission/_access。"""
    lines = text.splitlines()
    out = []
    for i, line in enumerate(lines):
        m = re.match(r"^\s*path:\s*['\"]?([^'\"\s]+)", line)
        if not m:
            continue
        path = m.group(1)
        if not path.startswith("/"):
            continue
        methods, markers = [], []
        for j in range(i, min(len(lines), i + 16)):
            mm = re.search(r"methods:\s*\[([^\]]+)\]", lines[j])
            if mm:
                methods = [x.strip(" '\"").upper() for x in mm.group(1).split(",")
                           if x.strip(" '\"")]
            if re.search(r"\b(_permission|_access|_role|_user_is_logged_in)\s*:", lines[j]):
                markers.append("drupal access requirement")
            if re.match(r"^\s{0,4}\w[\w.]*:\s*$", lines[j]) and j > i:
                break
        if not methods:
            methods = ["GET"]
        for method in methods:
            out.append(_make_endpoint(
                root, p, method, path, i + 1, "",
                markers, "Drupal routing.yml；requirements 供参考"))
    return out


def _scan_php(root: Path, p: Path, text: str) -> list[dict]:
    rel = str(p.relative_to(root)).replace("\\", "/")
    low = rel.lower()
    if not any(k in low for k in ("admin", "api", "manage", "system", "config",
                                  "user", "order", "file", "upload", "download",
                                  "export", "module", "route", "index", "public",
                                  "ajax", "action", "controller")):
        return []
    # Laravel / ThinkPHP 路由文件：Route::get('/x', ...) / Route::rule('x', ...)
    route_out = []
    for m in re.finditer(
            r"Route::(get|post|put|delete|patch|any|rule)\(\s*['\"]([^'\"]+)['\"]",
            text, re.I):
        kind = m.group(1).lower()
        method = "ANY" if kind in ("any", "rule") else kind.upper()
        line = text[:m.start()].count("\n") + 1
        route_out.append(_make_endpoint(
            root, p, method, m.group(2), line, "", _markers(text[:8000]),
            "Laravel/ThinkPHP 路由文件；prefix/group 未完全解析"))
    if route_out:
        return route_out
    if not re.search(r"\$_(GET|POST|REQUEST|COOKIE)\b", text):
        return []
    methods = []
    if "$_GET" in text:
        methods.append("GET")
    if "$_POST" in text or "$_REQUEST" in text:
        methods.append("POST")
    if not methods:
        methods = ["ANY"]
    line = next((i + 1 for i, l in enumerate(text.splitlines())
                 if re.search(r"\$_(GET|POST|REQUEST|COOKIE)\b", l)), 1)
    markers = _markers(text[:8000])
    route = "/" + re.sub(r"\.php$", "", low).replace("index", "")
    out = []
    for method in methods:
        out.append(_make_endpoint(root, p, method, route, line, p.name, markers,
                                  "PHP 文件级启发式；需确认实际路由/包含关系"))
    return out


def scan(workspace: str) -> dict:
    root = Path(workspace)
    endpoints, files, py_paths = [], 0, []
    for p in _iter_files(root):
        files += 1
        text = _read(p)
        if not text:
            continue
        try:
            if p.suffix.lower() == ".py":
                py_paths.append(p)
                endpoints += _scan_python(root, p, text)
            elif p.suffix.lower() in (".java", ".kt"):
                endpoints += _scan_java(root, p, text)
            elif p.suffix.lower() in (".js", ".ts", ".tsx", ".jsx"):
                endpoints += _scan_js(root, p, text)
                endpoints += _scan_nest(root, p, text)
            elif p.suffix.lower() == ".go":
                endpoints += _scan_go(root, p, text)
            elif p.suffix.lower() == ".php":
                endpoints += _scan_php(root, p, text)
            elif p.suffix.lower() in (".yml", ".yaml"):
                endpoints += _scan_routing_yml(root, p, text)
        except Exception:
            continue
    if py_paths:
        endpoints += _scan_django(root, py_paths)
    seen, uniq = set(), []
    for e in endpoints:
        if not e:
            continue
        key = (e["method"], e["path"], e["file"], e["line"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(e)
    candidates = [e for e in uniq if not e["protected"]]
    candidates.sort(key=lambda e: (-e["score"], e["path"]))
    others = [e for e in uniq if e["protected"]]
    others.sort(key=lambda e: (-e["score"], e["path"]))
    all_items = candidates + others
    items = all_items if MAX_ITEMS <= 0 else all_items[:MAX_ITEMS]
    return {
        "summary": {
            "files": files, "endpoints": len(uniq),
            "candidates": len(candidates), "protected": len(others),
            "sensitive": sum(1 for e in uniq if e["sensitive"]),
            "returned": len(items), "truncated": max(0, len(all_items) - len(items)),
            "note": "静态启发式：未发现鉴权标记≠未授权；全局中间件/框架配置需沙箱无凭证验证",
        },
        "items": items,
    }


def to_findings(data: dict, limit: int = 30, min_score: int = 6) -> list[dict]:
    """把高信号未授权候选转成平台漏洞 dict；静态候选，poc_verified=False。"""
    out = []
    for e in (data.get("items") or []):
        if e.get("protected") or e.get("score", 0) < min_score:
            continue
        payload = f"{e['method']} {e['poc']['path']}"
        if e.get("poc", {}).get("body"):
            payload += "\n{}"
        out.append({
            "source": "authz",
            "rule_id": f"authz:unauth:{e['method']}:{e['path']}"[:128],
            "title": f"未授权接口候选：{e['method']} {e['path']}"[:120],
            "severity": "WARNING",
            "file_path": e["file"], "line": e["line"],
            "code_snippet": (f"{e['file']}:{e['line']} {e.get('handler') or ''}；"
                             f"未发现鉴权标记；{'、'.join(e.get('reasons') or [])}")[:500],
            "precondition": (f"预期角色：{e.get('expected_role')}；"
                             f"路径：{e['method']} {e['path']}；"
                             "可能由全局中间件/框架配置保护"),
            "poc_payload": payload[:500],
            "poc_verified": False,
            "verify_result": "静态候选：未发现鉴权标记；需无凭证/沙箱验证（未验证）",
        })
    return out[:limit]


def to_markdown(data: dict, task=None) -> str:
    s = data.get("summary") or {}
    lines = ["# 未授权 / 越权接口候选清单", ""]
    if task is not None:
        lines += [f"- 任务：#{getattr(task, 'id', '')} {getattr(task, 'filename', '')}",
                  f"- 技术栈：{getattr(task, 'tech_stack', '')}", ""]
    lines += [
        f"> {s.get('note', '')}",
        f"- 扫描文件：{s.get('files', 0)}；识别接口：{s.get('endpoints', 0)}；"
        f"未发现鉴权标记：{s.get('candidates', 0)}；发现鉴权标记：{s.get('protected', 0)}；"
        f"敏感路径：{s.get('sensitive', 0)}",
        "",
        "## 未发现鉴权标记的候选（按风险排序）",
        "",
    ]
    cands = [x for x in (data.get("items") or []) if not x.get("protected")]
    if not cands:
        lines.append("未识别到候选（可能是框架/路由未被当前提取器覆盖）。")
    for i, e in enumerate(cands, 1):
        lines += [
            f"### {i}. {e['method']} `{e['path']}`（风险分 {e['score']}）",
            "",
            f"- 位置：`{e['file']}:{e['line']}`"
            + (f"；handler：`{e['handler']}`" if e.get("handler") else ""),
            f"- 预期角色：{e.get('expected_role')}；鉴权标记："
            + (", ".join(e.get("auth_markers") or []) or "**未发现**"),
            f"- 原因：{'、'.join(e.get('reasons') or [])}",
            f"- 说明：{e.get('note', '')}",
            "- 无凭证 POC：",
            "```bash",
            e["poc"]["curl"].replace("{BASE_URL}", "http://127.0.0.1:PORT"),
            "```",
            "",
        ]
    protected = [x for x in (data.get("items") or []) if x.get("protected")]
    if protected:
        lines += ["## 已发现鉴权标记的接口（仍需测越权/绕过）", "",
                  "| 方法 | 路径 | 位置 | 鉴权标记 |", "| --- | --- | --- | --- |"]
        for e in protected[:40]:
            lines.append(f"| {e['method']} | `{e['path']}` | `{e['file']}:{e['line']}` | "
                         f"{', '.join(e.get('auth_markers') or [])} |")
        lines.append("")
    lines += ["## 验证建议", "",
              "1. 先对候选发无 Cookie/Token 请求，确认实际状态码与响应；401/403 视为已拦截。",
              "2. 若返回 200/列表/用户资料/配置，记录脱敏响应作为未授权证据；不要批量导出。",
              "3. 遍历只允许沙箱测试数据上试最多 3 个相邻 ID，证明可访问非当前主体记录即可。",
              "4. 写操作接口（POST/PUT/DELETE）不要盲打；先确认参数和副作用，再在沙箱验证。",
              "5. 静态清单不是漏洞结论；沙箱无凭证验证通过后才标 `verified`。"]
    return "\n".join(lines) + "\n"


def to_json(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)
