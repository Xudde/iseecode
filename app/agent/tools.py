"""Agent 工具注册表（升级阶段 3）：静态阅读/搜索/索引 + 动态沙箱验证 + 结论产出"""
import ast
import logging
import os
import re
import subprocess
from pathlib import Path

log = logging.getLogger("agent.tools")
SANDBOX_EXEC_TIMEOUT = max(3, int(os.environ.get("AUDIT_SANDBOX_EXEC_TIMEOUT", "20")))

SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "__pycache__", "vendor", "target", "build", "dist", ".gradle", ".idea"}

ROUTE_PATTERNS = {
    "python": [r"@(\w+)\.route\(\s*[\"']([^\"']+)", r"@(\w+)\.(get|post|put|delete)\(\s*[\"']([^\"']+)",
               r"@(app|router)\.(get|post|put|delete|websocket)\(\s*[\"']([^\"']+)",
               r"@[A-Za-z_]+\.(route|get|post|put|delete|websocket)\(([^)]*)"],
    "java": [r"@(?:Request|Get|Post|Put|Delete)Mapping\s*\(([^)]*)"],
    "php": [r"Route::(get|post|put|delete)\(\s*['\"]([^'\"]+)", r"\$router->(get|post|put|delete)\(\s*['\"]([^'\"]+)"],
    "javascript": [r"(?:router|app)\.(get|post|put|delete)\(\s*['\"`]([^'\"`]+)"],
    "typescript": [r"(?:router|app)\.(get|post|put|delete)\(\s*['\"`]([^'\"`]+)",
                   r"@(?:Get|Post|Put|Delete)\(\s*['\"]([^\"']+)"],
    "go": [r'\.(GET|POST|PUT|DELETE)\(\s*"([^"]+)'],
}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".jar", ".woff", ".ttf", ".mp3", ".mp4", ".class", ".dex", ".so"}


def _safe_path(workspace: str, rel: str) -> Path | None:
    """路径安全校验：必须落在 workspace 内"""
    try:
        p = (Path(workspace) / rel).resolve()
        if not str(p).startswith(str(Path(workspace).resolve())):
            return None
        return p
    except (OSError, ValueError):
        return None


def read_file(workspace: str, path: str, start_line: int = 1, end_line: int = 80) -> str:
    """读源码片段，带行号；单次最多 200 行"""
    p = _safe_path(workspace, path)
    if p is None or not p.is_file():
        return f"ERROR: 无法读取 {path}"
    start_line = max(1, int(start_line))
    end_line = min(start_line + 199, int(end_line))
    try:
        lines = p.read_text(errors="ignore").splitlines()
        seg = lines[start_line - 1: end_line]
        body = "\n".join(f"{i:>5} | {l}" for i, l in enumerate(seg, start=start_line))
        return f"{path} 共 {len(lines)} 行，显示 {start_line}-{min(end_line, len(lines))}:\n{body}"
    except OSError as e:
        return f"ERROR: {e}"


def search(workspace: str, pattern: str, glob: str = "*") -> str:
    """跨文件正则搜索，返回 file:line:text，上限 50 条"""
    rx = re.compile(pattern)
    root = Path(workspace)
    hits, scanned = [], 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if Path(name).suffix.lower() in SKIP_EXT:
                continue
            from fnmatch import fnmatch
            if glob != "*" and not fnmatch(name, glob):
                continue
            fp = Path(dirpath) / name
            scanned += 1
            if scanned > 2000:
                return "ERROR: 文件数超限，请缩小 glob 范围"
            try:
                for i, line in enumerate(fp.read_text(errors="ignore").splitlines(), 1):
                    if rx.search(line):
                        rel = fp.relative_to(root)
                        hits.append(f"{rel}:{i}: {line.strip()[:200]}")
                        if len(hits) >= 50:
                            return f"搜索命中（截断至50条）:\n" + "\n".join(hits)
            except OSError:
                continue
    return f"搜索命中 {len(hits)} 条:\n" + "\n".join(hits) if hits else "无命中"


def list_dir(workspace: str, path: str = ".") -> str:
    """目录结构浏览（跳过依赖目录），返回相对路径列表上限 200"""
    p = _safe_path(workspace, path)
    if p is None or not p.is_dir():
        return f"ERROR: 目录不存在 {path}"
    out = []
    for dirpath, dirnames, filenames in os.walk(p):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        rel_base = Path(dirpath).relative_to(p)
        for name in dirnames:
            out.append(f"{rel_base / name}/")
        for name in sorted(filenames):
            out.append(str(rel_base / name))
        if len(out) >= 200:
            break
    return "目录结构（截断200条）:\n" + "\n".join(out[:200])


def file_tree(workspace: str, max_files: int = 300) -> str:
    """列出全部源码文件（相对路径 + 行数），全量审计 Agent 用它建立文件清单"""
    root = Path(workspace)
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            if Path(name).suffix.lower() in SKIP_EXT:
                continue
            fp = Path(dirpath) / name
            try:
                n = len(fp.read_text(errors="ignore").splitlines())
            except OSError:
                n = 0
            out.append(f"{fp.relative_to(root)} ({n}行)")
            if len(out) >= max_files:
                return f"文件清单（截断至{max_files}条）:\n" + "\n".join(out)
    return f"文件清单（共{len(out)}条）:\n" + "\n".join(out) if out else "无源码文件"


class SymbolIndex:
    """轻量 AST 符号索引（Python 完整、其他语言正则兜底），每任务构建一次"""

    def __init__(self, workspace: str):
        self.workspace = workspace
        self.defs: dict[str, list[str]] = {}   # symbol -> ["file:line"]
        self.calls: dict[str, set[str]] = {}   # file -> symbols it calls

    def build(self) -> None:
        root = Path(self.workspace)
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                fp = Path(dirpath) / name
                if fp.suffix == ".py":
                    self._index_python(fp)
                elif fp.suffix in (".java", ".kt", ".php", ".js", ".ts", ".rb", ".go", ".cs"):
                    self._index_regex(fp)

    def _add_def(self, sym: str, fp: Path, line: int) -> None:
        rel = str(fp.relative_to(self.workspace))
        self.defs.setdefault(sym, []).append(f"{rel}:{line}")

    def _index_python(self, fp: Path) -> None:
        try:
            tree = ast.parse(fp.read_text(errors="ignore"))
        except (SyntaxError, OSError):
            return
        rel = str(fp.relative_to(self.workspace))
        called = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self._add_def(node.name, fp, node.lineno)
            if isinstance(node, ast.Call):
                f = node.func
                name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
                if name:
                    called.add(name)
        self.calls[rel] = called

    # 语言关键字/控制流/常见内置符号：不算函数调用（否则 call_chain 全是噪音）
    _NOISE_WORDS = {
        "if", "else", "elif", "for", "foreach", "while", "do", "switch", "case", "catch", "finally",
        "return", "throw", "new", "typeof", "sizeof", "await", "yield", "in", "of", "and", "or", "not",
        "print", "echo", "die", "exit", "isset", "unset", "empty", "include", "require", "require_once",
        "include_once", "list", "array", "true", "false", "null", "none", "self", "this", "static",
        "synchronized", "try", "with", "as", "is", "lambda", "function", "func", "def", "end", "then",
        "elif", "unless", "raise", "assert", "del", "global", "nonlocal", "pass", "break", "continue",
    }

    def _index_regex(self, fp: Path) -> None:
        try:
            lines = fp.read_text(errors="ignore").splitlines()
        except OSError:
            return
        rel = str(fp.relative_to(self.workspace))
        called = set()
        for i, line in enumerate(lines, 1):
            m = re.search(r"(?:function|def|fun|func|public|private|protected)\s+(?:[\w<>\[\]]+\s+)?(\w+)\s*\(", line)
            if m:
                self._add_def(m.group(1), fp, i)
            for m in re.finditer(r"(\w+)\s*\(", line):
                w = m.group(1).lower()
                if w not in self._NOISE_WORDS:
                    called.add(m.group(1))
        self.calls[rel] = called

    def call_chain(self, symbol: str) -> str:
        """返回符号定义位置 + 调用者文件"""
        defs = self.defs.get(symbol, [])
        if not defs:
            return f"符号 {symbol} 未找到定义"
        out = [f"定义: {d}" for d in defs[:10]]
        callers = [f for f, calls in self.calls.items() if symbol in calls and f not in [d.rsplit(':', 1)[0] for d in defs]]
        out.append(f"调用者 ({len(callers)}): " + ", ".join(callers[:20]))
        return "\n".join(out)


def build_route_map(workspace: str, lang: str) -> str:
    """提取路由/控制器入口（攻击面）"""
    pats = ROUTE_PATTERNS.get(lang, ROUTE_PATTERNS["python"])
    root = Path(workspace)
    hits = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if Path(name).suffix.lstrip(".").lower() not in {lang, "py", "java", "php", "js", "ts", "go"}:
                continue
            fp = Path(dirpath) / name
            try:
                text = fp.read_text(errors="ignore")
            except OSError:
                continue
            for pat in pats:
                for i, line in enumerate(text.splitlines(), 1):
                    if re.search(pat, line):
                        rel = fp.relative_to(root)
                        entry = f"{rel}:{i}: {line.strip()[:150]}"
                        if entry not in hits:  # 去重（同文件多 pattern 命中同一行）
                            hits.append(entry)
                        break  # 每行只记一次
                if len(hits) >= 60:
                    break
        if len(hits) >= 60:
            break
    return f"路由/入口 {len(hits)} 条:\n" + "\n".join(hits) if hits else "未识别到路由入口"


def run_semgrep_subset(workspace: str, rel_path: str) -> str:
    """对单文件/目录局部复扫"""
    import json as _json
    p = _safe_path(workspace, rel_path)
    if p is None or not p.exists():
        return f"ERROR: 路径不存在 {rel_path}"
    rules_dir = Path(__file__).resolve().parent.parent / "skills" / "rules"
    cmd = ["semgrep", "--json", "--quiet", "--metrics=off"]
    for y in sorted(rules_dir.glob("*.yaml")):
        cmd += ["--config", str(y)]
    cmd.append(str(p))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        data = _json.loads(proc.stdout)
        results = data.get("results", [])[:20]
        if not results:
            return "局部复扫无命中"
        return "局部复扫命中:\n" + "\n".join(
            f"{r['path']}:{r['start']['line']} [{r['check_id']}] {(r.get('extra', {}).get('message') or '')[:100]}"
            for r in results)
    except Exception as e:
        return f"ERROR: {e}"


# 动态验证工具由 orchestrator 注入 SandboxHandle 后生成闭包。
# 全局沙箱并发闸：唯一定义处（orchestrator 不得再建第二个，否则上限翻倍），
# 上限取 config.SANDBOX_CONCURRENCY。
import threading
from app.config import SANDBOX_CONCURRENCY

_sandbox_sem = threading.Semaphore(max(1, SANDBOX_CONCURRENCY))


def make_http_request_tool(handle):
    def http_request(method: str = "GET", path: str = "/", params: str = "", body: str = "", headers: str = "") -> str:
        """对沙箱内应用发 HTTP 请求。
        path 形如 /vuln 或 /vuln?s=xxx；params 为查询串 k=v&k2=v2（会正确 URL 编码）；
        body 为表单串（POST 时作为表单数据发送）；method 支持 GET/POST。"""
        import urllib.parse

        def _parse_qs(s: str) -> dict:
            out = {}
            for kv in (s or "").split("&"):
                if "=" in kv:
                    k, _, v = kv.partition("=")
                    out[urllib.parse.unquote_plus(k.strip())] = urllib.parse.unquote_plus(v)
            return out

        url = path or "/"
        q = _parse_qs(params)
        if q:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(q)
        if not url.startswith("/"):
            url = "/" + url
        data = _parse_qs(body) if body else None
        m = (method or "GET").upper()
        with _sandbox_sem:
            status, resp = handle.request(url, data or {}, timeout=10, method=m)
        return f"HTTP {status}\n{str(resp)[:1000]}"
    return http_request


def make_sandbox_exec_tool(handle):
    def sandbox_exec(cmd: str) -> str:
        """在沙箱容器内执行命令（用于动态验证），返回输出"""
        with _sandbox_sem:
            out = handle.container.exec_run(["sh", "-c", cmd])
        return f"exit={out.exit_code}\n{str(out.output.decode(errors='ignore'))[:1500]}"
    return sandbox_exec


def build_tool_registry(workspace: str, lang: str, handle=None) -> dict:
    """组装工具注册表 {name: (func, description)}"""
    idx = SymbolIndex(workspace)
    try:
        idx.build()
    except Exception as e:
        log.warning("符号索引构建失败: %s", e)
    reg = {
        "file_tree": (lambda max_files=300: file_tree(workspace, max_files),
                      "列出全部源码文件与行数，建立审计清单，参数 max_files"),
        "read_file": (lambda path, start_line=1, end_line=80: read_file(workspace, path, start_line, end_line),
                      "读源码片段（带行号），参数 path/start_line/end_line"),
        "search": (lambda pattern, glob="*": search(workspace, pattern, glob),
                   "跨文件正则搜索，参数 pattern/glob"),
        "list_dir": (lambda path=".": list_dir(workspace, path),
                     "浏览目录结构，参数 path"),
        "call_chain": (lambda symbol: idx.call_chain(symbol),
                       "查函数/类的定义与调用者，参数 symbol"),
        "route_map": (lambda: build_route_map(workspace, lang),
                      "列出全部路由/控制器入口"),
        "run_semgrep_subset": (lambda path: run_semgrep_subset(workspace, path),
                               "对单文件局部复扫 semgrep，参数 path"),
    }
    if handle is not None:
        reg["http_request"] = (make_http_request_tool(handle), "对沙箱应用发 HTTP 请求验证漏洞，参数 method/path/params/body")
        reg["sandbox_exec"] = (make_sandbox_exec_tool(handle), "在沙箱容器内执行命令，参数 cmd")
    return reg
