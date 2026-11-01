import re


def normalize_path(path: str, names=()) -> str:
    """把源码文件路径/路由路径归一成可去重的 URL 形态。
    只做保守清洗：去项目根、web root、文件后缀和参数占位符。"""
    p = (path or "").strip()
    if not p:
        return ""
    p = p.replace("\\", "/")
    p = re.sub(r"/+", "/", p)
    if not p.startswith("/"):
        p = "/" + p
    names = {str(n).lower() for n in names if n}
    variants = set(names)
    for n in names:
        variants.add(n.replace("_", "-"))
        variants.add(n.replace("-", "_"))
    names = variants
    parts = [x for x in p.split("/") if x]
    if parts and parts[0].lower() in names:
        parts = parts[1:]
    low = "/" + "/".join(parts)
    for marker in ("/src/public/", "/app/public/", "/backend/public/",
                   "/frontend/public/", "/public/", "/wwwroot/", "/www/", "/html/"):
        idx = low.find(marker)
        if idx >= 0:
            low = low[idx + len(marker) - 1:]
            break
    if low.startswith("/src/"):
        low = "/" + low[5:]
    for marker in ("/app/api/", "/pages/api/"):
        idx = low.find(marker)
        if idx >= 0:
            low = "/api/" + low[idx + len(marker):]
            break
    if "/api/" in low and not low.startswith("/api/"):
        first = low.split("/")[1] if len(low.split("/")) > 1 else ""
        if first.lower() in names or re.search(r"\d", first):
            low = low[low.find("/api/"):]
    low = re.sub(r"/route\.(js|ts|jsx|tsx)$", "", low)
    low = re.sub(r"\.(php|py|rb|java|kt|go|js|ts|tsx|jsx)$", "", low)
    low = re.sub(r"/index$", "/", low)
    low = re.sub(r"\{[^}]+\}|:[A-Za-z_]\w*|<[^>]+>|\[[^\]]+\]", "{param}", low)
    low = re.sub(r"/+", "/", low)
    if low != "/":
        low = low.rstrip("/")
    return low or "/"
