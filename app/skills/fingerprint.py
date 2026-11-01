# -*- coding: utf-8 -*-
"""组件指纹识别（阶段 0.5）：审计前先摸清包里有什么
识别主流框架/中间件组件 + 文件后缀统计，输出结构化指纹供展示和 Agent 审计参考。
设计原则：
  - 只读特征文件（pom.xml/build.gradle/go.mod/composer.json/package.json/*.csproj 等）
  - 内容匹配只取每个文件前 8KB，避免大文件拖慢
  - 规则聚焦"高审计价值"组件（框架、ORM、反序列化库、模板引擎、网关）
"""
import json
import logging
import os
from pathlib import Path

log = logging.getLogger("fingerprint")

# 特征文件：命中即读取内容跑规则
FEATURE_FILES = {
    "pom.xml", "build.gradle", "settings.gradle", "build.gradle.kts",
    "go.mod", "go.sum", "composer.json", "package.json", "package-lock.json",
    "requirements.txt", "Pipfile", "pyproject.toml", "poetry.lock",
    "struts.xml", "web.xml", "spring.xml", "application.yml", "application.yaml",
    "application.properties", "log4j2.xml", "AndroidManifest.xml", "manage.py",
    "artisan", "wp-config.php", "web.config", "app.config", "packages.config",
    "connectionstrings.config", "machine.config", "global.asax", "*.csproj", "*.sln",
    "global.json",
}

# 各语言后缀统计
LANG_EXTS = {
    "java": {".java", ".jsp", ".jar", ".class", ".xml"},
    "php": {".php", ".phtml"},
    "python": {".py", ".pyc"},
    "javascript": {".js", ".mjs", ".cjs", ".ts", ".vue"},
    "go": {".go"},
    "csharp": {".cs", ".cshtml", ".dll", ".exe", ".aspx", ".ascx",
               ".config", ".csproj", ".sln", ".asax", ".ashx", ".master", ".user"},
    "cpp": {".cpp", ".c", ".h", ".hpp", ".cc", ".so"},
    "html": {".html", ".htm"},
    "css": {".css", ".scss", ".less"},
    "sql": {".sql"},
    "shell": {".sh", ".bash"},
    "ruby": {".rb"},
    "rust": {".rs"},
    "swift": {".swift"},
    "kotlin": {".kt", ".kts"},
}

# 组件规则：(组件名, 关键词列表，任一命中即识别)
# 关键词匹配路径（小写）或特征文件内容（小写）
COMPONENT_RULES = [
    # ---- Java ----
    ("Spring Boot", ["spring-boot-starter", "spring-boot-maven-plugin", "@springbootapplication"]),
    ("Spring MVC / Spring Framework", ["org.springframework", "spring-webmvc", "spring-context"]),
    ("Apache Struts2", ["struts2-core", "org.apache.struts", "struts.xml"]),
    ("Apache Shiro", ["shiro-core", "org.apache.shiro", "shiro.ini"]),
    ("MyBatis", ["mybatis", "mybatis-spring", "org.mybatis"]),
    ("MyBatis-Plus", ["mybatis-plus"]),
    ("Hibernate", ["org.hibernate", "hibernate-core"]),
    ("JPA (Spring Data)", ["spring-data-jpa", "spring-boot-starter-data-jpa"]),
    ("Fastjson", ["fastjson", "com.alibaba.fastjson"]),
    ("Jackson", ["com.fasterxml.jackson"]),
    ("Gson", ["com.google.code.gson"]),
    ("Log4j2", ["log4j-core", "log4j-api", "log4j2.xml"]),
    ("Log4j1 (高危历史漏洞)", ["log4j:log4j", "log4j-1.2", "org.apache.log4j"]),
    ("Apache Commons-Collections (反序列化)", ["commons-collections", "org.apache.commons.collections"]),
    ("XStream (反序列化)", ["com.thoughtworks.xstream"]),
    ("SnakeYAML (反序列化)", ["snakeyaml", "org.yaml"]),
    ("Apache Dubbo", ["org.apache.dubbo", "dubbo-spring"]),
    ("Apache CXF / WebService", ["org.apache.cxf", "javax.jws"]),
    ("Druid 连接池", ["com.alibaba.druid"]),
    ("Netty", ["io.netty"]),
    ("Thymeleaf 模板", ["thymeleaf"]),
    ("Freemarker 模板", ["freemarker", "org.freemarker"]),
    ("Velocity 模板 (SSTI 面)", ["org.apache.velocity", "velocity-engine"]),
    ("JSP/Servlet (老项目)", ["javax.servlet", "jakarta.servlet", ".jsp"]),
    ("Tomcat 内嵌", ["spring-boot-starter-tomcat", "org.apache.tomcat"]),
    # ---- PHP ----
    ("ThinkPHP", ["thinkphp", "think\\app", "topthink"]),
    ("Laravel", ["laravel/framework", "artisan"]),
    ("CodeIgniter", ["codeigniter", "ci4"]),
    ("WordPress", ["wp-config.php", "wp-content", "wp-includes"]),
    ("Yii", ["yiisoft"]),
    ("Slim", ["slim/slim"]),
    ("PHPUnit", ["phpunit/phpunit"]),
    # ---- Python ----
    ("Django", ["django", "django-admin", "manage.py"]),
    ("Flask", ["flask", "from flask"]),
    ("FastAPI", ["fastapi"]),
    ("Tornado", ["tornado"]),
    ("SQLAlchemy", ["sqlalchemy"]),
    ("Celery", ["celery"]),
    ("Pickle (反序列化面)", ["pickle", "cPickle", "joblib"]),
    # ---- Go ----
    ("Gin", ["gin-gonic", "github.com/gin-gonic"]),
    ("Beego", ["beego", "astaxie/beego"]),
    ("Echo", ["labstack/echo", "github.com/labstack/echo"]),
    ("Gorilla/Mux", ["gorilla/mux", "gorilla/sessions"]),
    ("net/http (原生)", ["package main"]),
    # ---- Node/JS ----
    ("Express", ["express"]),
    ("Koa", ["koa"]),
    ("Next.js", ["next"]),
    ("NestJS", ["@nestjs"]),
    ("Vue", ["\"vue\"", "vue/dist"]),
    ("React", ["\"react\"", "react-dom"]),
    ("jQuery", ["jquery"]),
    ("Lodash (链式 payload 面)", ["lodash"]),
    # ---- .NET ----
    ("ASP.NET MVC", ["system.web.mvc", "aspnetcore", "microsoft.aspnetcore"]),
    ("ASP.NET WebForms", ["system.web.ui", "aspx"]),
    (".NET Core / 现代 ASP.NET", ["microsoft.aspnetcore", "netcoreapp", "net6.0", "net8.0"]),
    ("Entity Framework", ["entityframework", "microsoft.entityframeworkcore"]),
    ("WCF", ["system.servicemodel"]),
    ("Newtonsoft.Json", ["newtonsoft.json"]),
    ("NPOI (Excel/Office 读写)", ["npoi.openxml", "npoi"]),
    ("IKVM (.NET-Java 互操作)", ["ikvm.openjdk", "ikvm.runtime"]),
    ("log4net", ["log4net"]),
    ("SignalR", ["microsoft.aspnetcore.signalr", "microsoft.aspnet.signalr"]),
    ("Quartz.NET (任务调度)", ["quartz"]),
    # ---- 通用中间件/客户端 ----
    ("Redis 客户端", ["redis", "spring-boot-starter-data-redis", "jedis", "redigo"]),
    ("MySQL 客户端", ["mysql", "mysql-connector", "pymysql", "github.com/go-sql-driver"]),
    ("MongoDB", ["mongodb", "pymongo", "go.mongodb.org"]),
    ("WebSocket", ["websocket", "socket.io"]),
    ("GraphQL", ["graphql"]),
]

MAX_SCAN_FILES = int(os.environ.get("AUDIT_FINGERPRINT_MAX_FILES", "4000"))  # 0=不限制
FEATURE_READ_BYTES = 8192      # 特征文件只读前 8KB
# 跳过的大型/无关目录（bin/obj/target 保留：.NET 编译产物 dll 在 bin/ 下，是重要指纹与反编译来源）
SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".idea", ".vscode",
             "vendor", "__pycache__", ".gradle", "test", "tests"}


def fingerprint(workspace: str) -> dict:
    """扫描 workspace，返回 {components: [...], ext_stats: {...}, total_files: n}
    components 为已识别的组件名列表（去重保序）。
    """
    root = Path(workspace)
    ext_stats: dict[str, int] = {}
    components: list[str] = []
    seen_comps: set[str] = set()
    scanned = 0
    feature_hits: list[Path] = []

    if not root.is_dir():
        return {"components": [], "ext_stats": {}, "total_files": 0}

    for p in root.rglob("*"):
        if MAX_SCAN_FILES > 0 and scanned >= MAX_SCAN_FILES:
            break
        if not p.is_file():
            continue
        rel = p.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        scanned += 1
        ext = p.suffix.lower()
        if ext:
            ext_stats[ext] = ext_stats.get(ext, 0) + 1
        # 特征文件：文件名精确匹配 或 *.ext 通配匹配（如 *.csproj / *.sln）
        name = p.name.lower()
        if name in FEATURE_FILES or any(
                name.endswith(f[1:]) for f in FEATURE_FILES if f.startswith("*.")):
            feature_hits.append(p)

    # 组件识别：全部文件相对路径都参与匹配（编译产物按文件名即可识别，如 NPOI/IKVM/Newtonsoft.dll），
    # 特征文件额外读内容（前 8KB），弥补纯源码包无特征文件的场景。
    all_parts = [p.relative_to(root).as_posix().lower()
                 for p in root.rglob("*") if p.is_file()]
    path_parts = all_parts if MAX_SCAN_FILES <= 0 else all_parts[:MAX_SCAN_FILES]
    haystack_parts: list[str] = list(path_parts)
    for p in feature_hits[:80]:
        try:
            haystack_parts.append(p.read_text(encoding="utf-8", errors="ignore")[:FEATURE_READ_BYTES].lower())
        except OSError:
            continue
    haystack = "\n".join(haystack_parts)

    for comp, kws in COMPONENT_RULES:
        if any(kw in haystack for kw in kws):
            if comp not in seen_comps:
                seen_comps.add(comp)
                components.append(comp)

    # 后缀 → 语言统计
    lang_stats: dict[str, int] = {}
    for ext, cnt in ext_stats.items():
        for lang, exts in LANG_EXTS.items():
            if ext in exts:
                lang_stats[lang] = lang_stats.get(lang, 0) + cnt
                break

    return {
        "components": components,
        "ext_stats": ext_stats,
        "lang_stats": lang_stats,
        "total_files": scanned,
    }


def format_fingerprint(fp: dict) -> str:
    """人类可读摘要（用于日志/任务详情）"""
    comps = ", ".join(fp.get("components") or []) or "未识别到知名组件"
    langs = sorted(fp.get("lang_stats") or {}, key=lambda k: -fp["lang_stats"][k])
    lang_s = "; ".join(f"{k} {fp['lang_stats'][k]}文件" for k in langs[:6]) or "-"
    return f"组件: {comps} | 语言分布: {lang_s} | 文件数: {fp.get('total_files', 0)}"
