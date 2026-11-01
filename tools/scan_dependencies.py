# -*- coding: utf-8 -*-
"""递归依赖 CVE 热扫描：Maven pom / npm package.json / composer.lock / requirements.txt。
用 OSV querybatch 查询；结果写 dependency_scan_cache；--apply 同时落 vulnerabilities 并重生成 static 报告。
"""
import argparse
import json
import os
import re
import sqlite3
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import DATA_DIR

DB_PATH = Path(os.environ.get("AUDIT_DB_PATH", str(DATA_DIR / "app.db")))
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
SKIP_DIRS = {"node_modules", "vendor", "third_party", "thirdparty", "dist",
             "build", "target", "obj", ".git", ".venv", "venv", "__pycache__",
             ".next", ".nuxt", "coverage", "test", "tests", "docs", "examples"}
SEMVER = re.compile(r"^\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?$")


def _tag(n):
    return n.tag.split("}")[-1] if isinstance(n.tag, str) else ""


def _text(n):
    return (n.text or "").strip() if n is not None else ""


def _resolve(ver, props, default=""):
    if not ver:
        return default
    m = re.fullmatch(r"\$\{([^}]+)\}", ver.strip())
    if not m:
        return ver.strip()
    key = m.group(1)
    return props.get(key) or default


def _pom_packages(root: Path, max_files=40):
    out = []
    seen = set()
    for pom in root.rglob("pom.xml"):
        if len(out) >= max_files:
            break
        if any(p.lower() in SKIP_DIRS for p in pom.relative_to(root).parts):
            continue
        try:
            data = ET.parse(pom).getroot()
        except Exception:
            continue
        props = {}
        for p in data.iter():
            if _tag(p) == "properties":
                for c in p:
                    props[_tag(c)] = _text(c)
        project_ver = _text(next((c for c in data if _tag(c) == "version"), None))
        props.setdefault("project.version", project_ver)
        props.setdefault("pom.version", project_ver)
        for dep in data.iter():
            if _tag(dep) != "dependency":
                continue
            group = _text(next((c for c in dep if _tag(c) == "groupId"), None))
            art = _text(next((c for c in dep if _tag(c) == "artifactId"), None))
            ver = _resolve(_text(next((c for c in dep if _tag(c) == "version"), None)), props)
            scope = _text(next((c for c in dep if _tag(c) == "scope"), None)).lower()
            if not group or not art or not ver or "${" in ver or scope in ("test", "provided"):
                continue
            if not SEMVER.match(ver.replace("v", "", 1) if ver.startswith("v") else ver):
                continue
            key = (group, art, ver)
            if key in seen:
                continue
            seen.add(key)
            out.append(("Maven", f"{group}:{art}", ver, str(pom.relative_to(root))))
    return out


def _composer_packages(root: Path):
    out = []
    for lock in root.rglob("composer.lock"):
        if any(p.lower() in SKIP_DIRS for p in lock.relative_to(root).parts):
            continue
        try:
            d = json.loads(lock.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        for sec in ("packages", "packages-dev"):
            for p in d.get(sec, []) or []:
                name = str(p.get("name") or "")
                ver = str(p.get("version") or "").lstrip("v")
                if name and SEMVER.match(ver):
                    out.append(("Packagist", name, ver, str(lock.relative_to(root))))
    return out


def _npm_packages(root: Path):
    out = []
    for pkg in root.rglob("package.json"):
        if any(p.lower() in SKIP_DIRS for p in pkg.relative_to(root).parts):
            continue
        try:
            d = json.loads(pkg.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        for sec in ("dependencies", "devDependencies"):
            for name, ver in (d.get(sec) or {}).items():
                ver = str(ver).lstrip("^~=v ")
                if SEMVER.match(ver):
                    out.append(("npm", name, ver, str(pkg.relative_to(root))))
    return out


def _pip_packages(root: Path):
    out = []
    for req in root.rglob("requirements*.txt"):
        if any(p.lower() in SKIP_DIRS for p in req.relative_to(root).parts):
            continue
        try:
            lines = req.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line in lines:
            m = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*==\s*([0-9][^\s;#]+)", line)
            if m:
                out.append(("PyPI", m.group(1), m.group(2), str(req.relative_to(root))))
    return out


def _packages(root: Path, limit: int):
    out = []
    for fn in (_pom_packages, _composer_packages, _npm_packages, _pip_packages):
        out += fn(root)
    seen, uniq = set(), []
    for eco, name, ver, manifest in out:
        key = (eco, name, ver)
        if key in seen:
            continue
        seen.add(key)
        uniq.append((eco, name, ver, manifest))
    return uniq[:limit]


def _osv_batch(pkgs):
    queries = [{"package": {"name": name, "ecosystem": eco}, "version": ver}
               for eco, name, ver, _ in pkgs]
    if not queries:
        return []
    req = urllib.request.Request(
        OSV_BATCH, data=json.dumps({"queries": queries}).encode(),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        print("OSV_BATCH_ERR", e, flush=True)
        return [{} for _ in pkgs]
    raw = data.get("results") or []
    out = []
    for item in raw:
        if isinstance(item, dict):
            out.append(item)
        elif isinstance(item, list):
            out.append({"vulns": item})
        else:
            out.append({})
    if len(out) < len(pkgs):
        out += [{} for _ in range(len(pkgs) - len(out))]
    return out


def _cve(v):
    for a in (v.get("aliases") or []):
        if str(a).startswith("CVE-"):
            return a
    return str(v.get("id") or "")


def _sev(v):
    s = str((v.get("database_specific") or {}).get("severity") or "").upper()
    return {"CRITICAL": "ERROR", "HIGH": "ERROR", "MODERATE": "WARNING",
            "MEDIUM": "WARNING", "LOW": "INFO"}.get(s, "WARNING")


def _fixed(v):
    for aff in (v.get("affected") or []):
        for rng in (aff.get("ranges") or []):
            for ev in (rng.get("events") or []):
                if ev.get("fixed"):
                    return str(ev["fixed"])
    return ""


def scan_task(task_id, filename, workspace, limit):
    root = Path(workspace or "")
    if not root.is_dir():
        return [], 0
    pkgs = _packages(root, limit)
    results = _osv_batch(pkgs)
    hits = []
    for (eco, name, ver, manifest), result in zip(pkgs, results):
        for v in (result.get("vulns") or []):
            cve = _cve(v)
            if not cve:
                continue
            hits.append({"ecosystem": eco, "package": name, "version": ver,
                         "cve": cve, "severity": _sev(v), "fixed": _fixed(v),
                         "manifest": manifest, "summary": str(v.get("summary") or "")})
    return hits, len(pkgs)


def ensure_tables(db):
    db.execute("""
    CREATE TABLE IF NOT EXISTS dependency_scan_cache (
        task_id INTEGER PRIMARY KEY,
        scanned_at TEXT NOT NULL,
        packages INTEGER NOT NULL DEFAULT 0,
        hits INTEGER NOT NULL DEFAULT 0,
        error TEXT NOT NULL DEFAULT ''
    )""")
    db.commit()


def apply_hits(db, task_id, hits):
    from app.models import Vulnerability
    from sqlalchemy import select
    added = 0
    for h in hits:
        rid = f"osv_nested:{h['cve']}"[:128]
        exists = db.execute(select(Vulnerability.id).where(
            Vulnerability.task_id == task_id,
            Vulnerability.source == "osv_nested",
            Vulnerability.rule_id == rid,
            Vulnerability.file_path == h["manifest"])).first()
        if exists:
            continue
        db.add(Vulnerability(
            task_id=task_id, source="osv_nested", rule_id=rid,
            severity=h["severity"], file_path=h["manifest"], line=0,
            code_snippet=f"{h['package']} {h['version']} -> fixed {h['fixed'] or 'see advisory'}",
            llm_is_real=None, llm_reason="OSV 嵌套依赖命中；需确认项目实际使用与可达性",
            llm_confidence=0.5, poc_verified=False,
            verify_result="依赖版本命中，未验证可达性",
            title=f"{h['cve']} {h['package']} {h['version']}"[:200],
            precondition=f"{h['ecosystem']} {h['package']}=={h['version']}",
        ))
        added += 1
    db.commit()
    return added


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--task", type=int, default=0)
    ap.add_argument("--limit", type=int, default=80)
    args = ap.parse_args()
    from app.db import SessionLocal
    from app.models import Task
    db = SessionLocal()
    ensure_tables_sql = sqlite3.connect(str(DB_PATH), timeout=30)
    ensure_tables(ensure_tables_sql)
    ensure_tables_sql.close()
    q = db.query(Task).order_by(Task.id)
    if args.task:
        q = q.filter(Task.id == args.task)
    tasks = q.all()
    done = skipped = 0
    for t in tasks:
        if not t.workspace_path or not Path(t.workspace_path).is_dir():
            continue
        row = sqlite3.connect(str(DB_PATH), timeout=30).execute(
            "select task_id from dependency_scan_cache where task_id=?", (t.id,)).fetchone()
        if row and not args.force:
            skipped += 1
            continue
        t0 = time.time()
        hits, n = scan_task(t.id, t.filename, t.workspace_path, args.limit)
        c = sqlite3.connect(str(DB_PATH), timeout=30)
        c.execute("""INSERT INTO dependency_scan_cache(task_id,scanned_at,packages,hits,error)
                     VALUES(?,?,?,?,?) ON CONFLICT(task_id) DO UPDATE SET
                     scanned_at=excluded.scanned_at,packages=excluded.packages,
                     hits=excluded.hits,error=excluded.error""",
                  (t.id, datetime.now().isoformat(timespec="seconds"), n, len(hits), ""))
        c.commit(); c.close()
        added = apply_hits(db, t.id, hits) if args.apply else 0
        print(f"T{t.id} packages={n} hits={len(hits)} added={added} sec={time.time()-t0:.1f} {t.filename}", flush=True)
        if args.apply and hits:   # 不限 audit_mode：以前只给 static 重生成报告，
                                   # 导致 poc/full 任务的报告里没有后补的依赖漏洞（2026-11-01 体检查出 289 份过期）
            try:
                from app.queue_worker import _gen_report
                _gen_report(db, t)
                print(f"T{t.id} report regenerated", flush=True)
            except Exception as e:
                print(f"T{t.id} report_fail {e}", flush=True)
        done += 1
    print(f"DONE scanned={done} skipped={skipped}", flush=True)
    db.close()


if __name__ == "__main__":
    main()
