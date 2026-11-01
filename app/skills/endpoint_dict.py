# -*- coding: utf-8 -*-
"""全局接口字典：把各任务的 authz_endpoints 归一化后按项目去重，持久化到 SQLite，
并导出 JSONL/CSV 供 D 盘备份。独立脚本运行，不依赖平台 worker。"""
import csv
import json
import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path

from app.config import DATA_DIR
from app.skills.route_paths import normalize_path

DB_PATH = Path(os.environ.get("AUDIT_DB_PATH", str(DATA_DIR / "app.db")))
EXPORT_DIR = Path(os.environ.get("AUDIT_ENDPOINT_EXPORT_DIR", str(DATA_DIR)))
CONF_RANK = {"low": 0, "medium": 1, "high": 2}
STATIC_SUFFIX = (".html", ".htm", ".css", ".js", ".mjs", ".map", ".png",
                 ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
                 ".ttf", ".eot", ".json", ".xml", ".txt", ".webp", ".avif")


def _project_key(filename: str) -> str:
    stem = Path(filename or "unknown").stem
    stem = re.sub(r"_(?:poc|static)$", "", stem, flags=re.I)
    stem = re.sub(r"^\d{8,}_", "", stem)
    return stem[:120] or "unknown"


def _params(path: str) -> list[str]:
    found = re.findall(r"\{([^}]+)\}|:([A-Za-z_]\w*)|<([^>]+)>|\[([^\]]+)\]", path or "")
    out = []
    for groups in found:
        name = next((g for g in groups if g), "")
        if name and name not in out:
            out.append(name)
    return out


def _create(conn):
    conn.execute("""
    CREATE TABLE IF NOT EXISTS endpoint_dict (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_key TEXT NOT NULL,
        project_name TEXT NOT NULL,
        task_id INTEGER NOT NULL,
        framework TEXT NOT NULL DEFAULT '',
        method TEXT NOT NULL DEFAULT 'ANY',
        path_raw TEXT NOT NULL DEFAULT '',
        path_norm TEXT NOT NULL DEFAULT '',
        params_json TEXT NOT NULL DEFAULT '[]',
        auth_label TEXT NOT NULL DEFAULT 'unknown',
        confidence TEXT NOT NULL DEFAULT 'low',
        source TEXT NOT NULL DEFAULT '',
        evidence_file TEXT NOT NULL DEFAULT '',
        evidence_line INTEGER NOT NULL DEFAULT 0,
        note TEXT NOT NULL DEFAULT '',
        first_task_id INTEGER NOT NULL DEFAULT 0,
        last_task_id INTEGER NOT NULL DEFAULT 0,
        seen_count INTEGER NOT NULL DEFAULT 1,
        first_seen TEXT NOT NULL DEFAULT '',
        last_seen TEXT NOT NULL DEFAULT '',
        UNIQUE(project_key, method, path_norm)
    )""")
    conn.execute("""
    CREATE TABLE IF NOT EXISTS endpoint_inventory_cache (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id INTEGER NOT NULL,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        framework TEXT NOT NULL DEFAULT 'inventory',
        confidence TEXT NOT NULL DEFAULT 'low',
        evidence_file TEXT NOT NULL DEFAULT '',
        evidence_line INTEGER NOT NULL DEFAULT 0,
        note TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT '',
        UNIQUE(task_id, method, path)
    )""")


def build(db_path: str | Path = DB_PATH) -> dict:
    conn = sqlite3.connect(str(db_path), timeout=30)
    try:
        _create(conn)
        conn.execute("DELETE FROM endpoint_dict")
        tasks = conn.execute(
            "SELECT id, filename, workspace_path, created_at FROM tasks ORDER BY id").fetchall()
        now = datetime.now().isoformat(timespec="seconds")
        for tid, filename, workspace, created_at in tasks:
            rows = conn.execute("""
                SELECT framework, method, path, labels, confidence, evidence_file,
                       evidence_line, note
                FROM authz_endpoints WHERE task_id=?""", (tid,)).fetchall()
            if not rows:
                continue
            pkey = _project_key(filename)
            project = Path(filename or "").stem
            ws_name = Path(workspace or "").name
            per_task = {}
            for framework, method, path, label, confidence, ef, el, note in rows:
                method = (method or "ANY").upper()
                norm = normalize_path(path or "", (pkey, project, ws_name))
                if (not norm or norm.lower().endswith(STATIC_SUFFIX)
                        or "^" in norm or "$" in norm):
                    continue
                key = (method, norm)
                rank = CONF_RANK.get((confidence or "low").lower(), 0)
                old = per_task.get(key)
                if old is None or rank > old[0]:
                    per_task[key] = (rank, framework, path, label, confidence, ef, el, note,
                                     "authz_semantic")
            for framework, method, path, confidence, ef, el, note in conn.execute("""
                    SELECT framework, method, path, confidence, evidence_file,
                           evidence_line, note
                    FROM endpoint_inventory_cache WHERE task_id=?""", (tid,)).fetchall():
                method = (method or "ANY").upper()
                norm = normalize_path(path or "", (pkey, project, ws_name))
                if (not norm or norm.lower().endswith(STATIC_SUFFIX)
                        or "^" in norm or "$" in norm):
                    continue
                key = (method, norm)
                rank = CONF_RANK.get((confidence or "low").lower(), 0)
                old = per_task.get(key)
                if old is None or rank > old[0]:
                    per_task[key] = (rank, framework, path, "unknown", confidence,
                                     ef, el, note, "inventory")
            for (method, norm), (_, framework, raw, label, confidence, ef, el, note, source) in per_task.items():
                conn.execute("""
                    INSERT INTO endpoint_dict
                    (project_key, project_name, task_id, framework, method, path_raw,
                     path_norm, params_json, auth_label, confidence, source,
                     evidence_file, evidence_line, note, first_task_id, last_task_id,
                     seen_count, first_seen, last_seen)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(project_key, method, path_norm) DO UPDATE SET
                        last_task_id=excluded.last_task_id,
                        last_seen=excluded.last_seen,
                        seen_count=endpoint_dict.seen_count + 1,
                        framework=CASE WHEN excluded.confidence='high' THEN excluded.framework ELSE endpoint_dict.framework END,
                        auth_label=CASE WHEN excluded.confidence='high' THEN excluded.auth_label ELSE endpoint_dict.auth_label END,
                        confidence=CASE WHEN excluded.confidence='high' THEN excluded.confidence ELSE endpoint_dict.confidence END
                """, (pkey, project, tid, framework or "", method, raw or "", norm,
                      json.dumps(_params(raw), ensure_ascii=False), label or "unknown",
                      confidence or "low", source, ef or "", int(el or 0),
                      note or "", tid, tid, 1, created_at or now, now))
        conn.commit()
        total, projects = conn.execute(
            "SELECT count(*), count(DISTINCT project_key) FROM endpoint_dict").fetchone()
        by_label = dict(conn.execute(
            "SELECT auth_label, count(*) FROM endpoint_dict GROUP BY auth_label").fetchall())
        by_conf = dict(conn.execute(
            "SELECT confidence, count(*) FROM endpoint_dict GROUP BY confidence").fetchall())
        by_fw = dict(conn.execute(
            "SELECT framework, count(*) FROM endpoint_dict GROUP BY framework ORDER BY count(*) DESC LIMIT 15").fetchall())
        top_paths = [{"path": p, "projects": n} for p, n in conn.execute(
            "SELECT path_norm, count(DISTINCT project_key) n FROM endpoint_dict GROUP BY path_norm ORDER BY n DESC, path_norm LIMIT 30")]
        return {"total": total, "projects": projects, "by_label": by_label,
                "by_confidence": by_conf, "by_framework": by_fw, "top_paths": top_paths,
                "built_at": now}
    finally:
        conn.close()


def export(db_path: str | Path = DB_PATH, out_dir: str | Path = EXPORT_DIR) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    summary = build(db_path)
    conn = sqlite3.connect(str(db_path), timeout=30)
    try:
        _create(conn)
        rows = conn.execute("""
            SELECT project_key, project_name, task_id, framework, method, path_raw,
                   path_norm, params_json, auth_label, confidence, source,
                   evidence_file, evidence_line, note, first_task_id, last_task_id,
                   seen_count, first_seen, last_seen
            FROM endpoint_dict ORDER BY project_key, path_norm, method""").fetchall()
        cols = ["project_key", "project_name", "task_id", "framework", "method",
                "path_raw", "path_norm", "params_json", "auth_label", "confidence",
                "source", "evidence_file", "evidence_line", "note", "first_task_id",
                "last_task_id", "seen_count", "first_seen", "last_seen"]
        jsonl = out / "endpoint_dict.jsonl"
        with open(jsonl, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(dict(zip(cols, r)), ensure_ascii=False) + "\n")
        csv_path = out / "endpoint_dict.csv"
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f)
            w.writerow(cols)
            w.writerows(rows)
        (out / "endpoint_dict_summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        return {"jsonl": str(jsonl), "csv": str(csv_path),
                "summary": str(out / "endpoint_dict_summary.json"), **summary}
    finally:
        conn.close()


if __name__ == "__main__":
    print(json.dumps(export(), ensure_ascii=False, indent=2))
