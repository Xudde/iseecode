"""串行任务队列消费器：完整流水线
preprocess → tech_detect → sast → llm_judge → sandbox → poc → agent → report
支持协作式取消（用户停止）：阶段间检查 cancel_requested，取消时清理沙箱。
任何异常不得导致线程退出。
"""
import itertools
import json
import logging
import os
import queue
import threading
from datetime import datetime
from pathlib import Path

from app.db import SessionLocal
from app.models import AgentRun, Task, Vulnerability
from app.skills import (apk_analyze, decompile, driver_analyze, image_baseline, llm_judge,
                        poc, preprocess, report, sast_semgrep, sandbox, tech_detect)
from app.agent_settings import agent_settings
from app.agent import orchestrator

# 阶段 0.4：优先级队列（poc 动态任务 > full > static），seq 防止同优先级比较 task_id
task_queue: "queue.PriorityQueue[tuple[int, int, int]]" = queue.PriorityQueue()
_queue_seq = itertools.count()

# 全量审计熔断：实测千文件级仓库（GitLab 4000 文件 900 步 0 发现，147 万 token）
# 投入产出比极低，默认按工作区文件数熔断。依赖/构建产物不计入。
AUDIT_COUNT_SKIP_DIRS = {"node_modules", "vendor", "third_party", "thirdparty",
                         "bower_components", ".git", ".svn", ".hg", "__pycache__",
                         ".venv", "venv", "dist", "build", "target", "obj"}


def count_audit_files(workspace: str) -> int:
    """统计纳入全量审计范围的文件数（排除依赖/构建/VCS 目录，含 test/docs）"""
    if not workspace or not os.path.isdir(workspace):
        return 0
    n = 0
    for _, dirnames, filenames in os.walk(workspace):
        dirnames[:] = [d for d in dirnames if d.lower() not in AUDIT_COUNT_SKIP_DIRS]
        n += len(filenames)
    return n


# _log 会被 Agent 线程池的多个工作线程并发调用（共享同一 Session，
# SQLAlchemy Session 非线程安全——并发 commit 会打坏会话导致任务卡死），必须串行化
_log_lock = threading.Lock()


def _log(db, task, msg: str) -> None:
    with _log_lock:
        try:
            task.log = (task.log or "") + f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n"
            db.commit()
        except Exception:
            db.rollback()
            try:
                db.refresh(task)
            except Exception:
                pass


def _gen_report(db, task, partial: bool = False) -> None:
    """从 DB 已有漏洞数据生成报告（正常收尾，或停止时保留已发现成果）。
    生成前先用 LLM 为缺 title 的漏洞批量生成可读中文名称（很小的 token 开销）。"""
    try:
        db_vulns = db.query(Vulnerability).filter(Vulnerability.task_id == task.id).all()
        if not db_vulns:
            if partial:
                _log(db, task, "尚无已发现漏洞，跳过阶段性报告")
            return
        try:
            llm_cfg = llm_judge.get_llm_config(db)
            name_max = int(os.environ.get("AUDIT_REPORT_NAME_MAX", "80"))
            # 静态/POC 模式承诺 0 token：AI 命名也跳过；大批量报告不做逐批命名，避免尾部 LLM 调用挂住 worker
            if (llm_cfg is not None and getattr(task, "audit_mode", "full") not in ("static", "poc")
                    and len(db_vulns) <= name_max
                    and any(not (r.title or "").strip() for r in db_vulns)):
                _log(db, task, "为漏洞生成可读中文名称（LLM 批量命名）…")
                n_named = llm_judge.name_vulns(db, task, db_vulns, llm_cfg,
                                               log_fn=lambda m: _log(db, task, m))
                if n_named:
                    _log(db, task, f"已命名 {n_named} 条漏洞")
            elif len(db_vulns) > name_max:
                _log(db, task, f"跳过 LLM 批量命名（{len(db_vulns)} 条 > 上限 {name_max}），报告用 rule_id/已有标题")
        except Exception as e:
            _log(db, task, f"漏洞命名失败（不影响报告）: {e}")
        report_vulns = [{
            "id": r.id, "source": r.source,
            "rule_id": r.rule_id, "title": r.title, "precondition": r.precondition,
            "severity": r.severity, "file_path": r.file_path,
            "line": r.line, "code_snippet": r.code_snippet,
            "llm_is_real": r.llm_is_real, "llm_reason": r.llm_reason,
            "llm_confidence": r.llm_confidence, "poc_payload": r.poc_payload,
            "poc_verified": r.poc_verified, "verify_result": r.verify_result,
            "agent_status": r.agent_status, "agent_evidence": r.agent_evidence,
            "agent_confidence": r.agent_confidence, "agent_reason": r.agent_reason,
            "agent_payload": r.poc_payload,
        } for r in db_vulns]
        hot = None
        try:
            from app.skills import hotlist as hotlist_skill
            hot = hotlist_skill.build(task, db_vulns, top_n=20)
            if hot.get("items"):
                _log(db, task, f"人工深挖清单：Top {len(hot['items'])} 文件（0 token）")
        except Exception as e:
            _log(db, task, f"深挖清单生成失败（不影响报告）: {e}")
        report_path = report.run_report(task, report_vulns, hotlist=hot)
        task.report_path = report_path
        _log(db, task, f"报告已生成：{report_path}")
    except Exception as e:
        _log(db, task, f"报告生成失败: {e}")


def _maybe_cancel(db, task, handle=None) -> bool:
    """协作式取消检查：已请求停止则立即保留已发现成果并生成阶段性报告，返回 True。
    db.refresh：API 会话写入的 cancel_requested 对本会话的 ORM 缓存不可见
    （expire_on_commit=False），必须强制重读，否则运行中任务的停止请求永远看不到。"""
    try:
        db.refresh(task)
    except Exception:
        pass
    if task.cancel_requested or task.status == "cancelled":
        if handle is not None:
            try:
                handle.cleanup()
            except Exception:
                pass
            _log(db, task, "沙箱容器已销毁")
        task.status = "cancelled"
        task.error_msg = "任务已被停止（已发现结果已保存，可点击“继续任务”续跑）"
        _log(db, task, "收到停止请求：已发现结果立即生成阶段性报告…")
        _gen_report(db, task, partial=True)
        _log(db, task, "任务已停止，结果已保留")
        db.commit()
        return True
    return False


def _process(task_id: int) -> None:
    db = SessionLocal()
    try:
        task = db.get(Task, task_id)
        if task is None:
            return
        if task.status == "cancelled" or task.cancel_requested:
            task.status = "cancelled"
            task.error_msg = "任务已被用户停止"
            db.commit()
            return
        handle = None  # 沙箱句柄，取消时需清理

        def _cc() -> bool:
            """实时取消检查（供 Agent/全量审计长阶段使用，每次重读数据库）"""
            try:
                db.refresh(task)
            except Exception:
                pass
            return bool(task.cancel_requested)

        # 1. 预处理：APK/镜像/反编译直接分析；zip 解压 + 初筛
        if task.project_type in ("apk", "image", "decompile", "driver"):
            task.status = "preprocessing"
            ready = {"apk": "APK 文件", "image": "镜像文件", "decompile": "待反编译文件",
                     "driver": "驱动文件"}.get(task.project_type, f"{task.project_type} 文件")
            _log(db, task, f"{ready}就绪，跳过解压")
            vuln_dict_map = {}
        else:
            task.status = "preprocessing"
            _log(db, task, "开始预处理：解压源码包…")
            try:
                # 续跑修复：首次运行后 workspace_path 已是解压目录，解压源必须用
                # 始终指向原始上传 zip 的 upload_path，否则续跑报 Is a directory 失败
                src_path = task.upload_path or task.workspace_path
                if Path(src_path).is_dir():
                    _log(db, task, "复用已解压的工作区（续跑，上传原件缺失）")
                    result = {"workspace": str(src_path), "total_size": 0}
                else:
                    result = preprocess.run_preprocess(
                        task, src_path, lambda m: _log(db, task, m))
                task.workspace_path = result["workspace"]
                suspicious = preprocess.pre_screen(result["workspace"])
                if suspicious:
                    _log(db, task, f"恶意样本初筛发现可疑文件：{', '.join(suspicious[:10])}")
                _log(db, task, f"解压完成，共 {result['total_size']} 字节")
                nested_count = result.get("nested_count", 0)
                if nested_count:
                    _log(db, task, f"嵌套压缩包已展开：{nested_count} 个（最多 3 层 / 20 个，"
                                   f"仍受 {preprocess.MAX_EXTRACT_SIZE // 1024 // 1024}MB 总大小限制）")
                skipped_nested = result.get("nested_skipped") or []
                if skipped_nested:
                    _log(db, task, f"嵌套压缩包跳过 {len(skipped_nested)} 个（详情见上方日志/失败原因）")
            except Exception as e:
                task.status = "failed"
                task.error_msg = f"预处理失败: {e}"
                _log(db, task, f"预处理失败: {e}")
                return
        if _maybe_cancel(db, task):
            return

        # 2~3. 技术栈识别 + 静态扫描
        if task.project_type == "apk":
            task.tech_stack = "android"
            task.status = "sast"
            _log(db, task, "执行 APK 静态分析（Manifest + DEX）…")
            try:
                apk_info, vulns = apk_analyze.run_apk_analysis(task.workspace_path)
                _log(db, task, f"APK 信息：{apk_info.get('package')} v{apk_info.get('version_name')}")
                try:
                    from app.skills import mobsf_scan
                    mv = mobsf_scan.scan(
                        task.workspace_path, lambda m: _log(db, task, f"  [mobsf] {m}"))
                    if mv:
                        for v in mv:
                            v["file_path"] = task.filename
                        vulns = list(vulns) + mv
                        _log(db, task, f"MobSF APK 静态分析：新增 {len(mv)} 条")
                except Exception as e:
                    _log(db, task, f"MobSF 分析失败（跳过）: {e}")
            except Exception as e:
                task.status = "failed"
                task.error_msg = f"APK 分析失败: {e}"
                _log(db, task, f"APK 分析失败: {e}")
                return
        elif task.project_type == "image":
            task.tech_stack = "image"
            task.status = "sast"
            name = Path(task.filename).name
            if "dockerfile" in name.lower():
                _log(db, task, "执行 Dockerfile 基线检查…")
                try:
                    text = Path(task.workspace_path).read_text(errors="ignore")
                    vulns = image_baseline.scan_dockerfile(text)
                except Exception as e:
                    task.status = "failed"
                    task.error_msg = f"Dockerfile 解析失败: {e}"
                    _log(db, task, f"Dockerfile 解析失败: {e}")
                    return
            else:
                try:
                    img_info, vulns = image_baseline.scan_image_tar(
                        task.workspace_path, lambda m: _log(db, task, m))
                    _log(db, task, f"镜像信息：{img_info.get('image_tags')} ({img_info.get('image_id')})")
                except Exception as e:
                    task.status = "failed"
                    task.error_msg = f"镜像基线检查失败: {e}"
                    _log(db, task, f"镜像基线检查失败: {e}")
                    return
        elif task.project_type == "decompile":
            # 升级阶段 2：反编译流水线（workspace_path 保持为上传文件路径）
            task.status = "preprocessing"
            _log(db, task, "执行反编译…")
            from app.config import WORKSPACE_DIR
            dec_ws = WORKSPACE_DIR / f"task_{task.id}"
            dec_ws.mkdir(parents=True, exist_ok=True)
            try:
                dec = decompile.decompile(task.workspace_path, str(dec_ws),
                                          lambda m: _log(db, task, m), native_deep=True)
            except Exception as e:
                dec = {"ok": False, "degraded": True, "lang": "unknown", "info": str(e)}
                _log(db, task, f"反编译异常: {e}")
            task.tech_stack = dec.get("lang", "unknown")
            vulns = []
            if dec.get("ok"):
                src = dec_ws / "decompiled"
                stacks = tech_detect.run_tech_detect_multi(str(src)) or [dec.get("lang", "unknown")]
                task.tech_stack = ",".join(stacks)
                _log(db, task, f"反编译成功（{dec['info']}），技术栈 {task.tech_stack}，产物标注“行号仅供参考”")
                task.status = "sast"
                _log(db, task, "对反编译产物执行 semgrep 扫描…")
                try:
                    vulns = sast_semgrep.run_sast(str(src), stacks)
                except Exception as e:
                    _log(db, task, f"反编译产物扫描失败: {e}")
            else:
                # 降级：字符串特征扫描
                _log(db, task, f"反编译失败（{dec.get('info','')}），降级为字符串特征扫描")
                try:
                    vulns = decompile.degrade_string_scan(task.workspace_path)
                except Exception as e:
                    _log(db, task, f"降级扫描失败: {e}")
        elif task.project_type == "driver":
            task.tech_stack = "windows-driver"
            task.status = "sast"
            _log(db, task, "执行 Windows 驱动静态审计（PE 结构/导入/签名/攻击面启发式 + capa/Ghidra，0 token）…")
            try:
                from app.config import WORKSPACE_DIR
                artifact_dir = str(WORKSPACE_DIR / f"task_{task.id}_driver_decompiled")
                drv = driver_analyze.analyze(
                    task.workspace_path, lambda m: _log(db, task, f"  [driver] {m}"),
                    deep=True, artifact_dir=artifact_dir)
                vulns = drv["findings"]
                for v in vulns:
                    v["file_path"] = task.filename  # 上传落盘名带时间戳，展示用原始文件名
                task.fingerprint = json.dumps(drv["fingerprint"], ensure_ascii=False)
                _log(db, task, f"驱动静态审计完成：{len(vulns)} 条风险/线索（启发式，需人工复核）")
            except Exception as e:
                task.status = "failed"
                task.error_msg = f"驱动审计失败: {e}"
                _log(db, task, f"驱动审计失败: {e}")
                return
        elif task.project_type == "web":
            # 混合包支持：解压目录内若含编译产物（dll/exe/jar 等），先批量反编译
            # 用户常见场景：上传"整体打包的编译产物 zip"（如 ASP.NET 发布目录），
            # 业务逻辑在 bin/*.dll 里，不能只扫静态资源。此处把它们还原为源码再一起扫。
            try:
                from app.config import DECOMPILE_EXTENSIONS
                emb_bins = [p for p in Path(task.workspace_path).rglob("*")
                            if p.is_file() and p.suffix.lower() in DECOMPILE_EXTENSIONS]
                if emb_bins:
                    _log(db, task, f"检测到包内含编译产物 {len(emb_bins)} 个（含 .dll/.exe/.jar 等），自动反编译…")
                    emb_dec = Path(task.workspace_path) / "decompiled_embedded"
                    emb_dec.mkdir(parents=True, exist_ok=True)
                    emb_ok = 0
                    for b in emb_bins[:100]:  # 上限 100 个，防爆炸
                        try:
                            # 每个二进制独立子目录，避免反编译产物互相覆盖（缓存合并 bug 修复）
                            sub = emb_dec / b.stem[:80].replace(".", "_")
                            sub.mkdir(parents=True, exist_ok=True)
                            d = decompile.decompile(str(b), str(sub),
                                                    lambda m: _log(db, task, m))
                            if d.get("ok"):
                                emb_ok += 1
                        except Exception as e:
                            _log(db, task, f"反编译 {b.name} 异常: {e}")
                    if emb_ok:
                        _log(db, task, f"反编译成功 {emb_ok} 个编译产物，源码已并入扫描目录")
                    else:
                        _log(db, task, "编译产物反编译均失败，仅扫描静态源码")
            except Exception as e:
                _log(db, task, f"混合包反编译检测异常: {e}")
            techs = tech_detect.run_tech_detect_multi(task.workspace_path)
            sys_files = []
            try:
                sys_files = [p for p in Path(task.workspace_path).rglob("*.sys")
                             if p.is_file() and p.stat().st_size <= 200 * 1024 * 1024][:20]
            except OSError:
                pass
            if not techs and sys_files:
                task.tech_stack = "windows-driver"
                task.audit_mode = "static"
                _log(db, task, f"未识别到源码栈，但发现 {len(sys_files)} 个 Windows 驱动（.sys），"
                               f"进入驱动静态审计（自动切为静态模式，不消耗 token）")
            else:
                task.tech_stack = ",".join(techs) if techs else "unknown"
                _log(db, task, f"识别技术栈：{task.tech_stack}")
                if not techs:
                    task.status = "skipped"
                    task.error_msg = "未能识别代码语言栈（压缩包内可能不含源码文件），已跳过扫描"
                    _log(db, task, "未能识别代码语言栈（压缩包内可能不含源码文件），任务标记为 skipped")
                    return
            # 组件指纹识别：审计前先摸清组件/语言分布，供展示与 Agent 参考
            try:
                from app.skills import fingerprint
                fp = fingerprint.fingerprint(task.workspace_path)
                if sys_files:
                    comps = fp.setdefault("components", [])
                    if "Windows Kernel Driver" not in comps:
                        comps.append("Windows Kernel Driver")
                task.fingerprint = json.dumps(fp, ensure_ascii=False)
                _log(db, task, f"组件指纹：{fingerprint.format_fingerprint(fp)}")
            except Exception as e:
                _log(db, task, f"组件指纹识别异常: {e}")
            task.status = "sast"
            if techs:
                _log(db, task, "执行 semgrep 静态扫描…")
                try:
                    vulns = sast_semgrep.run_sast(task.workspace_path, techs)
                except Exception as e:
                    task.status = "failed"
                    task.error_msg = f"静态扫描失败: {e}"
                    _log(db, task, f"静态扫描失败: {e}")
                    return
            else:
                vulns = []
                _log(db, task, "无源码栈：跳过 semgrep，仅执行驱动静态审计")
            if sys_files:
                _log(db, task, f"对 {len(sys_files)} 个 Windows 驱动执行静态审计…")
                if len(sys_files) > 3:
                    _log(db, task, "capa/Ghidra 深度分析仅前 3 个驱动（避免多驱动批量过慢）")
                from app.config import WORKSPACE_DIR
                artifact_dir = str(WORKSPACE_DIR / f"task_{task.id}_driver_decompiled")
                drv_vulns = []
                for idx, sp in enumerate(sys_files):
                    try:
                        drv = driver_analyze.analyze(
                            str(sp), lambda m: _log(db, task, f"  [driver] {m}"),
                            deep=(idx < 3), artifact_dir=artifact_dir)
                        rel = str(sp.relative_to(task.workspace_path)).replace("\\", "/")
                        for v in drv["findings"]:
                            v["file_path"] = rel
                            drv_vulns.append(v)
                        _log(db, task, f"  驱动 {rel}: {len(drv['findings'])} 条线索")
                    except Exception as e:
                        _log(db, task, f"  驱动 {sp.name} 分析失败（跳过）: {e}")
                vulns = list(vulns) + drv_vulns
        if _maybe_cancel(db, task):
            return

        # 2.8 巨人组合扫描（零 token 全离线）：授权/配置规则包 + gitleaks + trivy
        if task.project_type == "driver":
            _log(db, task, "驱动任务由专用引擎分析，跳过巨人组合扫描（如需密钥扫描请打包为 zip 上传）")
        else:
            try:
                from app.skills import giants
                g_ws = task.workspace_path
                if task.project_type == "decompile":
                    # 反编译任务：扫反编译产物而不是二进制原件
                    from app.config import WORKSPACE_DIR
                    dec = WORKSPACE_DIR / f"task_{task.id}" / "decompiled"
                    if dec.is_dir():
                        g_ws = str(dec)
                eng_settings = agent_settings(db)
                gv = giants.run_giants(
                    g_ws, lambda m: _log(db, task, f"  [giants] {m}"),
                    task_name=task.filename, settings=eng_settings)
                if gv:
                    vulns = list(vulns) + gv
                    _log(db, task, f"巨人组合扫描：新增 {len(gv)} 条（0 token）")
            except Exception as e:
                _log(db, task, f"巨人组合扫描失败（跳过，不影响任务）: {e}")

        # 6.8 SourceMap 还原产物补扫：giants 的 JS 情报在 semgrep 之后才写出原始 TS/Vue/JSX，
        # 这里对还原目录补跑一次，避免“还原了但没审计”。
        recovered_dir = Path(task.workspace_path) / "_sourcemap_recovered"
        if recovered_dir.is_dir():
            try:
                recovered_files = [p for p in recovered_dir.rglob("*") if p.is_file()]
                if recovered_files:
                    _log(db, task, f"对 SourceMap 还原的 {len(recovered_files)} 个源码文件补跑 semgrep…")
                    rv = sast_semgrep.run_sast(
                        str(recovered_dir), ["typescript", "javascript"])
                    if rv:
                        vulns = list(vulns) + rv
                        _log(db, task, f"SourceMap 还原源码补扫：新增 {len(rv)} 条")
                    else:
                        _log(db, task, "SourceMap 还原源码补扫：无新命中")
            except Exception as e:
                _log(db, task, f"SourceMap 还原源码补扫失败（跳过）: {e}")

        # 未授权接口清单：静态候选落库（不自动发写请求；沙箱探测走任务页按钮/API）
        if task.project_type == "web" and (eng_settings.get("engine_authz", 1) == 1):
            try:
                from app.skills import authz_inventory
                inv = authz_inventory.scan(task.workspace_path)
                af = authz_inventory.to_findings(inv)
                if af:
                    vulns = list(vulns) + af
                    s = inv.get("summary") or {}
                    _log(db, task, f"未授权接口候选：{s.get('endpoints', 0)} 个接口，"
                                   f"{s.get('candidates', 0)} 个未发现鉴权标记，"
                                   f"落库 {len(af)} 条（静态，未动态验证）")
                else:
                    _log(db, task, "未授权接口候选：无高信号候选")
            except Exception as e:
                _log(db, task, f"未授权接口清单失败（跳过，不影响任务）: {e}")

        # 阶段 1：框架级鉴权语义（Django/Spring/Express），输出匿名/登录/角色/条件放行标签
        if task.project_type == "web" and (eng_settings.get("engine_authz", 1) == 1):
            try:
                from app.skills import authz_semantic
                sem = authz_semantic.scan(task.workspace_path)
                authz_semantic.store(db, task.id, sem)
                s = sem.get("summary") or {}
                _log(db, task, f"鉴权语义：{s.get('endpoints', 0)} 个接口，标签 "
                               f"{json.dumps(s.get('by_label') or {}, ensure_ascii=False)}")
            except Exception as e:
                _log(db, task, f"鉴权语义分析失败（跳过，不影响任务）: {e}")

        _log(db, task, f"静态扫描完成，发现 {len(vulns)} 条疑似漏洞")

        # 落库（续跑兼容：同位置同规则已有记录则复用，不重复落库——
        # 重扫产生的行 agent_status 全为 None，若不复用，下方"跳过已研判"永远不成立，
        # 续跑会重复研判并重复消耗 token）
        existing_rows = {(r.file_path, r.line, r.rule_id): r
                         for r in db.query(Vulnerability).filter(Vulnerability.task_id == task.id).all()}
        vuln_rows = []
        new_cnt = 0
        for v in vulns:
            key = (v["file_path"], v["line"], v["rule_id"])
            row = existing_rows.get(key)
            if row is None:
                row = Vulnerability(
                    task_id=task.id,
                    source=v.get("source") or {"apk": "apk", "image": "image",
                                               "driver": "native"}.get(task.project_type, "semgrep"),
                    rule_id=v["rule_id"],
                    title=v.get("title"),
                    severity=v["severity"], file_path=v["file_path"],
                    line=v["line"], code_snippet=v["code_snippet"],
                    precondition=v.get("precondition"),
                    poc_payload=v.get("poc_payload"),
                    poc_verified=v.get("poc_verified"),
                    verify_result=v.get("verify_result"),
                    agent_evidence=v.get("agent_evidence"),
                )
                db.add(row)
                existing_rows[key] = row
                new_cnt += 1
            vuln_rows.append((row, v))
        db.commit()
        if new_cnt < len(vulns):
            _log(db, task, f"续跑兼容：复用已有漏洞记录 {len(vulns) - new_cnt} 条（含研判结果），新落库 {new_cnt} 条")

        # 阶段 3：利用链引擎 v1（入口来自鉴权语义，sink 来自漏洞候选）
        try:
            from app.skills import chain_engine
            n_chain = chain_engine.generate_and_store(db, task.id)
            if n_chain:
                _log(db, task, f"利用链引擎：生成 {n_chain} 条静态链候选（待动态验证）")
        except Exception as e:
            _log(db, task, f"利用链引擎失败（跳过，不影响任务）: {e}")

        # 4. 读取 LLM 配置（供 Agent 深度研判使用）。
        task.status = "llm_judging"
        llm_cfg = llm_judge.get_llm_config(db)
        if task.audit_mode == "static":
            llm_cfg = None
            _log(db, task, "仅静态扫描模式：跳过 Agent 深度研判与全量审计（不消耗 token），即将生成报告")
        elif task.audit_mode == "poc":
            llm_cfg = None
            _log(db, task, "沙箱 POC 验证模式：跳过 Agent 与全量审计（0 token），仅部署沙箱并验证命中")
        elif llm_cfg is None:
            _log(db, task, "未配置 LLM，跳过 Agent 深度研判")
        else:
            _log(db, task, "LLM 已配置，使用 Agent 深度研判（取代逐条片段研判）")
        if _maybe_cancel(db, task):
            return

        # 5. Docker 沙箱部署（APK/镜像/反编译任务跳过；失败不阻断，仅跳过 POC）
        if task.project_type in ("apk", "image"):
            handle = None
            if task.project_type == "apk":
                _log(db, task, "APK 任务不支持自动沙箱部署，跳过 POC 验证")
            else:
                _log(db, task, "镜像基线任务无需 POC 验证")
        elif task.project_type == "decompile":
            handle = None
            _log(db, task, "反编译任务为静态分析，跳过 POC 验证")
        elif task.project_type == "driver":
            handle = None
            _log(db, task, "驱动任务为静态审计，跳过沙箱部署与 POC 验证")
        elif task.audit_mode == "static":
            handle = None
            _log(db, task, "仅静态扫描模式：跳过沙箱部署与 POC 验证")
        else:
            task.status = "sandbox_deploying"
            _log(db, task, "部署 Docker 沙箱环境…")
            # 多栈任务按识别顺序逐栈尝试部署，任一栈成功即用
            # （修复：tech_stack 是逗号拼接串，直接查配置表必然 miss，多栈任务永远拿不到沙箱）
            handle = None
            for _tech in [t.strip() for t in (task.tech_stack or "").split(",") if t.strip()]:
                h = sandbox.deploy_sandbox(task.workspace_path, _tech, lambda m: _log(db, task, m))
                if h is not None:
                    handle = h
                    _log(db, task, f"沙箱已按 {_tech} 栈部署")
                    break
            if _maybe_cancel(db, task, handle):
                return
        # 6. POC 验证
        task.status = "poc_verifying"
        if handle is None:
            if task.project_type not in ("apk", "image", "decompile", "driver"):
                _log(db, task, "沙箱部署失败/不支持，跳过 POC 验证")
        else:
            try:
                passed = poc.verify_all(vuln_rows, task.workspace_path, handle)
                db.commit()
                _log(db, task, f"POC 验证完成：{passed}/{min(len(vuln_rows), 8)} 条验证通过")
            except Exception as e:
                _log(db, task, f"POC 验证异常: {e}")
            # 注意：容器保留到 Agent 深度研判结束再销毁（Agent 动态验证需要）
        if _maybe_cancel(db, task, handle):
            return

        # 6.5 Agent 深度研判（升级阶段 3）：配置了 LLM 才执行；优先 ERROR/WARNING，最多 agent_max_vulns 条
        st = agent_settings(db)
        if llm_cfg is None:
            _log(db, task, "未配置 LLM，跳过 Agent 深度研判")
        elif task.project_type == "driver":
            _log(db, task, "驱动任务为静态启发式审计，跳过 Agent 深度研判（避免对二进制臆测）")
        else:
            task.status = "agent_analyzing"
            # 续跑场景：跳过已研判的漏洞（agent_status 非空），不重复消耗 token
            all_rows = [row for row, _ in vuln_rows]
            judged = {r.id for r in all_rows if r.agent_status is not None}
            candidates = [r for r in all_rows if r.agent_status is None]
            if judged:
                _log(db, task, f"续跑：跳过已研判 {len(judged)} 条，仅研判未处理 {len(candidates)} 条")
            sev_rank = {"ERROR": 0, "HIGH": 0, "WARNING": 1, "MEDIUM": 1, "INFO": 2, "LOW": 2}
            candidates.sort(key=lambda r: sev_rank.get(r.severity, 3))
            candidates = candidates[:st["agent_max_vulns"]]
            if not candidates:
                _log(db, task, "无候选漏洞，跳过 Agent 深度研判")
            else:
                _log(db, task, f"启动 Agent 深度研判：{len(candidates)} 条候选"
                               f"（并发 {st['agent_concurrency']}，步数上限 {st['agent_max_steps']}）")
                try:
                    counts = orchestrator.analyze_vulns(
                        db, candidates, task.workspace_path, task.tech_stack,
                        handle=handle, llm_cfg=llm_cfg,
                        cancel_check=_cc,
                        log_fn=lambda m: _log(db, task, f"  [agent] {m}"),
                        settings=st)
                    _log(db, task, f"Agent 研判完成：verified={counts.get('verified', 0)} "
                                   f"false_positive={counts.get('false_positive', 0)} "
                                   f"unverified={counts.get('unverified', 0)} error={counts.get('error', 0)}")
                except Exception as e:
                    _log(db, task, f"Agent 研判失败（不影响任务完成）: {e}")
        if _maybe_cancel(db, task, handle):
            return

        # 7.5 Agent 全量审计（根治漏报：不限于 semgrep 命中行，覆盖未授权访问/逻辑/链式漏洞）
        if llm_cfg is not None and task.project_type in ("web", "decompile"):
            audit_ws = task.workspace_path
            if task.project_type == "decompile":
                from app.config import WORKSPACE_DIR
                audit_ws = str(WORKSPACE_DIR / f"task_{task.id}" / "decompiled")
            audit_files = count_audit_files(audit_ws)
            max_files = int(st["full_audit_max_files"])
            if audit_files > max_files:
                _log(db, task, f"全量审计已熔断：工作区 {audit_files} 个文件 > 上限 {max_files}。"
                               f"实测千文件级仓库全量审计产出极低且消耗百万级 token，本次跳过（0 token）。"
                               f"如确需执行，可在平台设置调高 full_audit_max_files。")
            else:
                task.status = "agent_full_audit"
                _log(db, task, f"启动 Agent 全量审计（工作区 {audit_files} 个文件，熔断阈值 {max_files}；"
                               f"自主遍历全部源码，不依赖静态规则命中）…")
                try:
                    existing = [(r.file_path, r.line, r.rule_id)
                                for r in db.query(Vulnerability).filter(Vulnerability.task_id == task.id).all()]
                    fcounts = orchestrator.full_audit(
                        db, task.id, audit_ws, task.tech_stack,
                        handle=handle, llm_cfg=llm_cfg, existing=existing,
                        cancel_check=_cc,
                        fingerprint_json=task.fingerprint,
                        log_fn=lambda m: _log(db, task, f"  [full-audit] {m}"),
                        settings=st)
                    _log(db, task, f"全量审计完成：新增 {fcounts.get('found', 0)} 条 verified，"
                                   f"升级已有 {fcounts.get('upgraded', 0)} 条，"
                                   f"跳过重复 {fcounts.get('skipped', 0)}，落库失败 {fcounts.get('error', 0)}")
                except Exception as e:
                    _log(db, task, f"全量审计异常（不影响任务完成）: {e}")
        if _maybe_cancel(db, task, handle):
            return

        # 沙箱生命周期终点：web 任务保留容器供"手工 POC 验证"使用（删除任务时销毁）；
        # 其余类型立即销毁。
        if handle is not None:
            if task.project_type == "web":
                try:
                    task.sandbox_cid = handle.container.id
                    task.sandbox_port = handle.internal_port
                    _log(db, task, "沙箱容器保留中：任务详情页可点击“手动验证”查看漏洞回显，删除任务时将自动销毁")
                except Exception as e:
                    _log(db, task, f"沙箱保留失败: {e}")
            else:
                try:
                    handle.cleanup()
                    _log(db, task, "沙箱容器已销毁")
                except Exception as e:
                    _log(db, task, f"沙箱销毁异常: {e}")
            db.commit()

        # 7. 生成报告（从 DB 读回最新漏洞状态，含 LLM/POC/Agent 结果）
        task.status = "reporting"
        if _maybe_cancel(db, task):
            return
        _gen_report(db, task, partial=False)

        task.status = "completed"
        db.commit()
    except Exception as e:  # 全局兜底
        try:
            task = db.get(Task, task_id)
            if task:
                task.status = "failed"
                task.error_msg = f"任务异常: {e}"
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


def recover_pending_tasks() -> int:
    """服务启动时恢复中断任务：非终态任务重置为 pending 并重新入队"""
    n = 0
    try:
        db = SessionLocal()
        # 阶段 0.5：清理已删任务遗留的深挖会话（FK 未强制，孤儿 run 会污染新任务状态）
        try:
            db.query(AgentRun).filter(~AgentRun.task_id.in_(db.query(Task.id))).delete(
                synchronize_session=False)
            db.commit()
        except Exception:
            db.rollback()
        # 阶段 0.3/0.6：启动时清理已退出沙箱的失效引用与容器，避免 runtime_ready 误报
        try:
            stale = db.query(Task).filter(Task.sandbox_cid.isnot(None)).all()
            for t in stale:
                if not sandbox.is_running(t.sandbox_cid):
                    sandbox.cleanup_cid(t.sandbox_cid)
                    t.sandbox_cid = None
                    t.sandbox_port = None
                    t.log = (t.log or "") + "[recover] 沙箱容器已退出，清理失效引用\n"
            db.commit()
        except Exception:
            db.rollback()
        non_terminal = ("pending", "preprocessing", "sast", "llm_judging", "agent_analyzing",
                        "agent_full_audit", "sandbox_deploying", "poc_verifying", "reporting")
        rows = db.query(Task).filter(Task.status.in_(non_terminal)).all()
        for t in rows:
            if t.status != "pending":
                t.log = (t.log or "") + f"[recover] 服务重启，任务从 {t.status} 重置为 pending\n"
                t.status = "pending"
            enqueue(t.id)
            n += 1
        db.commit()
        db.close()
    except Exception as e:  # 恢复失败不阻断启动
        try:
            logging.getLogger("audit-platform.worker").error(f"任务恢复失败: {e}")
        except Exception:
            pass
    return n


def _worker_loop() -> None:
    """单 worker 串行消费任务，任何异常不得导致线程退出。"""
    log = logging.getLogger("audit-platform.worker")
    while True:
        try:
            _, _, task_id = task_queue.get()
            _process(task_id)
            # 兜底：_process 返回但任务未到终态（会话被打坏导致兜底自身失败时发生），
            # 用新会话强制标记 failed，防止任务永久卡在中间状态
            s = SessionLocal()
            try:
                t = s.get(Task, task_id)
                if t is not None and t.status not in ("completed", "failed", "skipped", "cancelled"):
                    t.status = "failed"
                    t.error_msg = f"任务处理异常退出（原状态 {t.status}），已由 worker 兜底标记失败，可点「继续任务」续跑"
                    s.commit()
                    log.error(f"任务 {task_id} 处理返回后未到终态，已兜底标记 failed")
            finally:
                s.close()
        except Exception as e:  # noqa: BLE001
            # 异常写服务端日志，不再静默吞掉
            try:
                log.exception(f"worker 处理任务 {task_id} 异常: {e}")
            except Exception:
                pass


def start_worker() -> threading.Thread:
    t = threading.Thread(target=_worker_loop, name="task-worker", daemon=True)
    t.start()
    return t


def enqueue(task_id: int) -> None:
    """阶段 0.4：poc（动态验证）优先于 full，full 优先于 static；同优先级按入队顺序。"""
    priority = 2
    try:
        db = SessionLocal()
        t = db.get(Task, task_id)
        mode = (t.audit_mode or "") if t is not None else ""
        priority = 0 if mode == "poc" else (1 if mode == "full" else 2)
        db.close()
    except Exception:
        priority = 2
    task_queue.put((priority, next(_queue_seq), int(task_id)))
