"""开源规则包加载器（gosec 7 条 + njsscan 21 条；平台侧最小实现）。"""
import hashlib
import os
from pathlib import Path

DATA = Path(__file__).resolve().parent / "rule_pack_data"
# 哈希按仓库 LF 归一化后的文件计算；.gitattributes 固定 eol=lf
OPENSOURCE = (
    (DATA / "opensource-gosec.yml", "0dd5e30dea4e1f7bbd69f28f044263e46d2b6664d98729f8a1ee2a021490d095"),
    (DATA / "opensource-njsscan.yml", "dfd3996a5418dbf04ac24f57a56048c8abf55238fe5b1808832264df600180c1"),
)
VALID_MODES = ("off", "test", "extended")


def mode():
    value = os.environ.get("AUDIT_RULE_PACKS_MODE", "off").strip().lower()
    return value if value in VALID_MODES else "off"


def _verified(path, expected):
    if not path.is_file():
        return False, "缺少 %s，已 fail-closed" % path.name
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        return False, "%s sha256 不匹配，已 fail-closed" % path.name
    return True, ""


def selected_configs():
    current = mode()
    if current == "off":
        return [], "rule_packs mode=off"
    if current == "extended":
        return [], "rule_packs mode=extended 未配置，fail-closed"
    configs = []
    for path, expected in OPENSOURCE:
        ok, why = _verified(path, expected)
        if not ok:
            return [], "rule_packs " + why
        configs.append(str(path))
    return configs, "rule_packs mode=test，加载 opensource 28 条（gosec 7/njsscan 21）"


def status():
    configs, note = selected_configs()
    return {"mode": mode(), "configs": configs, "note": note}
