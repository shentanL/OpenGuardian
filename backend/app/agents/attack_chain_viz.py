"""攻击链可视化 —— 将风险列表转化为可视化的 ATT&CK 战术链条。

借鉴: Unclecheng-li/DeepSec 的 Attack Chain Visualization
输出: TTP 链条文本
"""

from __future__ import annotations

from ..kb.attack_map import ATTACK_MAP

# ATT&CK 战术阶段顺序 + 中文名
_TACTIC_CN = {
    "TA0001": "初始访问", "TA0002": "执行", "TA0003": "持久化",
    "TA0004": "提权", "TA0005": "防御规避", "TA0006": "凭据获取",
    "TA0007": "发现", "TA0008": "横向移动",
    "TA0011": "命令控制", "TA0010": "数据渗出", "TA0040": "影响",
}
_TACTIC_ORDER = [
    "TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
    "TA0006", "TA0007", "TA0008", "TA0011", "TA0010", "TA0040",
]


def build_attack_chain(risks: list[dict]) -> list[dict]:
    """从风险列表构建有序攻击链。"""
    chain: dict[str, dict] = {}
    for r in risks:
        item_type = r.get("item_type", "")
        attack = ATTACK_MAP.get(item_type, {})
        tactic = attack.get("tactic", {})
        technique = attack.get("technique", {})
        tid = tactic.get("id", "")
        if not tid or tid == "TA9999":
            continue
        if tid not in chain:
            chain[tid] = {"tactic_id": tid, "techniques": []}
        tech_sub = technique.get("sub", "") or technique.get("id", "")
        existing = [t for t in chain[tid]["techniques"] if t["id"] == tech_sub]
        if existing:
            existing[0]["risks"].append(r.get("name", ""))
        else:
            chain[tid]["techniques"].append({
                "id": tech_sub, "risks": [r.get("name", "")],
            })
    ordered = []
    for tid in _TACTIC_ORDER:
        if tid in chain:
            ordered.append(chain[tid])
    return ordered


def chain_to_text(chain: list[dict]) -> str:
    """攻击链 → 文本叙述。"""
    if not chain:
        return "未识别到完整的攻击链模式。"
    lines = ["🔗 **攻击链分析** (MITRE ATT&CK)\n"]
    for i, stage in enumerate(chain):
        tid = stage["tactic_id"]
        tcn = _TACTIC_CN.get(tid, tid)
        lines.append(f"  {i+1}. **{tid} {tcn}**")
        for tech in stage["techniques"]:
            names = "、".join(tech["risks"][:3])
            lines.append(f"      {tech['id']} → {names}")
    return "\n".join(lines)
