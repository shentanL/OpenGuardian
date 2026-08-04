"""攻击链可视化 —— 将风险列表转化为可视化的 ATT&CK 战术链条。

借鉴: Unclecheng-li/DeepSec 的 Attack Chain Visualization
输出: TTP 链条文本 + SVG 图
"""

from __future__ import annotations

from ..kb.attack_map import ATTACK_MAP

# ATT&CK 战术阶段顺序（按攻击生命周期）
TACTIC_ORDER = [
    ("TA0001", "Initial Access", "初始访问"),
    ("TA0002", "Execution", "执行"),
    ("TA0003", "Persistence", "持久化"),
    ("TA0004", "Privilege Escalation", "提权"),
    ("TA0005", "Defense Evasion", "防御规避"),
    ("TA0006", "Credential Access", "凭据获取"),
    ("TA0007", "Discovery", "发现"),
    ("TA0008", "Lateral Movement", "横向移动"),
    ("TA0011", "Command and Control", "命令控制"),
    ("TA0010", "Exfiltration", "数据渗出"),
    ("TA0040", "Impact", "影响"),
]


def build_attack_chain(risks: list[dict]) -> list[dict]:
    """从风险列表构建攻击链。

    Returns:
        [{"tactic_id": "TA0005", "tactic_name": "Defense Evasion",
          "techniques": [{"id": "T1562.001", "name": "Disable Tools", "risk": "Defender未启用"}]}]
    """
    chain: dict[str, dict] = {}

    for r in risks:
        item_type = r.get("item_type", "")
        attack = ATTACK_MAP.get(item_type, {})
        tactic = attack.get("tactic", {})
        technique = attack.get("technique", {})
        tid = tactic.get("id", "")
        tname = tactic.get("name", "")

        if not tid:
            continue

        if tid not in chain:
            chain[tid] = {
                "tactic_id": tid,
                "tactic_name": tname,
                "techniques": [],
            }

        tech_id = technique.get("sub") or technique.get("id", "")
        tech_name = technique.get("name", "")
        existing = [t for t in chain[tid]["techniques"] if t["id"] == tech_id]
        if existing:
            existing[0]["risks"].append(r.get("name", ""))
        else:
            chain[tid]["techniques"].append({
                "id": tech_id,
                "name": tech_name,
                "risks": [r.get("name", "")],
            })

    # 按 ATT&CK 战术生命周期排序
    ordered = []
    for tid, tname, tcn in TACTIC_ORDER:
        if tid in chain:
            ordered.append(chain[tid])

    return ordered


def chain_to_text(chain: list[dict]) -> str:
    """攻击链 → 文本叙述。"""
    if not chain:
        return "未识别到完整的攻击链模式。"

    lines = ["🔗 **攻击链分析** (MITRE ATT&CK 生命周期)\n"]
    for i, stage in enumerate(chain):
        tid = stage["tactic_id"]
        tname = stage["tactic_name"]
        tcn = dict(TACTIC_ORDER).get(tid, ("", "", ""))[2] or tname
        lines.append(f"  **{i+1}. {tid} {tcn}** ({tname})")

        for tech in stage["techniques"]:
            names = "、".join(tech["risks"][:3])
            lines.append(f"       ├─ {tech['id']} {tech['name']}")
            lines.append(f"       │  影响: {names}")

    return "\n".join(lines)


def chain_to_svg(chain: list[dict]) -> str:
    """攻击链 → 简易 SVG 流程图（1000×200）。"""
    if not chain:
        return '<svg xmlns="http://www.w3.org/2000/svg" width="400" height="40"><text x="10" y="25" fill="#757575" font-size="12">无攻击链数据</text></svg>'

    n = len(chain)
    w = max(800, n * 160)
    h = 180
    cx_step = min(140, (w - 160) // max(n, 1))
    cx0 = 80

    rects = []
    texts = []
    arrows = []

    for i, stage in enumerate(chain):
        x = cx0 + i * cx_step
        y = 30
        rw = 120
        rh = 120
        tname = stage["tactic_name"]
        tcn = dict(TACTIC_ORDER).get(stage["tactic_id"], ("", "", ""))[2] or tname

        rects.append(
            f'<rect x="{x}" y="{y}" width="{rw}" height="{rh}" rx="2" '
            f'fill="#0d0d0d" stroke="#76b900" stroke-width="2"/>'
        )
        texts.append(
            f'<text x="{x + 60}" y="{y + 24}" text-anchor="middle" fill="#76b900" font-size="10" font-family="monospace" font-weight="bold">{stage["tactic_id"]}</text>'
        )
        texts.append(
            f'<text x="{x + 60}" y="{y + 42}" text-anchor="middle" fill="#e0e0e0" font-size="11" font-family="sans-serif">{tcn}</text>'
        )

        # 技术列表
        ty = y + 58
        for j, tech in enumerate(stage["techniques"][:3]):
            texts.append(
                f'<text x="{x + 8}" y="{ty + j * 18}" fill="#a7a7a7" font-size="9" font-family="monospace">{tech["id"]}</text>'
            )

        # 箭头
        if i < n - 1:
            arrows.append(
                f'<line x1="{x + rw}" y1="{y + rh/2}" x2="{x + rw + (cx_step - rw)}" y2="{y + rh/2}" '
                f'stroke="#76b900" stroke-width="2" marker-end="url(#arrow)"/>'
            )

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">'
        f'<defs><marker id="arrow" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">'
        f'<polygon points="0 0, 10 3.5, 0 7" fill="#76b900"/></marker></defs>'
        f'{" ".join(rects)}{" ".join(texts)}{" ".join(arrows)}'
        f'</svg>'
    )
