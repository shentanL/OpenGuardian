"""MITRE ATT&CK 攻击链映射 —— 将检测到的风险项映射到攻击阶段。

帮助用户理解：攻击者是怎么进来的（初始入侵）→ 做了什么（持久化/横向移动）→ 要偷什么。
"""
from __future__ import annotations


# MITRE ATT&CK 战术 → 中文名 + 描述
TACTICS: dict[str, dict] = {
    "TA0001": {"name": "初始入侵", "en": "Initial Access",
               "desc": "攻击者如何进入你的系统——钓鱼邮件、漏洞利用、USB 投递等"},
    "TA0002": {"name": "执行", "en": "Execution",
               "desc": "攻击者在你的电脑上运行恶意代码"},
    "TA0003": {"name": "持久化", "en": "Persistence",
               "desc": "攻击者确保重启后或登出后仍然能控制你的电脑"},
    "TA0004": {"name": "权限提升", "en": "Privilege Escalation",
               "desc": "攻击者从普通用户升级到管理员权限"},
    "TA0005": {"name": "防御规避", "en": "Defense Evasion",
               "desc": "攻击者关闭杀毒软件、防火墙，隐藏自己的踪迹"},
    "TA0006": {"name": "凭据访问", "en": "Credential Access",
               "desc": "攻击者窃取你的密码、Token、Cookie"},
    "TA0007": {"name": "发现", "en": "Discovery",
               "desc": "攻击者摸清你的网络环境——有哪些机器、哪些共享文件夹"},
    "TA0008": {"name": "横向移动", "en": "Lateral Movement",
               "desc": "攻击者从一台机器跳到另一台——通常是内网传播"},
    "TA0009": {"name": "收集", "en": "Collection",
               "desc": "攻击者收集想要的数据——文档、数据库、邮件"},
    "TA0010": {"name": "数据窃取", "en": "Exfiltration",
               "desc": "攻击者把偷到的数据传出去"},
    "TA0011": {"name": "命令与控制", "en": "Command and Control",
               "desc": "被黑的电脑与攻击者的服务器保持通信，接收远程指令"},
    "TA0040": {"name": "影响", "en": "Impact",
               "desc": "攻击者破坏系统——加密文件（勒索）、删除数据、篡改网站"},
}

# 检测类型 → MITRE 战术映射
TYPE_TO_TACTIC: dict[str, list[str]] = {
    # 进程异常
    "process": ["TA0002", "TA0003"],
    "malware_hash": ["TA0002"],
    # 网络
    "network": ["TA0011", "TA0010"],
    "port": ["TA0011", "TA0007"],
    "malicious_ip": ["TA0011", "TA0010"],
    "malicious_domain": ["TA0011", "TA0010"],
    # 漏洞
    "vuln": ["TA0001"],
    "vuln_patch": ["TA0001"],
    "vuln_smb1": ["TA0001", "TA0008"],
    "vuln_firewall": ["TA0005"],
    "vuln_guest": ["TA0001"],
    "vuln_uac": ["TA0004"],
    "vuln_share": ["TA0007", "TA0008"],
    "vuln_autorun": ["TA0003", "TA0005"],
    "vuln_runonce": ["TA0003"],
    "vuln_task": ["TA0003"],
    "vuln_wmi": ["TA0003", "TA0005"],
    "vuln_hosts": ["TA0011", "TA0005"],
    # Defender
    "defender": ["TA0005"],
    # 资源
    "resource": ["TA0040"],
    # 账户
    "asset": ["TA0006"],
    # 更新
    "updates": ["TA0001"],
    "services": ["TA0007"],
}


def map_risks_to_attack_chain(risks: list[dict]) -> dict:
    """将风险列表映射到 MITRE ATT&CK 攻击链。

    返回: {tactic_id: {name, en, desc, risks: [...]}}
    """
    chains: dict[str, dict] = {}

    for r in risks:
        item_type = str(r.get("item_type", "")).lower()
        # 子类型归一化
        if item_type.startswith("vuln_"):
            lookup = item_type
        else:
            lookup = item_type

        tactic_ids = TYPE_TO_TACTIC.get(lookup, ["TA0002"])

        for tid in tactic_ids:
            if tid not in chains:
                info = TACTICS.get(tid, {"name": tid, "en": tid, "desc": ""})
                chains[tid] = {**info, "risks": []}
            chains[tid]["risks"].append({
                "name": r.get("name", "未知"),
                "level": r.get("level", "low"),
                "detail": r.get("detail", "")[:100],
            })

    # 按 ATT&CK 顺序排列
    ordered = {}
    for tid in sorted(TACTICS.keys()):
        if tid in chains:
            ordered[tid] = chains[tid]

    return ordered


def generate_attack_narrative(risks: list[dict]) -> str:
    """根据 ATT&CK 映射生成攻击链叙述。"""
    chains = map_risks_to_attack_chain(risks)
    if not chains:
        return ""

    lines = ["\n📊 攻击链分析（MITRE ATT&CK 映射）\n"]
    lines.append("下面把你的检测结果按攻击阶段排列，帮你理解攻击者的完整路径：\n")

    tactic_order = list(chains.keys())
    for i, (tid, info) in enumerate(chains.items()):
        arrow = " └─▶ " if i > 0 else "▶ "
        lines.append(f"{arrow}阶段 {i+1}：{info['name']} ({info['en']})")
        lines.append(f"    {info['desc']}")
        for risk in info["risks"]:
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
                risk["level"], "⚪")
            lines.append(f"    {icon} {risk['name']} — {risk['detail']}")

    # 总体评估
    covered_phases = len(chains)
    if covered_phases >= 5:
        lines.append(f"\n⚠️ 风险覆盖了攻击链的 {covered_phases} 个阶段，说明系统可能存在完整的攻击路径。建议从上到下逐阶段处置。")
    elif covered_phases >= 3:
        lines.append(f"\n⚡ 风险涉及 {covered_phases} 个攻击阶段，需重点关注早期阶段（初始入侵和持久化）。")
    else:
        lines.append(f"\n📌 风险集中在 {covered_phases} 个阶段，暂未形成完整攻击链。但不要忽视孤立风险。")

    return "\n".join(lines)
