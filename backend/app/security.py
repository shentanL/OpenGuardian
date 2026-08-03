"""电脑安全系数评估 + 面向小白的加固方案。

评分算法（透明、可解释）：
- 基础分 100
- 每项风险扣分：严重 20 / 高危 15 / 中危 10 / 低危 5
- 威胁情报命中（恶意 IP/域名）额外扣 10（代表外部攻击面）
- 等级：优 ≥85 / 良 70-84 / 中 50-69 / 差 <50

加固方案：按风险类别生成"人话"行动项，小白也能照做。
"""
from __future__ import annotations

# 等级定义
LEVEL_PENALTY = {"critical": 20, "high": 15, "medium": 10, "low": 5}
THREAT_INTEL_TYPES = {"malicious_ip", "malicious_domain"}


def assess_security(risks: list[dict] | None) -> dict:
    """根据最近一次检测的风险列表计算安全系数与加固建议。

    risks: 检测风险项列表（[{item_type, name, detail, level, suggestion, pid}]）
    返回: {score, grade, label, suggestions: [{icon, text}]}
    """
    risks = risks or []
    score = 100
    threat_hits = 0
    seen_suggestions: set[str] = set()
    suggestions: list[dict] = []

    for r in risks:
        lv = str(r.get("level", "low")).lower()
        score -= LEVEL_PENALTY.get(lv, 5)
        itype = str(r.get("item_type", "process")).lower()
        name = r.get("name") or r.get("process") or r.get("item") or "未知程序"
        pid = r.get("pid")
        detail = r.get("detail") or ""

        if itype in THREAT_INTEL_TYPES:
            threat_hits += 1
            score -= 10
            sug = (
                f"电脑正在连接恶意地址「{name}」——立即断开网络，"
                f"运行安全检测结束相关进程，近期不要在这台电脑上登录网银或社交账号"
            )
        elif itype == "process":
            pid_txt = f"（PID {pid}）" if pid else ""
            sug = (
                f"发现可疑程序「{name}」{pid_txt}：在安全助手中发送「结束进程 {pid or name}」，"
                f"或打开任务管理器找到它手动结束，然后全盘查杀"
            )
        elif itype == "port":
            sug = (
                f"发现可疑监听端口「{name}」：检查是哪个程序在监听，"
                f"不认识的程序请结束它，并关闭电脑的远程桌面/远程协助功能"
            )
        elif itype == "resource":
            sug = (
                f"程序「{name}」占用资源异常：{detail}。如果它不是你在用的软件，"
                f"大概率是挖矿或恶意程序，请结束并查杀"
            )
        elif itype == "asset":
            sug = (
                f"密码安全提醒：{detail}。把重要账号密码改成「大写+小写+数字+符号」组合，"
                f"每个网站用不同密码，生日和 123456 这类千万别用"
            )
        elif itype == "network":
            sug = (
                f"检测到外部连接「{name}」：确认是否为你主动使用的软件（如游戏、更新），"
                f"不是的话建议留意并结束该程序"
            )
        else:
            sug = f"发现「{name}」风险：{detail}。建议按检测报告中的处置建议操作"

        if sug not in seen_suggestions:
            seen_suggestions.add(sug)
            suggestions.append({"icon": itype, "text": sug})

    # 无风险时给通用加固建议（小白也能做的 4 件事）
    if not risks:
        suggestions = [
            {"icon": "update", "text": "保持系统更新：打开 Windows 设置 → 更新和安全 → 检查更新，让系统补丁保持最新"},
            {"icon": "firewall", "text": "确认防火墙已开启：Windows 安全中心 → 防火墙和网络保护 → 确认三个网络都显示绿色"},
            {"icon": "password", "text": "重要账号启用双重验证（短信/验证器 App），密码别用生日、手机号、123456"},
            {"icon": "phishing", "text": "警惕陌生链接和附件：任何要求转账、验证码、扫码的「客服」都是骗子"},
            {"icon": "backup", "text": "重要文件定期备份到移动硬盘或云盘，防止勒索病毒加密后无法恢复"},
        ]

    score = max(0, min(100, score))
    if score >= 85:
        grade, label = "excellent", "优"
    elif score >= 70:
        grade, label = "good", "良"
    elif score >= 50:
        grade, label = "medium", "中"
    else:
        grade, label = "poor", "差"

    return {
        "score": score,
        "grade": grade,
        "label": label,
        "risk_count": len(risks),
        "threat_hits": threat_hits,
        "suggestions": suggestions[:6],
    }
