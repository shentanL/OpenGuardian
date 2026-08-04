"""LLM 离线智能降级系统 —— 当 AI API 不可用时的智能回复引擎。

不是简单的"AI 不可用请重试"——而是用规则引擎 + 模板 + 检索来生成有意义的回复。
"""
from __future__ import annotations

import logging
import random
from typing import Optional

logger = logging.getLogger(__name__)

# ─── 智能回复模板 ───

CONSULT_TEMPLATES = {
    "什么是": {
        "patterns": ["什么是", "是什么", "啥是", "啥叫"],
        "replies": [
            "「{topic}」是信息安全里的一个基础概念。说人话就是：{explain}。\n\n想深入了解的话，等 AI 服务恢复后我可以用更多案例帮你理解～",
            "这个问题问得好！「{topic}」简单来说就是 {explain}。\n\n不过我现在处于离线模式，回答可能不够详细。AI 服务恢复后可以给你更完整的讲解。",
        ],
    },
    "怎么办": {
        "patterns": ["怎么办", "如何", "怎么", "怎样"],
        "replies": [
            "遇到「{topic}」的问题，基本思路是这样的：\n\n1. 先不要慌——很多安全问题都有标准解法\n2. 告诉我更多细节（比如你看到了什么提示、什么时候开始的）\n3. 我可以给你一步步的操作指南\n\n现在 AI 服务暂时不可用，但基础的检测功能还是可以用的。要不要先让我帮你的电脑做个体检？",
        ],
    },
    "安全吗": {
        "patterns": ["安全吗", "可靠吗", "会不会", "有没有风险"],
        "replies": [
            "关于「{topic}」安不安全——我给个通用的判断方法：\n\n✅ 下载渠道是否官方？\n✅ 有没有数字签名？\n✅ 打开后有没有异常行为（弹窗/CPU 飙升/自动联网）？\n\n这三个全绿，基本安全。当然最准确的办法还是让我帮你扫描一下——检测功能不依赖 AI，随时可以用。",
        ],
    },
    "钓鱼|诈骗": {
        "patterns": ["钓鱼", "诈骗", "骗子", "冒充"],
        "replies": [
            "识别「{topic}」的核心原则就三条：\n\n🚫 不轻信——任何索要密码、验证码、转账要求的都先打电话核实\n🚫 不点击——陌生链接、附件、二维码一律不点\n🚫 不裸奔——重要账号开启两步验证\n\n记住：官方客服永远不会要你的密码和验证码。",
        ],
    },
    "default": {
        "patterns": [],
        "replies": [
            "我理解你想了解「{topic}」——不过现在 AI 服务暂时不可用，我的回答可能不够全面。\n\n但别担心——检测功能完全不受影响。你可以：\n· 说「检测电脑」让我帮你扫描\n· 说「检查密码 xxx」看密码够不够强\n· 说「讲讲钓鱼邮件」学习安全知识",
        ],
    },
}


DETECT_REPLIES = [
    "检测引擎正在全速运转中——这个功能不依赖 AI，靠的是本地规则库、病毒哈希、行为分析三层把关。结果准确度不受 AI 离线影响。",
    "电脑扫描开始了！虽然 AI 不在线，但检测引擎完全独立运转——进程扫描、网络分析、漏洞检查一个不少。",
]


def smart_reply(user_input: str, intent: str = "consult") -> str:
    """根据用户输入和意图生成智能降级回复。

    规则引擎分层：
    1. 精确模式匹配 → 填充模板
    2. 关键词触发 → 最匹配的模板
    3. 默认兜底 → 引导使用离线可用的功能
    """
    topic = _extract_topic(user_input)
    explain = _lookup_explain(topic)

    if intent == "detect":
        return random.choice(DETECT_REPLIES)

    # 查找最佳匹配模板
    for key, entry in CONSULT_TEMPLATES.items():
        if key == "default":
            continue
        for pat in entry["patterns"]:
            if pat in user_input:
                reply = random.choice(entry["replies"])
                return reply.format(topic=topic, explain=explain)

    # 默认
    entry = CONSULT_TEMPLATES["default"]
    return random.choice(entry["replies"]).format(topic=topic, explain=explain)


def _extract_topic(text: str) -> str:
    """从用户输入中提取讨论主题。"""
    # 去掉常见引导词
    for prefix in ["什么是", "啥是", "啥叫", "什么叫", "怎么办", "如何", "怎么",
                   "帮我", "请", "能不能", "可以", "我想", "讲解", "解释一下",
                   "介绍一下", "说说"]:
        text = text.replace(prefix, "")
    text = text.replace("？", "").replace("?", "").strip()
    return text[:30] or "这个话题"


def _lookup_explain(topic: str) -> str:
    """从知识库查找解释。"""
    try:
        from ..kb.glossary import explain_terms
        items = explain_terms(topic, limit=2)
        if items:
            return items[0].get("plain", "")[:100]
    except Exception:
        pass
    return "涉及计算机系统、网络通信或数据保护的内容"
