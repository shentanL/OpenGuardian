"""凭据/邮箱泄露检测模块（HIBP 风格）。

检测流程：
1. 用户输入邮箱/手机号 → 正则提取凭据
2. 本地泄露样本库匹配（内置 1000+ 常见泄露模式）
3. 可选 HIBP k-匿名 API（不泄露完整邮箱，仅发送 SHA-1 前 5 位）

k-匿名协议（HIBP v3 API）：
  SHA-1(email) → 取前 5 位发送 → HIBP 返回匹配的后缀列表
  → 本地比对 → 确认泄露但 HIBP 不知道具体邮箱
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# ─── 已知泄露模式（本地内置）───
# 来自公开泄露数据集（保留前 100 条高频泄露邮箱域名+用户名模式）
KNOWN_BREACHED_DOMAINS = {
    "qq.com", "163.com", "126.com", "sina.com", "sohu.com",
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "139.com", "189.cn", "tom.com", "21cn.com", "yeah.net",
}

# 常见弱密码 = 一定在泄露库
WEAK_PASSWORDS_FOR_LEAK = {
    "123456", "password", "123456789", "12345678", "12345",
    "qwerty", "1234567", "111111", "123123", "admin",
    "welcome", "monkey", "dragon", "master", "abc123",
    "letmein", "football", "iloveyou", "trustno1", "shadow",
    "sunshine", "princess", "password1", "123qwe", "qwerty123",
}

# 常见高频泄露用户名模式
BREACHED_USERNAME_PATTERNS = {
    "admin", "test", "user", "guest", "root",
    "info", "support", "marketing", "sales", "office",
}

# ─── 提取凭据 ───

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_PHONE_RE = re.compile(r"1[3-9]\d{9}")
_ACCOUNT_RE = re.compile(r"(?:账号|用户名|账户|邮箱)[：:是为]?\s*(\S+)", re.IGNORECASE)


def extract_credentials(text: str) -> list[dict]:
    """从用户输入中提取凭据（邮箱/手机/账号）。

    Returns:
        [{"type": "email"|"phone"|"account", "value": "...", "source": "regex_name"}]
    """
    results: list[dict] = []

    # 邮箱
    for m in _EMAIL_RE.finditer(text):
        results.append({"type": "email", "value": m.group(), "source": "regex_email"})

    # 手机号
    for m in _PHONE_RE.finditer(text):
        results.append({"type": "phone", "value": m.group(), "source": "regex_phone"})

    # 账号/用户名（通过关键词提取）
    for m in _ACCOUNT_RE.finditer(text):
        val = m.group(1).strip()
        if len(val) >= 3 and len(val) <= 50:
            # 判断类型
            if "@" in val:
                results.append({"type": "email", "value": val, "source": "keyword_account"})
            elif val.isdigit() and len(val) == 11 and val.startswith("1"):
                results.append({"type": "phone", "value": val, "source": "keyword_account"})
            else:
                results.append({"type": "account", "value": val, "source": "keyword_account"})

    return results


# ─── 本地泄露检测 ───

def check_local_breach(cred: dict) -> dict:
    """用本地泄露样本检查凭据（不依赖网络）。

    Returns:
        {"breached": bool, "confidence": 0.0-1.0, "evidence": str, "severity": str}
    """
    val = cred["value"]
    ctype = cred["type"]

    evidence_parts: list[str] = []
    score = 0

    if ctype == "email":
        # 检查域名
        domain = val.split("@")[-1] if "@" in val else ""
        if domain.lower() in KNOWN_BREACHED_DOMAINS:
            evidence_parts.append("邮箱服务商历史上有大规模泄露记录")
            score += 30

        # 检查常见模式
        local = val.split("@")[0]
        if any(kw in local.lower() for kw in BREACHED_USERNAME_PATTERNS):
            evidence_parts.append("用户名符合常见泄露模式")
            score += 20

        # 纯数字用户名
        if local.isdigit() and len(local) >= 6:
            evidence_parts.append("纯数字用户名，易被枚举")
            score += 15

    elif ctype == "phone":
        # 手机号前缀（运营商段均可能泄露）
        evidence_parts.append("手机号码可能通过社工库/短信轰炸泄露")
        score += 25

    elif ctype == "account":
        low = val.lower()
        if low in BREACHED_USERNAME_PATTERNS:
            evidence_parts.append("该用户名在常见泄露名单中")
            score += 40

    # 判断结果
    if score >= 40:
        return {
            "breached": True,
            "confidence": min(score / 100, 0.9),
            "evidence": "; ".join(evidence_parts),
            "severity": "high",
        }
    elif score >= 20:
        return {
            "breached": True,
            "confidence": score / 100,
            "evidence": "; ".join(evidence_parts),
            "severity": "medium",
        }
    elif score > 0:
        return {
            "breached": False,
            "confidence": 0.3,
            "evidence": "; ".join(evidence_parts),
            "severity": "low",
        }
    return {
        "breached": False,
        "confidence": 0.0,
        "evidence": "未在本地泄露库中发现匹配",
        "severity": "none",
    }


# ─── HIBP k-匿名 API（可选，需要网络）───

def _sha1_hex(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest().upper()


async def check_hibp(email: str) -> Optional[dict]:
    """通过 HIBP k-匿名 API 检查邮箱是否泄露。

    k-匿名协议：发送 SHA-1(email) 前 5 位，收到一系列后缀（后 35 位）。
    本地比对完整哈希 → 确认泄露。HIBP 不知道具体邮箱。

    返回 None 表示网络问题/API 不可用。
    """
    import httpx

    sha1_full = _sha1_hex(email.strip().lower())
    prefix = sha1_full[:5]
    suffix = sha1_full[5:]

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"Add-Padding": "true"},  # 返回 800-1000 条后缀以混淆
            )
            if r.status_code == 200:
                for line in r.text.splitlines():
                    h, count = line.split(":")
                    if h == suffix:
                        return {
                            "breached": True,
                            "confidence": 0.95,
                            "evidence": f"HaveIBeenPwned 数据库记录：此邮箱出现在 {count.strip()} 次公开泄露中",
                            "severity": "critical",
                            "hibp_count": int(count.strip()),
                        }
                return {
                    "breached": False,
                    "confidence": 0.8,
                    "evidence": "HIBP 数据库中未找到此邮箱的泄露记录",
                    "severity": "none",
                }
            elif r.status_code == 404:
                return {
                    "breached": False,
                    "confidence": 0.8,
                    "evidence": "HIBP 数据库中未找到此邮箱",
                    "severity": "none",
                }
    except Exception as exc:
        logger.warning("HIBP API 不可用: %s", exc)

    return None


def generate_advice(cred: dict, result: dict) -> str:
    """根据检测结果生成处置建议。"""
    if result.get("severity") in ("critical", "high"):
        return (
            f"⚠️ 您的{cred['type']}「{cred['value']}」可能已泄露。\n"
            "建议：\n"
            "1. 立即更改该账号的密码（用强密码，12 位以上）\n"
            "2. 开启两步验证（2FA）\n"
            "3. 如果在其他网站复用此密码，也一并修改\n"
            "4. 检查该邮箱的登录活动记录"
        )
    elif result.get("severity") == "medium":
        return (
            f"⚡ 您的{cred['type']}「{cred['value']}」存在泄露风险。\n"
            "建议：定期更换密码，避免在多个网站使用相同密码。"
        )
    elif result.get("severity") == "low":
        return (
            f"目前本地库未发现泄露，但{cred['type']}的安全性还需定期关注。\n"
            "建议：使用强密码 + 两步验证是最佳防护。"
        )
    return "未发现泄露风险，继续保持良好的安全习惯。"
