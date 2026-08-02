"""分析 Agent：数字资产防护（MVP 简化版）。

能力：
1. 密码强度评估（长度/字符集/常见弱密码）
2. 常见弱密码库检查（从 kb_data/passwords.txt 加载，1479+ 条）
3. 提供加固建议
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from ..schemas import AgentResult, AgentTask, RiskItem, RiskLevel
from .base import BaseAgent

logger = logging.getLogger(__name__)

# 内嵌兜底弱密码（数据文件缺失时使用）
_FALLBACK_WEAK = {
    "123456", "password", "12345678", "qwerty", "abc123",
    "111111", "123123", "admin", "letmein", "welcome",
    "1234567890", "password1", "iloveyou", "1q2w3e4r",
    "000000", "123456789", "666666", "88888888", "a123456",
}

_PW_FILE = Path(__file__).resolve().parent.parent.parent / "kb_data" / "passwords.txt"

_weak_cache: set[str] | None = None


def _load_weak_passwords() -> set[str]:
    """加载弱密码库（带缓存）；数据文件缺失时回退内置集。"""
    global _weak_cache
    if _weak_cache is not None:
        return _weak_cache
    try:
        if _PW_FILE.exists():
            with open(_PW_FILE, encoding="utf-8") as f:
                _weak_cache = {
                    line.strip() for line in f
                    if line.strip() and not line.startswith("#")
                }
            logger.info("弱密码库加载: %d 条（%s）", len(_weak_cache), _PW_FILE.name)
        else:
            _weak_cache = set(_FALLBACK_WEAK)
            logger.warning("弱密码数据文件缺失，使用内置 %d 条兜底", len(_weak_cache))
    except Exception as exc:  # noqa: BLE001
        logger.warning("弱密码库加载失败: %s，使用内置兜底", exc)
        _weak_cache = set(_FALLBACK_WEAK)
    return _weak_cache

# 常见危险习惯关键词（用于文本分析）
RISKY_KEYWORDS = [
    ("密码写在桌面/记事本", "明文保存密码，一旦电脑被入侵所有账号都会泄露"),
    ("所有网站用同一个密码", "一个网站泄露=所有账号沦陷"),
    ("自动登录", "自动登录会绕过二次验证，设备丢失即账号失守"),
]


class AnalystAgent(BaseAgent):
    name = "asset"
    description = "数字资产防护：密码强度评估与安全习惯分析"

    def handle(self, task: AgentTask) -> AgentResult:
        action = task.params.get("action", "password")
        risks: list[RiskItem] = []

        if action == "password":
            pwd = str(task.params.get("password", ""))
            risks.extend(self._check_password(pwd))
        elif action == "habit":
            text = str(task.params.get("text", ""))
            risks.extend(self._check_habits(text))

        if not risks:
            return AgentResult(
                agent=self.name,
                success=True,
                message="未发现明显的资产风险，继续保持！",
                risks=[],
            )
        return AgentResult(
            agent=self.name,
            success=True,
            message=f"发现 {len(risks)} 项资产风险，请按建议加固",
            risks=risks,
        )

    # ---- 密码强度 ----
    def _check_password(self, pwd: str) -> list[RiskItem]:
        risks: list[RiskItem] = []
        if not pwd:
            return risks
        if pwd in _load_weak_passwords():
            risks.append(RiskItem(
                item_type="asset",
                name="弱密码",
                detail="该密码在常见弱密码库（含中文弱密码 Top 1000）中，极易被暴力破解",
                level=RiskLevel.CRITICAL,
                suggestion="立即更换为 12 位以上、包含大小写字母+数字+符号的强密码",
            ))
            return risks

        length = len(pwd)
        has_lower = bool(re.search(r"[a-z]", pwd))
        has_upper = bool(re.search(r"[A-Z]", pwd))
        has_digit = bool(re.search(r"\d", pwd))
        has_symbol = bool(re.search(r"[^A-Za-z0-9]", pwd))
        score = sum([has_lower, has_upper, has_digit, has_symbol])

        if length < 8:
            risks.append(RiskItem(
                item_type="asset",
                name="密码过短",
                detail=f"长度仅 {length} 位（建议 ≥12 位）",
                level=RiskLevel.HIGH,
                suggestion="加长密码：用一句只有你知道的话的首字母+数字+符号组合",
            ))
        if length < 12 and score >= 3:
            risks.append(RiskItem(
                item_type="asset",
                name="密码强度一般",
                detail=f"{length} 位，字符类型 {score}/4 种",
                level=RiskLevel.MEDIUM,
                suggestion="建议增加到 12 位以上，混合大小写、数字和符号",
            ))
        if score <= 1 and length >= 12:
            risks.append(RiskItem(
                item_type="asset",
                name="密码类型单一",
                detail="只用了 1 种字符类型，容易被字典攻击",
                level=RiskLevel.MEDIUM,
                suggestion="在密码中加入大小写字母、数字和符号的混合",
            ))
        if not risks:
            risks.append(RiskItem(
                item_type="asset",
                name="密码强度良好",
                detail=f"{length} 位，{score}/4 种字符类型",
                level=RiskLevel.LOW,
                suggestion="继续保持！建议为每个重要账号使用不同密码",
            ))
        return risks

    # ---- 安全习惯 ----
    def _check_habits(self, text: str) -> list[RiskItem]:
        risks: list[RiskItem] = []
        for keyword, desc in RISKY_KEYWORDS:
            if keyword in text:
                risks.append(RiskItem(
                    item_type="asset",
                    name=keyword,
                    detail=desc,
                    level=RiskLevel.MEDIUM,
                    suggestion="建议使用密码管理器（如 Bitwarden）统一保管密码",
                ))
        return risks
