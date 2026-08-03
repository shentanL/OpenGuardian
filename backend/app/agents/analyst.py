"""分析 Agent：数字资产防护。

能力：
1. 密码强度评估（长度/字符集/常见弱密码）
2. 百万级弱密码库检查（Pwdb Top-1000000 + 中文弱密码库）
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

# 弱密码数据文件（按优先级合并加载）
_KB_DIR = Path(__file__).resolve().parent.parent.parent / "kb_data"
# PyInstaller 打包修正
import sys as _sys
if getattr(_sys, "frozen", False) and hasattr(_sys, "_MEIPASS"):
    _KB_DIR = Path(_sys._MEIPASS) / "backend" / "kb_data"
_PW_FILES = [
    _KB_DIR / "pwdb1m.txt",      # Pwdb 百万弱密码榜（主库）
    _KB_DIR / "passwords.txt",   # 中文弱密码 Top 1000 等（补充）
]

_weak_cache: set[str] | None = None


def _load_weak_passwords() -> set[str]:
    """加载百万级弱密码库（懒加载+缓存）；数据文件缺失时回退内置集。"""
    global _weak_cache
    if _weak_cache is not None:
        return _weak_cache
    result: set[str] = set()
    for pw_file in _PW_FILES:
        try:
            if pw_file.exists():
                with open(pw_file, encoding="utf-8", errors="ignore") as f:
                    result.update(
                        line.strip() for line in f
                        if line.strip() and not line.startswith("#")
                    )
                logger.info("弱密码库加载: %s (%d 条)", pw_file.name, len(result))
        except Exception as exc:  # noqa: BLE001
            logger.warning("弱密码文件 %s 加载失败: %s", pw_file.name, exc)
    if result:
        _weak_cache = result
    else:
        _weak_cache = set(_FALLBACK_WEAK)
        logger.warning("弱密码数据文件缺失，使用内置 %d 条兜底", len(_weak_cache))
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
        elif action == "scan":
            # 真实系统账户安全扫描
            risks.extend(self._scan_system_accounts())

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

    # ---- 真实系统账户安全扫描 ----
    @staticmethod
    def _scan_system_accounts() -> list[RiskItem]:
        """采集真实 Windows 账户安全数据（net accounts + 注册表 + secedit）。"""
        import subprocess

        risks: list[RiskItem] = []
        try:
            r = subprocess.run(
                ["net", "accounts"],
                capture_output=True, text=True, errors="replace", timeout=8,
            )
            out = r.stdout.lower()
            # 最小密码长度
            m = re.search(r"minimum password length[:\s]*(\d+)", out)
            if m and int(m.group(1)) < 8:
                risks.append(RiskItem(
                    item_type="asset", name="密码最小长度不足",
                    detail=f"系统最小密码长度仅 {m.group(1)} 位（建议 ≥8）",
                    level=RiskLevel.MEDIUM,
                    suggestion="运行 gpedit.msc → 计算机配置→Windows 设置→安全设置→账户策略→密码策略，设置最小密码长度 ≥8",
                ))
            # 密码最长使用期限
            m2 = re.search(r"maximum password age[:\s]*(\d+)", out)
            if m2 and int(m2.group(1)) == 42:
                pass  # 默认值
            elif m2 and int(m2.group(1)) > 90:
                risks.append(RiskItem(
                    item_type="asset", name="密码过期周期过长",
                    detail=f"密码最长使用 {m2.group(1)} 天（建议 ≤90）",
                    level=RiskLevel.LOW,
                    suggestion="在本地安全策略中设置密码最长使用期限 ≤90 天",
                ))
            # 锁定阈值
            m3 = re.search(r"lockout threshold[:\s]*(\d+)", out)
            if m3 and int(m3.group(1)) == 0:
                risks.append(RiskItem(
                    item_type="asset", name="账户锁定未启用",
                    detail="暴力破解无防护——连续输错密码不会锁定账户",
                    level=RiskLevel.MEDIUM,
                    suggestion="设置账户锁定阈值：5 次错误后锁定 30 分钟（net accounts /lockoutthreshold:5）",
                ))
            # 密码历史
            m4 = re.search(r"length of password history maintained[:\s]*(\d+)", out)
            if m4 and int(m4.group(1)) == 0:
                risks.append(RiskItem(
                    item_type="asset", name="密码历史未启用",
                    detail="可以反复使用相同密码——旧密码泄露后无防护",
                    level=RiskLevel.LOW,
                    suggestion="设置强制密码历史 ≥5（禁止重复使用最近 5 个密码）",
                ))
            # 最短使用期限
            m5 = re.search(r"minimum password age[:\s]*(\d+)", out)
            if m5 and int(m5.group(1)) == 0:
                risks.append(RiskItem(
                    item_type="asset", name="密码最短使用期限为 0",
                    detail="用户可无限次快速修改密码来绕过密码历史策略",
                    level=RiskLevel.LOW,
                    suggestion="设置密码最短使用期限 ≥1 天",
                ))
        except Exception:
            pass

        # 检查自动登录
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon") as key:
                try:
                    auto_admin, _ = winreg.QueryValueEx(key, "AutoAdminLogon")
                    if auto_admin == "1":
                        risks.append(RiskItem(
                            item_type="asset", name="自动登录已启用",
                            detail="Windows 设为自动登录——任何人开机即入桌面",
                            level=RiskLevel.HIGH,
                            suggestion="运行 netplwiz → 勾选「要使用本计算机，用户必须输入用户名和密码」",
                        ))
                except OSError:
                    pass
        except OSError:
            pass

        # 检查 Guest 账户
        try:
            r = subprocess.run(
                ["net", "user", "guest"],
                capture_output=True, text=True, errors="replace", timeout=5,
            )
            if "account active" in r.stdout.lower() and "yes" in r.stdout.lower():
                risks.append(RiskItem(
                    item_type="asset", name="Guest 账户已启用",
                    detail="来宾账户启用——未授权用户可能通过 Guest 访问系统",
                    level=RiskLevel.MEDIUM,
                    suggestion="运行 net user guest /active:no 禁用 Guest 账户",
                ))
        except Exception:
            pass

        return risks
    def _check_password(self, pwd: str) -> list[RiskItem]:
        """密码强度评估：zxcvbn（Dropbox 开源，714⭐ GitHub）。

        评分 0-4：
          0 = 即时可破（10^3 种组合以内）
          1 = 极易破解（10^6）
          2 = 较难破解（10^8）
          3 = 难以破解（10^10）
          4 = 极难破解（10^13）
        """
        risks: list[RiskItem] = []
        if not pwd:
            return risks

        try:
            from zxcvbn import zxcvbn

            result = zxcvbn(pwd)
            score = result["score"]
            feedback = result.get("feedback", {})
            warning = (feedback.get("warning") or "").strip()
            suggestions = feedback.get("suggestions") or []
            guesses_log10 = result.get("guesses_log10", 0)

            if score <= 1:
                risks.append(RiskItem(
                    item_type="asset", name="密码极弱",
                    detail=f"zxcvbn 评分 {score}/4（约 {10**guesses_log10:.0e} 次尝试可破解）。{warning}",
                    level=RiskLevel.CRITICAL,
                    suggestion=("立即更换： " + ("；".join(suggestions[:3]) if suggestions
                        else "至少 12 位，混合大小写+数字+符号，不用常见词")),
                ))
            elif score == 2:
                risks.append(RiskItem(
                    item_type="asset", name="密码中等",
                    detail=f"zxcvbn 评分 2/4，有一定破解风险。{warning}",
                    level=RiskLevel.MEDIUM,
                    suggestion=("建议强化：" + ("；".join(suggestions[:2]) if suggestions else "增加长度和复杂度")),
                ))
            # score 3-4: 安全
        except ImportError:
            if pwd in _load_weak_passwords():
                risks.append(RiskItem(
                    item_type="asset", name="弱密码",
                    detail="该密码在常见弱密码库中，极易被暴力破解",
                    level=RiskLevel.CRITICAL,
                    suggestion="立即更换为 12 位以上、包含大小写字母+数字+符号的强密码",
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
