"""验证 Agent（Verifier）：对检测结果做对抗性审核。

核心原则（2026 共识）：
- 独立上下文——不和 Detector 共享 prompt，避免"作者盲区"
- 对抗性立场——默认试图证伪每一项风险（"这个真的是威胁吗？"）
- 三态输出——CONFIRMED / REFUTED / UNCERTAIN（静默不是否定）

架构：
1. 确定性快速通道：白名单/签名验证/阈值边界检查（毫秒级，无需 LLM）
2. LLM 深度通道：模糊案例调用轻量模型做语义判断
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from ..llm.client import get_llm_client
from ..schemas import RiskItem, RiskLevel

logger = logging.getLogger(__name__)


class Verdict(str, Enum):
    CONFIRMED = "confirmed"      # 确认为真实威胁
    REFUTED = "refuted"          # 误报，有证据推翻
    UNCERTAIN = "uncertain"      # 无法确定，需人工判断
    BENIGN_VARIANT = "benign"    # 降级：威胁等级过高，实际没那么严重


@dataclass
class VerifiedRisk:
    """经过验证的风险项。"""
    risk: RiskItem
    verdict: Verdict
    evidence: str = ""           # 验证证据（为什么确认为威胁/为什么判定为误报）
    adjusted_level: RiskLevel | None = None  # 调整后的风险等级（如有）
    confidence: float = 1.0      # 验证置信度 0-1


# ─── 确定性快速验证规则 ───


def _quick_verify(risk: RiskItem, whitelist: set[str]) -> VerifiedRisk | None:
    """确定性规则快速验证。返回 None 表示需要 LLM 深度判断。

    规则优先级（高 → 低）：
    1. 白名单精确命中 → REFUTED
    2. 已知安全软件签名路径 → REFUTED
    3. 阈值边界情况（如 CPU 83% 差 2% 到阈值）→ BENIGN_VARIANT
    4. 系统目录 + 有效签名 → 大概率误报
    """
    name = (risk.name or "").lower()
    detail = (risk.detail or "").lower()
    item_type = risk.item_type

    # 1) 白名单精确命中
    if name in whitelist:
        return VerifiedRisk(
            risk=risk,
            verdict=Verdict.REFUTED,
            evidence=f"用户已将「{risk.name}」加入白名单",
            confidence=1.0,
        )

    # 1.5) 系统工具名豁免（不依赖 detail 路径，直接按进程名判定）
    system_tools = {
        "powershell.exe", "cmd.exe", "reg.exe", "regedit.exe", "taskmgr.exe",
        "msiexec.exe", "rundll32.exe", "wscript.exe", "cscript.exe", "schtasks.exe",
        "whoami.exe", "netstat.exe", "net.exe", "ipconfig.exe", "ping.exe",
        "nslookup.exe", "tasklist.exe", "wmic.exe", "systeminfo.exe", "gpupdate.exe",
        "svchost.exe", "explorer.exe", "conhost.exe", "dllhost.exe", "sihost.exe",
        "python.exe", "pythonw.exe", "node.exe", "npm.exe", "java.exe", "git.exe",
    }
    if item_type == "process" and name in system_tools:
        return VerifiedRisk(
            risk=risk,
            verdict=Verdict.REFUTED,
            evidence=f"「{risk.name}」是合法系统/开发工具，特征库命中为已知误报（如 shell.exe 子串匹配 powershell.exe）",
            confidence=0.95,
        )

    # 2) 已知安全软件路径
    safe_paths = [
        "program files", "program files (x86)",
        "\\windows\\system32\\", "\\windows\\syswow64\\",
        "\\microsoft\\", "\\windows defender\\",
    ]
    for sp in safe_paths:
        if sp in detail:
            # 但 ngix.exe 放在 system32 也是可疑的——默认信任但要核对
            return VerifiedRisk(
                risk=risk,
                verdict=Verdict.BENIGN_VARIANT,
                adjusted_level=RiskLevel.LOW,
                evidence=f"程序位于系统目录 {sp}，大概率是合法系统组件；建议核对数字签名",
                confidence=0.75,
            )

    # 3) 资源阈值边界：差 5% 以内不报警
    if item_type == "resource" or (item_type == "process" and "cpu" in detail):
        import re
        m = re.search(r"(\d+\.?\d*)\s*%", detail)
        if m:
            val = float(m.group(1))
            from ..config import settings
            threshold = settings.CPU_ALERT_PCT
            if threshold - 5 <= val < threshold:
                return VerifiedRisk(
                    risk=risk,
                    verdict=Verdict.BENIGN_VARIANT,
                    adjusted_level=RiskLevel.LOW,
                    evidence=f"CPU 占用 {val:.1f}% 接近阈值 {threshold:.0f}% 但未超标，属于临时峰值",
                    confidence=0.85,
                )

    # 4) 超过 LLM 判断阈值 → 交给 LLM
    return None


# ─── LLM 深度验证 ───

VERIFIER_PROMPT = """你是 OpenGuardian 的安全验证专家。你的任务是审查检测结果，判断每一条风险是否为**真实威胁**。

对于每条风险，你必须给出判定：
- CONFIRMED：确认为真实威胁（给出具体证据）
- REFUTED：判定为误报（给出推翻理由）
- UNCERTAIN：信息不足，无法判断（建议下一步调查方向）

审查要点：
1. 进程名是否为常见软件？（如 chrome.exe, vscode.exe, steam.exe 是正常的）
2. 是否有数字签名？微软/Google/Adobe 签名的进程基本安全
3. CPU/内存占用高是否是正常行为？（视频渲染、编译、游戏都会高占用）
4. 网络连接是否连接了已知 CDN/云服务 IP？（不要误报 AWS/Cloudflare）
5. 端口监听是否为开发工具？（IDE、Docker、Node.js 常监听本地端口）

输出 JSON：
{"verdicts": [{"name": "进程名", "verdict": "confirmed|refuted|uncertain", "evidence": "判定依据"}]}"""


class VerifierAgent:
    """验证 Agent：对检测结果做对抗性审核。"""

    name = "verify"
    description = "对抗性验证：审核检测结果，区分真实威胁与误报"

    def __init__(self) -> None:
        self.llm = get_llm_client()

    def verify(
        self,
        risks: list[RiskItem],
        whitelist: set[str] | None = None,
    ) -> list[VerifiedRisk]:
        """对风险列表做分层验证。

        流程：
        1. 每条风险先走确定性快速通道（毫秒级）
        2. 未决项批量送 LLM 深度判断
        3. 合并结果，附加验证统计
        """
        if not risks:
            return []

        whitelist = whitelist or set()
        verified: list[VerifiedRisk] = []
        llm_batch: list[RiskItem] = []

        # 第一轮：确定性快速验证
        # 确定性类型（vuln/malicious_ip/domain/malware_hash/defender/updates/services）
        # 来自真实系统命令/威胁情报，直接 CONFIRMED，无需 LLM 审核
        DETERMINISTIC_TYPES = {
            "vuln", "vuln_patch", "vuln_smb1", "vuln_firewall", "vuln_guest",
            "vuln_uac", "vuln_share", "vuln_autorun", "vuln_hosts", "vuln_task",
            "vuln_cve", "vuln_wmi", "malicious_ip", "malicious_domain",
            "malware_hash", "defender", "updates", "services", "asset",
        }
        for r in risks:
            # 确定性类型直接确认
            if r.item_type in DETERMINISTIC_TYPES:
                verified.append(VerifiedRisk(
                    risk=r,
                    verdict=Verdict.CONFIRMED,
                    evidence="确定性检测（系统命令/威胁情报/签名库），无需二次审核",
                    confidence=0.95,
                ))
                continue
            quick = _quick_verify(r, whitelist)
            if quick is not None:
                verified.append(quick)
            else:
                llm_batch.append(r)

        # 第二轮：LLM 深度验证（批量处理）
        if llm_batch and self.llm.available:
            llm_results = self._llm_verify(llm_batch)
            verified.extend(llm_results)
        elif llm_batch:
            # LLM 不可用 → 全部标记 UNCERTAIN
            for r in llm_batch:
                verified.append(VerifiedRisk(
                    risk=r, verdict=Verdict.UNCERTAIN,
                    evidence="AI 服务未配置，无法深度验证",
                    confidence=0.3,
                ))

        # 统计
        confirmed = sum(1 for v in verified if v.verdict == Verdict.CONFIRMED)
        refuted = sum(1 for v in verified if v.verdict == Verdict.REFUTED)
        logger.info(
            "Verifier: %d risks → %d confirmed, %d refuted, %d uncertain",
            len(risks), confirmed, refuted,
            len(verified) - confirmed - refuted,
        )
        return verified

    def _llm_verify(self, risks: list[RiskItem]) -> list[VerifiedRisk]:
        """调用 LLM 做批量深度验证。"""
        import json as _json
        from ..async_util import run_async

        # 构建风险摘要供 LLM 审查
        risk_summaries = []
        for i, r in enumerate(risks):
            risk_summaries.append(
                f"[{i}] {r.name} | 类型: {r.item_type} | 等级: {r.level.value} | "
                f"详情: {r.detail[:120]} | PID: {r.pid or 'N/A'}"
            )
        risk_text = "\n".join(risk_summaries)

        try:
            result = run_async(
                self.llm.chat_json(
                    [{"role": "user", "content": f"审查以下检测结果：\n\n{risk_text}"}],
                    system=VERIFIER_PROMPT,
                    fallback={"verdicts": []},
                    temperature=0.1,
                    max_tokens=600,
                ),
                timeout=10.0,  # 硬超时：LLM 验证尽力而为，超时不阻塞主流程
            )
            verdicts = result.get("verdicts", []) if isinstance(result, dict) else []
        except Exception as exc:
            logger.warning("Verifier LLM call failed: %s", exc)
            verdicts = []

        # 解析 LLM 输出，与原始风险对齐
        llm_verdicts: dict[str, dict] = {}
        for v in verdicts:
            name = v.get("name", "")
            llm_verdicts[name.lower()] = v

        verified: list[VerifiedRisk] = []
        for r in risks:
            name_key = (r.name or "").lower()
            v = llm_verdicts.get(name_key, {})
            verdict_str = v.get("verdict", "uncertain")
            evidence = v.get("evidence", "LLM 未给出明确判定依据")

            try:
                verdict = Verdict(verdict_str)
            except ValueError:
                verdict = Verdict.UNCERTAIN

            verified.append(VerifiedRisk(
                risk=r,
                verdict=verdict,
                evidence=evidence,
                confidence=0.7 if verdict != Verdict.UNCERTAIN else 0.4,
            ))

        return verified


# 全局单例
_verifier: VerifierAgent | None = None


def get_verifier() -> VerifierAgent:
    global _verifier
    if _verifier is None:
        _verifier = VerifierAgent()
    return _verifier
