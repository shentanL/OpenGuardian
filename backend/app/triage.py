"""置信度分级处置引擎。

2026 共识：不可逆操作需人工确认，低置信度操作不执行。
将检测结果映射为四种处置策略：

- AUTO      (≥95%)  自动处置 + 通知
- SUGGEST   (70-95%) 建议处置 + 一键确认
- EVIDENCE  (40-70%) 展示证据 + 人工判断
- REPORT    (<40%)   仅报告，不提供处置按钮
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .agents.verifier import VerifiedRisk, Verdict
from .schemas import RiskItem, RiskLevel


class ActionTier(str, Enum):
    AUTO = "auto"          # 自动处置 + 通知
    SUGGEST = "suggest"    # 建议处置 + 一键确认
    EVIDENCE = "evidence"  # 展示证据 + 人工判断
    REPORT = "report"      # 仅报告，不提供处置


@dataclass
class TriageResult:
    """处置决策结果。"""
    risk: RiskItem
    tier: ActionTier
    confidence: float                    # 综合置信度 0-1
    evidence_chain: list[str] = field(default_factory=list)  # 可解释证据链
    auto_reason: str = ""                # 为什么自动处置 / 为什么不自动处置
    suggested_action: str = ""           # 建议操作（面向用户）
    can_execute: bool = False            # 前端是否显示处置按钮


class TriageEngine:
    """置信度分级处置引擎。

    评估维度（加权）：
    - 特征库匹配强度（特征是否精确命中？通配符还是精确子串？）
    - Verifier 验证结果（CONFIRMED > UNCERTAIN > REFUTED）
    - 风险等级（CRITICAL > HIGH > MEDIUM > LOW）
    - 数字签名状态（无签名 > 未知签名 > 受信任签名）
    - 历史行为（首次出现 > 已出现多次被验证安全）
    - 进程树可疑度（被 Office 启动的 cmd > 正常启动链）
    """

    # 权重配置
    WEIGHTS = {
        "verdict": 0.35,       # Verifier 判定
        "risk_level": 0.25,    # 风险等级
        "signature": 0.20,     # 数字签名
        "history": 0.15,       # 历史行为
        "process_tree": 0.05,  # 进程树
    }

    def evaluate(
        self,
        verified: VerifiedRisk,
        deep_inspect: dict | None = None,
    ) -> TriageResult:
        """评估单个风险项，返回处置决策。"""
        risk = verified.risk
        inspect = deep_inspect or {}

        # 1) 各维度打分 (0-1)
        scores: dict[str, float] = {
            "verdict": self._score_verdict(verified.verdict, verified.confidence),
            "risk_level": self._score_level(risk.level),
            "signature": self._score_signature(inspect),
            "history": self._score_history(inspect),
            "process_tree": self._score_tree(inspect),
        }

        # 2) 加权综合置信度
        confidence = sum(
            scores[k] * self.WEIGHTS[k] for k in self.WEIGHTS
        )

        # 3) 证据链（可解释 AI）
        evidence = self._build_evidence(risk, verified, inspect)

        # 4) 分级
        if confidence >= 0.95:
            tier = ActionTier.AUTO
            can_execute = True
        elif confidence >= 0.70:
            tier = ActionTier.SUGGEST
            can_execute = True
        elif confidence >= 0.40:
            tier = ActionTier.EVIDENCE
            can_execute = risk.pid is not None  # 有 PID 才能处置
        else:
            tier = ActionTier.REPORT
            can_execute = False

        # 5) 生成建议操作
        action = self._suggest_action(risk, tier, inspect)

        return TriageResult(
            risk=risk,
            tier=tier,
            confidence=round(confidence, 3),
            evidence_chain=evidence,
            auto_reason=self._tier_reason(tier, scores),
            suggested_action=action,
            can_execute=can_execute,
        )

    # ─── 各维度评分 ───

    @staticmethod
    def _score_verdict(verdict: Verdict, confidence: float) -> float:
        """Verifier 结果 → 分数。"""
        return {
            Verdict.CONFIRMED: min(1.0, confidence + 0.1),
            Verdict.BENIGN_VARIANT: max(0.2, confidence - 0.2),
            Verdict.UNCERTAIN: 0.5,
            Verdict.REFUTED: max(0.0, confidence - 0.5),
        }.get(verdict, 0.5)

    @staticmethod
    def _score_level(level: RiskLevel) -> float:
        return {
            RiskLevel.CRITICAL: 1.0,
            RiskLevel.HIGH: 0.85,
            RiskLevel.MEDIUM: 0.55,
            RiskLevel.LOW: 0.2,
        }.get(level, 0.3)

    @staticmethod
    def _score_signature(inspect: dict) -> float:
        sig = inspect.get("check_signature", {})
        if not sig:
            return 0.5
        if sig.get("trusted"):
            return 0.05  # 受信任签名 → 大概率误报
        if sig.get("signed"):
            return 0.3  # 有签名但非知名厂商
        if sig.get("signed") is False:
            return 0.9  # 无签名 → 高风险
        return 0.5

    @staticmethod
    def _score_history(inspect: dict) -> float:
        tree = inspect.get("process_tree", {})
        if not tree:
            return 0.5
        ancestors = tree.get("ancestors", [])
        if not ancestors:
            return 0.5
        parent = ancestors[0].get("name", "").lower() if ancestors else ""
        # 可疑父子关系
        suspicious_parents = {"cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"}
        if parent in suspicious_parents:
            return 0.8
        return 0.3

    @staticmethod
    def _score_tree(inspect: dict) -> float:
        tree = inspect.get("process_tree", {})
        suspicious = tree.get("suspicious", [])
        return min(1.0, len(suspicious) * 0.25)

    # ─── 证据链构建 ───

    @staticmethod
    def _build_evidence(risk: RiskItem, verified: VerifiedRisk, inspect: dict) -> list[str]:
        """构建可解释证据链。"""
        chain: list[str] = []

        # 检测发现
        chain.append(f"检测发现：{risk.name} — {risk.detail[:80]}")

        # Verifier 判定
        chain.append(f"验证结果：{verified.verdict.value}（{verified.evidence[:100]}）")

        # 数字签名
        sig = inspect.get("check_signature", {})
        if sig:
            signer = sig.get("signer") or "无"
            chain.append(
                f"数字签名：{'✓ ' + signer if sig.get('trusted') else '✗ ' + signer if signer != '无' else '✗ 无签名'}"
            )

        # 进程树
        tree = inspect.get("process_tree", {})
        ancestors = tree.get("ancestors", [])
        if ancestors:
            parent = ancestors[0]
            chain.append(f"父进程：{parent['name']} (PID {parent['pid']})")
        if tree.get("suspicious"):
            chain.append(f"可疑模式：{'; '.join(tree['suspicious'][:2])}")

        # 网络
        net = inspect.get("network_profile", {})
        if net and net.get("connection_count", 0) > 0:
            chain.append(f"网络连接：{net['connection_count']} 个，{net.get('suspicious_connections', 0)} 个可疑")

        # 熵值
        ent = inspect.get("entropy_check", {})
        if ent.get("suspicious"):
            chain.append(f"文件熵值：{ent.get('entropy')}（偏高——可能加壳）")

        return chain

    # ─── 建议操作 ───

    @staticmethod
    def _suggest_action(risk: RiskItem, tier: ActionTier, inspect: dict) -> str:
        """生成面向用户的操作建议。"""
        pid = risk.pid
        name = risk.name

        if tier == ActionTier.AUTO:
            if pid:
                return f"已自动隔离 {name}（PID {pid}）"
            return f"已自动处理 {name}"
        elif tier == ActionTier.SUGGEST:
            if pid:
                return f"建议结束进程 {name}（PID {pid}），点击下方按钮确认"
            return risk.suggestion or f"建议按指南修复 {name}"
        elif tier == ActionTier.EVIDENCE:
            return (
                f"{name} 存在可疑特征，但证据不足以自动处置。"
                "请查看上方证据链后自行判断"
            )
        else:
            return f"{name} 风险较低，建议保持观察"

    @staticmethod
    def _tier_reason(tier: ActionTier, scores: dict) -> str:
        """解释为什么是这个处置等级。"""
        weaknesses = []
        if scores.get("signature", 0) < 0.3:
            weaknesses.append("有受信任数字签名")
        if scores.get("history", 0) < 0.3:
            weaknesses.append("历史记录正常")
        if scores.get("verdict", 1) < 0.5:
            weaknesses.append("验证结果不确定")

        if tier in (ActionTier.AUTO, ActionTier.SUGGEST):
            strengths = []
            if scores.get("risk_level", 0) > 0.8:
                strengths.append("风险等级高")
            if scores.get("signature", 0) > 0.7:
                strengths.append("无有效数字签名")
            return "处置原因：" + ("、".join(strengths) if strengths else "综合评估")
        else:
            return "暂不处置：" + ("、".join(weaknesses) if weaknesses else "风险较低")


# 全局单例
_triage_engine: TriageEngine | None = None


def get_triage() -> TriageEngine:
    global _triage_engine
    if _triage_engine is None:
        _triage_engine = TriageEngine()
    return _triage_engine
