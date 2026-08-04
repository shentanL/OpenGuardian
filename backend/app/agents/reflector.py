"""反思 Agent（Reflector）：检测后自审计。

在每次检测完成后，Reflector 会问：
1. 覆盖完整性——所有检测模块都跑了吗？有没有跳过的？
2. 边界信号——有没有差一点就到阈值的高风险信号？
3. 历史对比——和上次检测相比，有没有新出现的可疑项？
4. 质量自评——这次检测的可信度有多高？

输出检测质量报告，补充可能遗漏的风险。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

import psutil

from ..db import Database
from ..schemas import RiskItem, RiskLevel

logger = logging.getLogger(__name__)


@dataclass
class ReflectReport:
    """反思报告。"""
    coverage_score: float = 1.0        # 覆盖完整性 0-1
    modules_checked: list[str] = field(default_factory=list)
    modules_skipped: list[str] = field(default_factory=list)
    borderline_signals: list[dict] = field(default_factory=list)  # 边界信号
    new_vs_last_scan: list[dict] = field(default_factory=list)     # 与上次对比
    missed_risks: list[RiskItem] = field(default_factory=list)     # 补充发现的风险
    quality_note: str = ""              # 质量自评一句话


class ReflectorAgent:
    """反思 Agent：检测后自审计。"""

    name = "reflect"
    description = "检测后自审计：覆盖完整性、边界信号、历史对比、质量自评"

    # ─── 所有应被覆盖的检测模块 ───
    EXPECTED_MODULES = [
        "process", "network", "resource",
        "vuln", "defender", "updates", "services",
    ]

    def __init__(self, db: Database | None = None) -> None:
        self._db = db

    def reflect(
        self,
        scanned_modules: list[str],
        risks: list[RiskItem],
        system_context: dict | None = None,
    ) -> ReflectReport:
        """执行反思审计。"""
        report = ReflectReport()

        # 1) 覆盖完整性
        scanned_set = set(scanned_modules)
        expected_set = set(self.EXPECTED_MODULES)
        report.modules_checked = list(scanned_set)
        report.modules_skipped = list(expected_set - scanned_set)
        report.coverage_score = len(scanned_set) / len(expected_set) if expected_set else 1.0

        if report.modules_skipped:
            logger.info("Reflector: 未检测模块 %s", report.modules_skipped)

        # 2) 边界信号检测（实时采样，不依赖 LLM）
        borderline = self._check_borderline()
        report.borderline_signals = borderline

        # 边界信号转 RiskItem
        for b in borderline:
            if b.get("severity", "low") in ("high", "medium"):
                report.missed_risks.append(RiskItem(
                    item_type="resource",
                    name=b.get("name", "系统资源"),
                    detail=b.get("detail", ""),
                    level=RiskLevel.MEDIUM if b.get("severity") == "medium" else RiskLevel.LOW,
                    suggestion=b.get("suggestion", "建议关注该指标的变化趋势"),
                ))

        # 3) 历史对比
        if self._db:
            history = self._db.get_scan_history(limit=2)
            if len(history) >= 2:
                prev = history[1]  # 上一次
                curr = history[0]  # 当前（刚写入）
                prev_names = set()
                for r in (prev.get("risks") or []):
                    prev_names.add((r.get("name") or "").lower())

                for r in risks:
                    name = (r.name or "").lower()
                    if name and name not in prev_names:
                        report.new_vs_last_scan.append({
                            "name": r.name,
                            "level": r.level.value,
                            "detail": r.detail[:80],
                            "note": "上次检测未出现此项",
                        })

        # 4) 质量自评
        high_risks = sum(1 for r in risks if r.level in (RiskLevel.HIGH, RiskLevel.CRITICAL))
        report.quality_note = (
            f"覆盖 {len(scanned_set)}/{len(expected_set)} 模块"
            + (f"，缺失 {report.modules_skipped}" if report.modules_skipped else "，全部覆盖")
            + f"，发现 {len(risks)} 项风险（{high_risks} 高危）"
            + f"，补充边界信号 {len(borderline)} 项"
        )

        logger.info("Reflector: %s", report.quality_note)
        return report

    @staticmethod
    def _check_borderline() -> list[dict]:
        """检查接近阈值但未超标的边界信号（纯确定性，不调 LLM）。"""
        signals: list[dict] = []
        try:
            cpu = psutil.cpu_percent(interval=0.3)
            mem = psutil.virtual_memory().percent
            disk = psutil.disk_usage("/").percent

            from ..config import settings

            # CPU 接近告警线（差 5% 以内）
            cpu_gap = settings.CPU_ALERT_PCT - cpu
            if 0 < cpu_gap <= 5:
                signals.append({
                    "name": "CPU",
                    "value": f"{cpu:.1f}%",
                    "threshold": f"{settings.CPU_ALERT_PCT:.0f}%",
                    "gap": f"{cpu_gap:.1f}%",
                    "detail": f"CPU 使用率 {cpu:.1f}%，距离告警阈值仅差 {cpu_gap:.1f}%",
                    "severity": "medium",
                    "suggestion": "关注 CPU 趋势，若持续上升可能是挖矿木马前兆",
                })

            # 内存接近告警线
            mem_gap = settings.MEM_ALERT_PCT - mem
            if 0 < mem_gap <= 5:
                signals.append({
                    "name": "内存",
                    "value": f"{mem:.1f}%",
                    "threshold": f"{settings.MEM_ALERT_PCT:.0f}%",
                    "gap": f"{mem_gap:.1f}%",
                    "detail": f"内存使用率 {mem:.1f}%，距离告警阈值仅差 {mem_gap:.1f}%",
                    "severity": "medium",
                    "suggestion": "检查是否有内存泄漏或异常进程",
                })

            # 磁盘 → 低优先级
            disk_gap = settings.DISK_ALERT_PCT - disk
            if 0 < disk_gap <= 5:
                signals.append({
                    "name": "磁盘",
                    "value": f"{disk:.1f}%",
                    "threshold": f"{settings.DISK_ALERT_PCT:.0f}%",
                    "gap": f"{disk_gap:.1f}%",
                    "detail": f"磁盘使用率 {disk:.1f}%，接近告警阈值",
                    "severity": "low",
                    "suggestion": "建议清理临时文件，释放磁盘空间",
                })

        except Exception as exc:
            logger.debug("Reflector borderline check failed: %s", exc)

        return signals


_reflector: ReflectorAgent | None = None


def get_reflector(db: Database | None = None) -> ReflectorAgent:
    global _reflector
    if _reflector is None:
        _reflector = ReflectorAgent(db)
    return _reflector
