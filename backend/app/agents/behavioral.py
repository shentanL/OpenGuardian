"""行为异常检测引擎 —— 基于进程行为基线的无监督异常检测。

不需要 ML 模型、不需要训练数据、不需要 GPU。

核心算法：
1. 建立"正常行为基线"（每个进程的 CPU/内存/网络/子进程模式）
2. 新观测值与基线比较 → 计算偏离度得分
3. 偏离度 > 阈值 → 标记为异常

参考：CrowdStrike 的 Indicators of Attack (IoA) 方法论，但用纯统计实现。
"""
from __future__ import annotations

import json
import logging
import threading
from collections import defaultdict
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class ProcessBaseline:
    """单个进程的行为基线。"""

    __slots__ = ("name", "avg_cpu", "max_cpu", "avg_mem", "max_mem",
                 "avg_children", "max_children", "usual_network_ports",
                 "usual_parent", "sample_count", "first_seen", "last_seen")

    def __init__(self, name: str):
        self.name = name
        self.avg_cpu = 0.0
        self.max_cpu = 0.0
        self.avg_mem = 0.0
        self.max_mem = 0.0
        self.avg_children = 0.0
        self.max_children = 0
        self.usual_network_ports: set[int] = set()
        self.usual_parent = ""
        self.sample_count = 0
        self.first_seen = ""
        self.last_seen = ""

    def update(self, cpu: float, mem: float, children: int,
               network_ports: set[int], parent: str, timestamp: str) -> None:
        """增量更新基线（指数移动平均）。"""
        alpha = 0.1  # EMA 平滑因子
        if self.sample_count == 0:
            self.avg_cpu = cpu
            self.avg_mem = mem
            self.avg_children = float(children)
            self.first_seen = timestamp
        else:
            self.avg_cpu = alpha * cpu + (1 - alpha) * self.avg_cpu
            self.avg_mem = alpha * mem + (1 - alpha) * self.avg_mem
            self.avg_children = alpha * children + (1 - alpha) * self.avg_children

        self.max_cpu = max(self.max_cpu, cpu)
        self.max_mem = max(self.max_mem, mem)
        self.max_children = max(self.max_children, children)
        self.usual_network_ports.update(network_ports)
        if parent:
            self.usual_parent = parent
        self.sample_count += 1
        self.last_seen = timestamp


class BehavioralEngine:
    """行为异常检测引擎。

    使用方法：
        engine = BehavioralEngine()
        engine.update_baseline(process_snapshot)   # 持续更新基线
        anomalies = engine.check(process_snapshot)  # 检查是否异常
    """

    def __init__(self, min_samples_for_baseline: int = 5):
        self._baselines: dict[str, ProcessBaseline] = {}
        self._lock = threading.Lock()
        self._min_samples = min_samples_for_baseline
        self._system_processes = {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
                                  "services.exe", "spoolsv.exe", "dwm.exe", "explorer.exe",
                                  "system", "idle", "registry", "memcompression"}

    def update_baseline(self, name: str, cpu: float, mem: float, children: int,
                        network_ports: set[int], parent: str, timestamp: str) -> None:
        with self._lock:
            if name not in self._baselines:
                self._baselines[name] = ProcessBaseline(name)
            self._baselines[name].update(cpu, mem, children, network_ports, parent, timestamp)

    def check(self, name: str, cpu: float, mem: float, children: int,
              network_ports: set[int], parent: str) -> Optional[dict]:
        """检查进程行为是否偏离基线。

        返回 None = 正常，dict = 异常详情。
        """
        with self._lock:
            baseline = self._baselines.get(name)
            if baseline is None or baseline.sample_count < self._min_samples:
                return None  # 基线不足，不判定

            flags: list[str] = []
            scores: list[float] = []

            # 1) CPU 异常：当前值 > 基线平均值 3 倍
            if baseline.avg_cpu > 1.0 and cpu > baseline.avg_cpu * 3:
                flags.append(f"CPU 异常飙升 {cpu:.1f}%（基线 {baseline.avg_cpu:.1f}%）")
                scores.append(min(1.0, (cpu - baseline.avg_cpu) / baseline.avg_cpu))

            # 2) 内存异常
            if baseline.avg_mem > 1.0 and mem > baseline.avg_mem * 3:
                flags.append(f"内存异常 {mem:.1f}%（基线 {baseline.avg_mem:.1f}%）")
                scores.append(min(1.0, (mem - baseline.avg_mem) / baseline.avg_mem))

            # 3) 子进程爆炸
            if baseline.avg_children > 0 and children > baseline.avg_children * 3 + 5:
                flags.append(f"子进程激增 {children} 个（基线 {baseline.avg_children:.0f} 个）")
                scores.append(0.7)

            # 4) 异常网络端口
            new_ports = network_ports - baseline.usual_network_ports
            suspicious = {p for p in new_ports if p in (4444, 5555, 6666, 1337, 31337, 12345)}
            if suspicious:
                flags.append(f"连接异常端口 {suspicious}")
                scores.append(0.9)

            # 5) 异常父进程
            if parent and baseline.usual_parent and parent != baseline.usual_parent:
                # svchost.exe 被 Office 启动 → 可疑
                if parent.lower() in {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}:
                    flags.append(f"办公软件 {parent} 启动了 {name}（疑似宏攻击）")
                    scores.append(0.95)

            if not flags:
                return None

            anomaly_score = min(1.0, sum(scores) / len(scores))
            return {
                "process": name,
                "anomaly_score": round(anomaly_score, 3),
                "flags": flags,
                "baseline_samples": baseline.sample_count,
                "severity": "critical" if anomaly_score > 0.8 else
                            "high" if anomaly_score > 0.6 else
                            "medium" if anomaly_score > 0.4 else "low",
            }

    def get_baseline_stats(self) -> dict:
        with self._lock:
            return {
                "total_processes": len(self._baselines),
                "mature_baselines": sum(1 for b in self._baselines.values()
                                        if b.sample_count >= self._min_samples),
            }


# 全局单例
_engine: Optional[BehavioralEngine] = None


def get_behavioral_engine() -> BehavioralEngine:
    global _engine
    if _engine is None:
        _engine = BehavioralEngine()
    return _engine
