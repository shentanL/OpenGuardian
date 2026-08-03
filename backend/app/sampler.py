"""后台资源采样器：定时记录 CPU/内存/磁盘快照。

让资源趋势图拥有连续数据（不依赖用户触发检测），并支撑实时监控。
"""
from __future__ import annotations

import logging
import threading

import psutil

logger = logging.getLogger(__name__)


class ResourceSampler:
    """每 interval 秒采样一次资源状态写入 SQLite。"""

    def __init__(self, db, interval: float = 30.0) -> None:
        self._db = db
        self._interval = interval
        self._timer: threading.Timer | None = None
        self._stopping = threading.Event()

    def start(self) -> None:
        self._stopping.clear()
        self._schedule()
        logger.info("资源采样器启动（每 %.0fs）", self._interval)

    def _schedule(self) -> None:
        if self._stopping.is_set():
            return
        self._timer = threading.Timer(self._interval, self._tick)
        self._timer.daemon = True
        self._timer.start()

    def _tick(self) -> None:
        try:
            cpu = psutil.cpu_percent(interval=0.2)
            mem = psutil.virtual_memory().percent
            disk = psutil.disk_usage(".").percent
            self._db.add_resource_sample(cpu, mem, disk)
            logger.debug("资源采样: CPU %.1f%% MEM %.1f%% DISK %.1f%%", cpu, mem, disk)
        except Exception as exc:  # noqa: BLE001
            logger.warning("资源采样失败: %s", exc)
        self._schedule()

    def stop(self) -> None:
        self._stopping.set()
        if self._timer:
            self._timer.cancel()
            self._timer = None
        logger.info("资源采样器停止")
