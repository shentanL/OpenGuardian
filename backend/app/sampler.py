"""后台资源采样器：定时记录 CPU/内存/磁盘快照。

让资源趋势图拥有连续数据（不依赖用户触发检测），并支撑实时监控。
使用单守护线程 + while 循环（避免 threading.Timer 每次创建新线程）。
"""
from __future__ import annotations

import logging
import threading

import psutil

logger = logging.getLogger(__name__)


class ResourceSampler:
    """每 interval 秒采样一次资源状态写入 SQLite（单守护线程）。"""

    def __init__(self, db, interval: float = 10.0) -> None:
        self._db = db
        self._interval = max(interval, 2.0)  # 最小 2 秒，防止过于频繁
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stopping.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="resource-sampler")
        self._thread.start()
        logger.info("资源采样器启动（每 %.0fs，单守护线程）", self._interval)

    def _run(self) -> None:
        while not self._stopping.is_set():
            try:
                cpu = psutil.cpu_percent(interval=0.2)
                mem = psutil.virtual_memory().percent
                disk = psutil.disk_usage("C:\\").percent
                self._db.add_resource_sample(cpu, mem, disk)
                logger.debug("资源采样: CPU %.1f%% MEM %.1f%% DISK %.1f%%", cpu, mem, disk)
            except Exception as exc:  # noqa: BLE001
                logger.warning("资源采样失败: %s", exc)
            self._stopping.wait(self._interval)

    def stop(self) -> None:
        self._stopping.set()
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None
        logger.info("资源采样器停止")
