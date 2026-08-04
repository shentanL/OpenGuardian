"""威胁情报主动汲取器 — 兼容性包装。

已迁移至 ingestion.py（增强摄入管道：多源 + 增量 + 归一化 + 去重 + 定时）。
保留此模块以兼容旧调用。
"""
from __future__ import annotations

import logging

from .ingestion import (
    ingestion_stats as kb_stats,
    run_ingestion as update_knowledge,
    start_background_ingestion as start_background_update,
    force_refresh,
)

logger = logging.getLogger(__name__)

__all__ = ["update_knowledge", "start_background_update", "kb_stats", "force_refresh"]

