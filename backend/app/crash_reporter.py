"""崩溃上报模块 —— 本地日志 + 可选 Sentry 集成。

设计：
- 始终写本地崩溃日志（%LOCALAPPDATA%\OpenGuardian\crashes\）
- Sentry DSN 可选（无需外部依赖，纯 httpx POST）
- 不收集 PII，仅含异常类型 + 堆栈 + 版本号
"""
from __future__ import annotations

import json
import logging
import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

CRASH_DIR = Path.home() / "AppData" / "Local" / "OpenGuardian" / "crashes"
MAX_CRASH_FILES = 20

SENTRY_DSN: Optional[str] = os.getenv("OG_SENTRY_DSN", "")


def capture_exception(exc: Optional[Exception] = None) -> str:
    """捕获并记录崩溃信息。

    返回 crash_id 用于用户反馈。
    """
    exc_type, exc_value, exc_tb = sys.exc_info()
    if exc is not None:
        exc_type = type(exc)
        exc_value = exc

    crash_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + f"-{os.getpid()}"
    crash_data = {
        "crash_id": crash_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "app_version": _get_version(),
        "platform": sys.platform,
        "python_version": sys.version,
        "exception_type": exc_type.__name__ if exc_type else "Unknown",
        "exception_message": str(exc_value)[:500] if exc_value else "",
        "traceback": traceback.format_exc()[:3000],
    }

    # 本地文件
    try:
        CRASH_DIR.mkdir(parents=True, exist_ok=True)
        crash_file = CRASH_DIR / f"crash-{crash_id}.json"
        crash_file.write_text(json.dumps(crash_data, ensure_ascii=False, indent=2),
                              encoding="utf-8")
        _rotate_files()
    except Exception:
        pass

    # Sentry（可选）
    if SENTRY_DSN:
        try:
            _send_sentry(crash_data)
        except Exception:
            pass

    return crash_id


def _get_version() -> str:
    try:
        from .config import settings
        return settings.APP_VERSION
    except Exception:
        return "unknown"


def _rotate_files() -> None:
    """保留最近 MAX_CRASH_FILES 个崩溃日志。"""
    try:
        files = sorted(CRASH_DIR.glob("crash-*.json"), reverse=True)
        for f in files[MAX_CRASH_FILES:]:
            f.unlink(missing_ok=True)
    except Exception:
        pass


def _send_sentry(data: dict) -> None:
    """向 Sentry 发送崩溃事件（Sentry 兼容协议）。"""
    import httpx

    sentry_payload = {
        "event_id": data["crash_id"],
        "timestamp": data["timestamp"],
        "level": "error",
        "platform": "python",
        "exception": {
            "values": [{
                "type": data["exception_type"],
                "value": data["exception_message"],
                "stacktrace": {"frames": []},
            }],
        },
        "tags": {
            "app_version": data["app_version"],
            "platform": data["platform"],
        },
    }
    project_id = SENTRY_DSN.split("/")[-1] if SENTRY_DSN else ""
    if not project_id:
        return
    try:
        httpx.post(
            f"{SENTRY_DSN.rsplit('/', 1)[0]}/api/{project_id}/store/",
            json=sentry_payload,
            timeout=5,
        )
    except Exception:
        pass


def get_recent_crashes(limit: int = 5) -> list[dict]:
    """获取最近的崩溃日志（供诊断面板使用）。"""
    try:
        files = sorted(CRASH_DIR.glob("crash-*.json"), reverse=True)[:limit]
        return [json.loads(f.read_text(encoding="utf-8")) for f in files]
    except Exception:
        return []
