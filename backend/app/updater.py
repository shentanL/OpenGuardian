"""自动更新模块 —— 启动时检查 GitHub Releases，提示用户下载更新。

设计：
- 非阻塞后台检查（不延迟启动）
- 仅提示，不强制（用户手动下载安装）
- 缓存检查结果（24h 内不重复检查）
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

CACHE_FILE = Path.home() / "AppData" / "Local" / "OpenGuardian" / ".update_cache.json"
CHECK_INTERVAL = 86400  # 24 小时
GITHUB_API = "https://api.github.com/repos/OpenGuardian/OpenGuardian/releases/latest"

_current_version: str = "0.6.0"


def set_current_version(version: str) -> None:
    global _current_version
    _current_version = version


def _load_cache() -> dict:
    try:
        if CACHE_FILE.exists():
            return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _save_cache(data: dict) -> None:
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def check_update() -> Optional[dict]:
    """同步检查更新（应在后台线程中调用）。

    返回 None = 无更新，dict = 有新版本 {version, url, body, size_mb}
    """
    cache = _load_cache()
    last_check = cache.get("last_check", 0)
    if time.time() - last_check < CHECK_INTERVAL:
        cached_result = cache.get("latest")
        if cached_result and _is_newer(cached_result.get("version", ""), _current_version):
            return cached_result
        return None

    try:
        import httpx

        with httpx.Client(timeout=10) as client:
            resp = client.get(GITHUB_API, headers={"Accept": "application/vnd.github+json",
                                                    "User-Agent": "OpenGuardian-UpdateCheck/1.0"})
            if resp.status_code != 200:
                cache["last_check"] = time.time()
                _save_cache(cache)
                return None

            data = resp.json()
            tag = data.get("tag_name", "").lstrip("v")
            html_url = data.get("html_url", "")
            body = (data.get("body") or "")[:300]
            assets = data.get("assets", [])
            setup_asset = next((a for a in assets if a["name"].endswith("Setup.exe")), None)
            download_url = setup_asset["browser_download_url"] if setup_asset else html_url
            size_mb = round(setup_asset["size"] / 1024 / 1024, 1) if setup_asset else None

            result = {
                "version": tag,
                "url": download_url,
                "body": body,
                "size_mb": size_mb,
                "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }

            cache["last_check"] = time.time()
            if _is_newer(tag, _current_version):
                cache["latest"] = result
            else:
                cache.pop("latest", None)
            _save_cache(cache)

            if _is_newer(tag, _current_version):
                logger.info("发现新版本 v%s（当前 v%s）", tag, _current_version)
                return result

    except Exception as exc:
        logger.debug("更新检查失败: %s", exc)

    return None


def _is_newer(new: str, current: str) -> bool:
    """简单语义版本比较。"""
    try:
        new_parts = [int(x) for x in new.split(".")]
        cur_parts = [int(x) for x in current.split(".")]
        # 补齐长度
        while len(new_parts) < 3:
            new_parts.append(0)
        while len(cur_parts) < 3:
            cur_parts.append(0)
        return new_parts > cur_parts
    except (ValueError, AttributeError):
        return new != current  # 非语义版本直接比较字符串
