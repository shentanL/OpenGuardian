"""病毒库：恶意软件哈希签名（ESET malware-ioc 真实威胁情报）。

- fetch_virus_hashes(): 从 GitHub ESET malware-ioc 仓库（codeload zip）
  提取全部恶意软件 SHA256（真实 APT/恶意家族样本），累积去重存
  kb_data/virus_hashes.txt
- load_virus_hashes(): 加载全部恶意哈希
- 检测器对运行中进程的可执行文件算 SHA256，命中即严重风险
"""
from __future__ import annotations

import hashlib
import io
import logging
import re
import time
import zipfile
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

KB_DIR = Path(__file__).resolve().parent.parent.parent / "kb_data"
# PyInstaller 打包修正
import sys as _sys
if getattr(_sys, "frozen", False) and hasattr(_sys, "_MEIPASS"):
    KB_DIR = Path(_sys._MEIPASS) / "backend" / "kb_data"
HASHES_FILE = KB_DIR / "virus_hashes.txt"

ESET_ZIP_URL = "https://codeload.github.com/eset/malware-ioc/zip/refs/heads/master"
TIMEOUT = 60

_SHA256_RE = re.compile(r"\b[0-9a-f]{64}\b")


def _read_existing() -> set[str]:
    if not HASHES_FILE.exists():
        return set()
    return {ln.strip().lower() for ln in HASHES_FILE.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.startswith("#") and len(ln.strip()) == 64}


def fetch_virus_hashes() -> dict:
    """拉取 ESET 威胁情报中的恶意软件哈希并累积入库。返回 {added, total}。"""
    existing = _read_existing()
    added = 0
    try:
        with httpx.Client(timeout=TIMEOUT, verify=False) as client:
            resp = client.get(ESET_ZIP_URL)
            resp.raise_for_status()
            zip_data = resp.content

        fresh: set[str] = set()
        with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
            for name in zf.namelist():
                if name.endswith("/"):
                    continue
                try:
                    content = zf.read(name).decode("utf-8", errors="ignore")
                    fresh.update(h.lower() for h in _SHA256_RE.findall(content))
                except Exception:  # noqa: BLE001
                    continue
        fresh.discard("")

        new = fresh - existing
        added = len(new)
        merged = existing | fresh
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        HASHES_FILE.write_text(
            f"# OpenGuardian 病毒库（来源: ESET malware-ioc 真实恶意样本哈希）\n"
            f"# {len(merged)} 个恶意软件哈希 · {now}（主动汲取）\n"
            + "\n".join(sorted(merged)) + "\n",
            encoding="utf-8",
        )
        logger.info("病毒库更新: 新增 %d 个恶意哈希（共 %d）", added, len(merged))
        return {"added": added, "total": len(merged), "ok": True}
    except Exception as exc:  # noqa: BLE001
        logger.warning("病毒库拉取失败（沿用本地）: %s", exc)
        return {"added": 0, "total": len(existing), "ok": False, "error": str(exc)[:80]}


def load_virus_hashes() -> set[str]:
    """加载全部恶意软件哈希。"""
    return _read_existing()


def file_sha256(path: str | None, max_bytes: int = 80 * 1024 * 1024) -> str | None:
    """计算文件 SHA256（超过 max_bytes 跳过，失败返回 None）。"""
    if not path:
        return None
    try:
        p = Path(path)
        if not p.is_file() or p.stat().st_size > max_bytes:
            return None
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:  # noqa: BLE001
        return None


def hash_stats() -> dict:
    """病毒库状态（供 kb_stats 展示）。"""
    total = len(_read_existing())
    return {"total": total, "updated": None}


# 内存缓存（加载一次，进程检测热用）
_CACHE: set[str] | None = None


def cached_hashes() -> set[str]:
    global _CACHE
    if _CACHE is None:
        _CACHE = load_virus_hashes()
    return _CACHE


def invalidate_cache() -> None:
    global _CACHE
    _CACHE = None
