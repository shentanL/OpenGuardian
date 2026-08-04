"""Agent 三层记忆系统。

Facts（事实记忆）: 进程指纹、用户信任项、已知安全签名
Episodes（情节记忆）: 每次检测的结构化摘要（可对比、可追溯）
Policies（策略记忆）: 用户偏好、规则设置
"""
from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from .db import Database, get_db
from .schemas import RiskItem, RiskLevel

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════
# 进程指纹
# ═══════════════════════════════════════════


@dataclass
class ProcessFingerprint:
    """进程指纹：用于跨检测周期的身份识别。"""
    name: str
    path_hash: str      # 路径的 SHA256 前 16 位
    first_seen: str     # 首次发现时间
    last_seen: str      # 最后出现时间
    seen_count: int = 1
    verdict: str = "unknown"     # safe / suspicious / malicious / unknown
    signed_by: str = ""          # 签名者
    user_note: str = ""          # 用户备注


class MemoryManager:
    """三层记忆管理器。"""

    def __init__(self, db: Database | None = None) -> None:
        self.db = db or get_db()
        self._fingerprint_cache: dict[str, ProcessFingerprint] = {}
        self._cache_loaded = False
        self._lock = threading.Lock()

    # ─── Facts: 进程指纹 ───

    def _ensure_cache(self) -> None:
        """懒加载指纹缓存（线程安全）。"""
        if self._cache_loaded:
            return
        with self._lock:
            if self._cache_loaded:
                return
            try:
                rows = self.db._query(
                    "SELECT name, path_hash, first_seen, last_seen, seen_count, "
                    "verdict, signed_by, user_note FROM process_fingerprints"
                )
                for r in rows:
                    fp = ProcessFingerprint(
                        name=r[0], path_hash=r[1], first_seen=r[2], last_seen=r[3],
                        seen_count=r[4], verdict=r[5] or "unknown",
                        signed_by=r[6] or "", user_note=r[7] or "",
                    )
                    self._fingerprint_cache[f"{fp.name}:{fp.path_hash}"] = fp
                self._cache_loaded = True
                logger.debug("Memory: loaded %d fingerprints", len(self._fingerprint_cache))
            except Exception as exc:
                logger.debug("Memory: fingerprint load skipped (%s)", exc)
                self._cache_loaded = True

    def get_fingerprint(self, name: str, exe_path: str = "") -> ProcessFingerprint | None:
        """查询进程指纹（历史行为记录）。"""
        self._ensure_cache()
        import hashlib
        path_hash = hashlib.sha256(exe_path.encode()).hexdigest()[:16] if exe_path else "unknown"
        key = f"{name.lower()}:{path_hash}"
        return self._fingerprint_cache.get(key)

    def record_fingerprint(
        self, name: str, exe_path: str = "",
        verdict: str = "unknown", signed_by: str = "",
    ) -> None:
        """记录/更新进程指纹（线程安全）。"""
        import hashlib
        path_hash = hashlib.sha256(exe_path.encode()).hexdigest()[:16] if exe_path else "unknown"
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        key = f"{name.lower()}:{path_hash}"

        self._ensure_cache()
        with self._lock:

            existing = self._fingerprint_cache.get(key)
            if existing:
                existing.last_seen = now
                existing.seen_count += 1
                if verdict != "unknown":
                    existing.verdict = verdict
                if signed_by:
                    existing.signed_by = signed_by
                self.db._execute(
                    "UPDATE process_fingerprints SET last_seen=?, seen_count=?, verdict=?, signed_by=? "
                    "WHERE name=? AND path_hash=?",
                    (now, existing.seen_count, existing.verdict,
                     existing.signed_by or "", name.lower(), path_hash),
                )
            else:
                fp = ProcessFingerprint(
                    name=name.lower(), path_hash=path_hash, first_seen=now, last_seen=now,
                    verdict=verdict, signed_by=signed_by,
                )
                self._fingerprint_cache[key] = fp
                self.db._execute(
                    "INSERT INTO process_fingerprints(name, path_hash, first_seen, last_seen, "
                    "seen_count, verdict, signed_by) VALUES(?,?,?,?,?,?,?)",
                    (name.lower(), path_hash, now, now, 1, verdict, signed_by or ""),
                )


    def is_known_safe(self, name: str, exe_path: str = "") -> bool:
        """检查进程是否已知安全。"""
        fp = self.get_fingerprint(name, exe_path)
        if fp is None:
            return False
        return fp.verdict == "safe"

    # ─── Episodes: 检测摘要 ───

    def save_episode(self, summary: dict) -> None:
        """保存一次检测的情节记忆（结构化摘要）。"""
        data = json.dumps(summary, ensure_ascii=False)
        self.db._execute(
            "INSERT INTO episode_memory(time, summary_json) VALUES(?,?)",
            (time.strftime("%Y-%m-%dT%H:%M:%S"), data),
        )

    def get_recent_episodes(self, limit: int = 5) -> list[dict]:
        """获取最近的检测摘要（用于历史对比）。"""
        rows = self.db._query(
            "SELECT time, summary_json FROM episode_memory ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        episodes: list[dict] = []
        for r in rows:
            try:
                episodes.append(json.loads(r[1]))
            except json.JSONDecodeError:
                pass
        return list(reversed(episodes))  # 旧→新

    def compare_with_last(self, current_risks: list[dict]) -> dict:
        """与上一次检测对比，找出新增/消失/持续的风险。"""
        episodes = self.get_recent_episodes(2)
        if len(episodes) < 2:
            return {"new": [], "resolved": [], "persistent": [], "note": "无历史数据"}

        prev = episodes[-2]  # 上一次
        prev_names = set(
            (r.get("name") or "").lower()
            for r in (prev.get("risks") or [])
        )
        curr_names = set(
            (r.get("name") or "").lower()
            for r in current_risks
        )

        new = [n for n in curr_names if n not in prev_names]
        resolved = [n for n in prev_names if n not in curr_names]
        persistent = [n for n in curr_names if n in prev_names]

        return {
            "new": new,
            "resolved": resolved,
            "persistent": persistent,
            "note": (
                f"新增 {len(new)} 项，已解决 {len(resolved)} 项，"
                f"持续存在 {len(persistent)} 项"
            ),
        }

    # ─── Policies: 策略记忆 ───

    def get_policy(self, key: str, default: str = "") -> str:
        """读取策略/偏好。"""
        rows = self.db._query(
            "SELECT value FROM policy_memory WHERE key=?",
            (key,),
        )
        if rows:
            return rows[0][0]
        return default

    def set_policy(self, key: str, value: str) -> None:
        """设置策略/偏好。"""
        self.db._execute(
            "INSERT INTO policy_memory(key, value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=?",
            (key, value, value),
        )


# ─── 数据库模式扩展 ───

MEMORY_SCHEMA_EXT = """
CREATE TABLE IF NOT EXISTS process_fingerprints (
    name       TEXT NOT NULL,
    path_hash  TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    seen_count INTEGER DEFAULT 1,
    verdict    TEXT DEFAULT 'unknown',
    signed_by  TEXT DEFAULT '',
    user_note  TEXT DEFAULT '',
    PRIMARY KEY (name, path_hash)
);
CREATE TABLE IF NOT EXISTS episode_memory (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    time        TEXT NOT NULL,
    summary_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_memory (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_episode_time ON episode_memory(time);
CREATE INDEX IF NOT EXISTS idx_fp_verdict ON process_fingerprints(verdict);
"""


def init_memory_schema(db: Database) -> None:
    """初始化记忆系统所需的数据库表。"""
    if not db.available or db._conn is None:
        return
    try:
        with db._lock:
            db._conn.executescript(MEMORY_SCHEMA_EXT)
            db._conn.commit()
        logger.info("Memory schema initialized")
    except Exception as exc:
        logger.warning("Memory schema init skipped: %s", exc)


_memory_mgr: MemoryManager | None = None


def get_memory() -> MemoryManager:
    global _memory_mgr
    if _memory_mgr is None:
        _memory_mgr = MemoryManager()
    return _memory_mgr
