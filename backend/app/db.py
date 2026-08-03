"""SQLite 持久化层。

表：
- sessions     会话（含上下文消息，JSON 存储）
- audit_log    处置审计日志
- whitelist    用户白名单进程
- scan_history 检测历史（供报告/运维统计）

设计：
- 标准库 sqlite3，零依赖
- 单连接 + 线程锁（FastAPI 线程池场景）
- 所有写操作容错：DB 异常时降级为内存日志，服务不中断
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from .config import settings

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    messages   TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    time       TEXT NOT NULL,
    action     TEXT NOT NULL,
    pid        INTEGER,
    name       TEXT,
    result     TEXT
);
CREATE TABLE IF NOT EXISTS whitelist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    time        TEXT NOT NULL,
    total_risks INTEGER NOT NULL DEFAULT 0,
    high_risks  INTEGER NOT NULL DEFAULT 0,
    summary     TEXT,
    risks_json  TEXT
);
CREATE TABLE IF NOT EXISTS resource_history (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL,
    cpu  REAL NOT NULL,
    mem  REAL NOT NULL,
    disk REAL NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    """SQLite 封装：线程安全 + 容错降级。"""

    def __init__(self, path: Path | None = None) -> None:
        self._path = Path(path) if path else settings.DB_PATH
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._mem_logs: list[dict] = []  # 降级用内存缓冲
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self._path, check_same_thread=False)
            self._conn.executescript(_SCHEMA)
            # 轻量迁移：老库补 risks_json 列（已存在则忽略）
            try:
                self._conn.execute("ALTER TABLE scan_history ADD COLUMN risks_json TEXT")
                self._conn.commit()
                logger.info("迁移: scan_history 增加 risks_json 列")
            except sqlite3.OperationalError:
                pass  # 列已存在
            self._conn.commit()
            logger.info("SQLite 就绪: %s", self._path)
        except Exception as exc:  # noqa: BLE001
            logger.warning("SQLite 初始化失败，降级内存模式: %s", exc)
            self._conn = None

    @property
    def available(self) -> bool:
        return self._conn is not None

    # ---- 通用执行 ----
    def _execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor | None:
        if not self.available:
            return None
        with self._lock:
            try:
                cur = self._conn.execute(sql, params)
                self._conn.commit()
                return cur
            except Exception as exc:  # noqa: BLE001
                logger.warning("DB 操作失败: %s", exc)
                return None

    def _query(self, sql: str, params: tuple = ()) -> list[tuple]:
        if not self.available:
            return []
        with self._lock:
            try:
                return self._conn.execute(sql, params).fetchall()
            except Exception as exc:  # noqa: BLE001
                logger.warning("DB 查询失败: %s", exc)
                return []

    # ---- 会话 ----
    def save_session(self, session_id: str, messages: list[dict]) -> None:
        payload = json.dumps(messages[-40:], ensure_ascii=False)
        now = _now()
        self._execute(
            "INSERT INTO sessions(id, messages, created_at, updated_at) VALUES(?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET messages=?, updated_at=?",
            (session_id, payload, now, now, payload, now),
        )

    def load_session(self, session_id: str) -> list[dict]:
        rows = self._query("SELECT messages FROM sessions WHERE id=?", (session_id,))
        if not rows:
            return []
        try:
            return json.loads(rows[0][0])
        except (json.JSONDecodeError, IndexError):
            return []

    def list_sessions(self, limit: int = 20) -> list[dict]:
        rows = self._query(
            "SELECT id, updated_at FROM sessions ORDER BY updated_at DESC LIMIT ?",
            (limit,),
        )
        return [{"id": r[0], "updated_at": r[1]} for r in rows]

    def delete_session(self, session_id: str) -> bool:
        """删除会话及其消息。返回是否删除成功。"""
        cur = self._execute("DELETE FROM sessions WHERE id=?", (session_id,))
        return cur is not None and cur.rowcount > 0

    # ---- 审计日志 ----
    def add_audit(self, action: str, pid: int | None, name: str, result: str) -> None:
        entry = {"time": _now(), "action": action, "pid": pid, "name": name, "result": result}
        cur = self._execute(
            "INSERT INTO audit_log(time, action, pid, name, result) VALUES(?,?,?,?,?)",
            (_now(), action, pid, name, result),
        )
        if cur is None and len(self._mem_logs) < 500:  # 降级内存
            self._mem_logs.append(entry)

    def get_audit(self, limit: int = 100) -> list[dict]:
        if self.available:
            rows = self._query(
                "SELECT time, action, pid, name, result FROM audit_log "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            return [
                {"time": r[0], "action": r[1], "pid": r[2], "name": r[3], "result": r[4]}
                for r in rows
            ]
        return list(reversed(self._mem_logs[-limit:]))

    # ---- 白名单 ----
    def get_whitelist(self) -> set[str]:
        rows = self._query("SELECT name FROM whitelist")
        return {r[0] for r in rows}

    def add_whitelist(self, name: str) -> bool:
        cur = self._execute(
            "INSERT OR IGNORE INTO whitelist(name, created_at) VALUES(?,?)",
            (name, _now()),
        )
        return cur is not None and cur.rowcount > 0

    def remove_whitelist(self, name: str) -> bool:
        cur = self._execute("DELETE FROM whitelist WHERE name=?", (name,))
        return cur is not None and cur.rowcount > 0

    # ---- 检测历史 ----
    def add_scan(self, total_risks: int, high_risks: int, summary: str = "", risks: list[dict] | None = None) -> None:
        """写入扫描历史。risks 为 RiskItem 的 dict 列表（用于分布统计）。"""
        payload = json.dumps(risks, ensure_ascii=False) if risks else None
        self._execute(
            "INSERT INTO scan_history(time, total_risks, high_risks, summary, risks_json) "
            "VALUES(?,?,?,?,?)",
            (_now(), total_risks, high_risks, summary, payload),
        )

    def get_scan_history(self, limit: int = 50) -> list[dict]:
        rows = self._query(
            "SELECT time, total_risks, high_risks, summary, risks_json FROM scan_history "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        out = []
        for r in rows:
            risks = []
            if r[4]:
                try:
                    risks = json.loads(r[4])
                except json.JSONDecodeError:
                    risks = []
            out.append({"time": r[0], "total": r[1], "high": r[2], "summary": r[3], "risks": risks})
        return out

    # ---- 资源历史 ----
    def add_resource_sample(self, cpu: float, mem: float, disk: float) -> None:
        self._execute(
            "INSERT INTO resource_history(time, cpu, mem, disk) VALUES(?,?,?,?)",
            (_now(), round(cpu, 1), round(mem, 1), round(disk, 1)),
        )

    def get_resource_history(self, limit: int = 30) -> list[dict]:
        rows = self._query(
            "SELECT time, cpu, mem, disk FROM resource_history "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return [
            {"time": r[0], "cpu": r[1], "mem": r[2], "disk": r[3]}
            for r in reversed(rows)  # 正序返回（旧→新）
        ]


_db: Database | None = None


def get_db() -> Database:
    global _db
    if _db is None:
        _db = Database()
    return _db
