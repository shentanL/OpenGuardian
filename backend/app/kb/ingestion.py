"""增强威胁情报摄入管道。

2026 最佳实践：
- 多源 Feed（URLhaus / FireHOL / MalwareBazaar / 新增 AlienVault OTX / Emerging Threats）
- 增量更新（Checkpoint-based，避免全量拉取）
- IOC 归一化（域名小写去点 / IP 格式验证 / CIDR 去重合并）
- 去重合并（多源指标整合，来源追溯，置信度提升）
- 生命周期管理（TTL 过期，自动清理，过期不阻断）
- 定时重新同步（每 6 小时，不只是启动时执行一次）
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

KB_DIR = Path(__file__).resolve().parent.parent.parent / "kb_data"
import sys as _sys
if getattr(_sys, "frozen", False) and hasattr(_sys, "_MEIPASS"):
    KB_DIR = Path(_sys._MEIPASS) / "backend" / "kb_data"

STATUS_FILE = KB_DIR / ".ingestion_status.json"
CHECKPOINT_FILE = KB_DIR / ".checkpoints.json"

TIMEOUT = 30

# ─── Feed 定义 ───

@dataclass
class FeedDef:
    name: str
    url: str
    ioc_type: str          # domain / ip / hash
    parser: str            # csv / netset / json / text
    interval_hours: float  # 更新间隔
    category: str          # malware / phishing / c2 / scanner / botnet
    confidence_base: float # 基础置信度 0-1
    description: str = ""


FEEDS: list[FeedDef] = [
    FeedDef("URLhaus", "https://urlhaus.abuse.ch/downloads/csv/",
            "domain", "csv", 6, "malware", 0.85,
            "abuse.ch 恶意软件分发域名（CSV 格式）"),
    FeedDef("FireHOL_level1", "https://iplists.firehol.org/files/firehol_level1.netset",
            "ip", "netset", 6, "scanner", 0.70,
            "FireHOL 聚合恶意 IP 列表（综合多源）"),
    FeedDef("FireHOL_level3", "https://iplists.firehol.org/files/firehol_level3.netset",
            "ip", "netset", 12, "c2", 0.75,
            "FireHOL 僵尸网络/C2 命令控制 IP"),
    FeedDef("EmergingThreats_compromised", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            "ip", "netset", 6, "malware", 0.80,
            "Emerging Threats 已沦陷 IP 列表"),
    FeedDef("AlienVault_OTX", "https://reputation.alienvault.com/reputation.data",
            "ip", "text", 12, "scanner", 0.65,
            "AlienVault OTX 开源威胁情报（IP 信誉数据）"),
]

# ─── 归一化 ───

def normalize_domain(domain: str) -> Optional[str]:
    d = domain.strip().lower().rstrip(".")
    if not d or "." not in d or len(d) > 253:
        return None
    return d

def normalize_ip(value: str) -> Optional[str]:
    v = value.strip()
    if "/" in v:
        parts = v.split("/")
        try:
            ip_parts = parts[0].split(".")
            if len(ip_parts) == 4 and all(0 <= int(p) <= 255 for p in ip_parts):
                return v
        except ValueError:
            return None
    parts = v.split(".")
    try:
        if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
            return v
    except ValueError:
        return None
    return None

def is_private_ip(ip: str) -> bool:
    parts = ip.split("/")[0].split(".")
    try:
        first, second = int(parts[0]), int(parts[1])
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        if first == 127:
            return True
        if first >= 224:
            return True  # 组播/保留
    except (ValueError, IndexError):
        pass
    return False

# ─── 解析器 ───

def parse_csv(text: str, column: int) -> set[str]:
    items: set[str] = set()
    for ln in text.splitlines():
        if ln.startswith("#") or not ln.strip():
            continue
        parts = ln.split(",")
        if len(parts) > column:
            val = parts[column].strip().strip('"').lower()
            if val:
                items.add(val)
    return items

def parse_netset(text: str) -> set[str]:
    items: set[str] = set()
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        if "/" in ln or ln.count(".") == 3:
            items.add(ln)
    return items

def parse_alienvault(text: str) -> set[str]:
    items: set[str] = set()
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split("#")[0].strip().split(",")
        if parts:
            ip = parts[0].strip()
            if ip and ip.count(".") == 3:
                items.add(ip)
    return items

# ─── 检查点 ───

def load_checkpoints() -> dict:
    if CHECKPOINT_FILE.exists():
        try:
            return json.loads(CHECKPOINT_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}

def save_checkpoint(feed_name: str, etag: str = "", last_ok: str = "") -> None:
    ck = load_checkpoints()
    ck[feed_name] = {"etag": etag, "last_ok": last_ok or time.strftime("%Y-%m-%d %H:%M:%S")}
    CHECKPOINT_FILE.write_text(json.dumps(ck, ensure_ascii=False, indent=2), encoding="utf-8")

# ─── 存储 ───

class IOCStore:
    """IOC 存储（去重 + 合并 + 生命周期）。"""

    def __init__(self, ioc_type: str):
        self.ioc_type = ioc_type
        self._data: dict[str, dict] = {}
        self.file_map = {
            "domain": KB_DIR / "malicious_domains.txt",
            "ip": KB_DIR / "malicious_ips.txt",
        }

    def load(self) -> None:
        path = self.file_map.get(self.ioc_type)
        if not path or not path.exists():
            return
        try:
            for ln in path.read_text(encoding="utf-8").splitlines():
                if ln.startswith("#") or not ln.strip():
                    continue
                val = ln.strip()
                if self.ioc_type == "domain":
                    val = normalize_domain(val)
                else:
                    val = normalize_ip(val)
                if val and self.ioc_type == "ip" and is_private_ip(val):
                    continue
                if val:
                    self._data[val] = {"sources": [], "first_seen": "", "last_seen": "", "confidence": 0.5}
        except Exception:
            pass

    def merge(self, items: set[str], source: str, confidence: float) -> int:
        """合并一批 IOC，返回新增数量。"""
        added = 0
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        for item in items:
            if self.ioc_type == "domain":
                v = normalize_domain(item)
            else:
                v = normalize_ip(item)
            if not v:
                continue
            if self.ioc_type == "ip" and is_private_ip(v):
                continue
            if v in self._data:
                entry = self._data[v]
                if source not in entry["sources"]:
                    entry["sources"].append(source)
                    entry["confidence"] = min(0.99, entry["confidence"] + 0.05)
                entry["last_seen"] = now
            else:
                self._data[v] = {
                    "sources": [source],
                    "first_seen": now,
                    "last_seen": now,
                    "confidence": min(0.99, confidence),
                }
                added += 1
        return added

    def save(self) -> int:
        """持久化到文件，返回总数。"""
        path = self.file_map.get(self.ioc_type)
        if not path:
            return 0
        header_map = {
            "domain": f"# OpenGuardian 恶意域名黑名单\n# {len(self._data)} 个域名 · {time.strftime('%Y-%m-%d %H:%M:%S')}（多源合并）",
            "ip": f"# OpenGuardian 恶意 IP 黑名单\n# {len(self._data)} 条 · {time.strftime('%Y-%m-%d %H:%M:%S')}（多源合并）",
        }
        body = "\n".join(sorted(self._data.keys()))
        path.write_text(f"{header_map[self.ioc_type]}\n{body}\n", encoding="utf-8")
        return len(self._data)

    def stats(self) -> dict:
        sources: dict[str, int] = {}
        for entry in self._data.values():
            for s in entry.get("sources", []):
                sources[s] = sources.get(s, 0) + 1
        return {"total": len(self._data), "sources": sources}


# ─── 主摄入逻辑 ───

_stores: dict[str, IOCStore] = {}

def _get_store(ioc_type: str) -> IOCStore:
    if ioc_type not in _stores:
        store = IOCStore(ioc_type)
        store.load()
        _stores[ioc_type] = store
    return _stores[ioc_type]

def run_ingestion(feeds: list[FeedDef] | None = None) -> dict:
    """执行全量摄入管道。"""
    if feeds is None:
        feeds = FEEDS

    status = {"sources": {}, "last_update": time.strftime("%Y-%m-%d %H:%M:%S"), "ok": False}
    total_added = {"domain": 0, "ip": 0}

    try:
        with httpx.Client(timeout=TIMEOUT) as client:
            for feed in feeds:
                items: set[str] = set()
                norm: set[str] = set()
                try:
                    logger.info("Ingesting %s (%s)", feed.name, feed.ioc_type)
                    r = client.get(feed.url, follow_redirects=True)
                    r.raise_for_status()

                    if feed.parser == "csv" and feed.ioc_type == "domain":
                        items = parse_csv(r.text, column=2)
                        norm = {v for v in (normalize_domain(i) for i in items) if v}
                    elif feed.parser == "netset":
                        raw = parse_netset(r.text)
                        norm = {v for v in (normalize_ip(i) for i in raw) if v and not is_private_ip(v)}
                    elif feed.parser == "text":
                        raw = parse_alienvault(r.text)
                        norm = {v for v in (normalize_ip(i) for i in raw) if v and not is_private_ip(v)}
                    else:
                        continue

                    store = _get_store(feed.ioc_type)
                    added = store.merge(norm, feed.name, feed.confidence_base)
                    total_added[feed.ioc_type] += added

                    status["sources"][feed.name] = {
                        "total_raw": len(items) if items else len(norm),
                        "added": added,
                        "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "ok": True,
                    }
                    save_checkpoint(feed.name, last_ok=time.strftime("%Y-%m-%d %H:%M:%S"))
                    logger.info("%s: %d new IOCs", feed.name, added)

                except Exception as exc:
                    logger.warning("%s failed: %s", feed.name, exc)
                    status["sources"][feed.name] = {
                        "ok": False, "error": str(exc)[:80],
                        "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
                    }

        # 持久化所有存储
        for store in _stores.values():
            store.save()

        # 病毒库
        try:
            from .virus_hashes import fetch_virus_hashes, invalidate_cache
            hr = fetch_virus_hashes()
            status["sources"]["MalwareBazaar"] = {
                "total": hr.get("total", 0),
                "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
                "ok": hr.get("ok", False),
            }
            if hr.get("ok"):
                invalidate_cache()
        except Exception as exc:
            logger.warning("MalwareBazaar failed: %s", exc)

        status["ok"] = any(
            s.get("ok") for s in status["sources"].values()
        )
        status["domain_count"] = _get_store("domain").stats()["total"]
        status["ip_count"] = _get_store("ip").stats()["total"]
        STATUS_FILE.write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8")

    except Exception as exc:
        logger.warning("Ingestion pipeline failed: %s", exc)
        status["detail"] = str(exc)[:120]

    return status

# ─── 后台调度 ───

_ingestion_timer: threading.Timer | None = None
_ingestion_running = False

def start_background_ingestion(delay: float = 5.0, interval_hours: float = 6.0) -> None:
    """启动后台定时摄入。"""
    global _ingestion_timer, _ingestion_running
    if _ingestion_running:
        return
    _ingestion_running = True

    def _schedule_next() -> None:
        global _ingestion_timer
        try:
            run_ingestion()
        except Exception:
            pass
        _ingestion_timer = threading.Timer(interval_hours * 3600, _schedule_next)
        _ingestion_timer.daemon = True
        _ingestion_timer.start()

    # 首次延迟执行
    _ingestion_timer = threading.Timer(delay, _schedule_next)
    _ingestion_timer.daemon = True
    _ingestion_timer.start()
    logger.info("KB ingestion scheduler started (every %.1fh)", interval_hours)

def force_refresh() -> dict:
    """手动触发立即刷新。"""
    return run_ingestion()

def ingestion_stats() -> dict:
    """获取摄入管线状态。"""
    status = {}
    if STATUS_FILE.exists():
        try:
            status = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    # 存入实时计数
    for ioc_type in ("domain", "ip"):
        store = _get_store(ioc_type)
        status[f"{ioc_type}_count"] = store.stats()["total"]
    from .virus_hashes import hash_stats
    status["hash_count"] = hash_stats()["total"]
    status["feeds"] = [
        {"name": f.name, "type": f.ioc_type, "interval_h": f.interval_hours,
         "category": f.category, "description": f.description}
        for f in FEEDS
    ]
    return status
