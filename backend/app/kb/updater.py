"""威胁情报主动汲取器（知识库被动 → 主动）。

启动时后台线程自动拉取最新威胁情报，合并更新本地黑名单：
- URLhaus（abuse.ch）：恶意域名（每日更新）
- FireHOL level1：恶意 IP / CIDR（每日更新）

设计原则：
- 启动 5 秒后执行一次（不阻塞服务启动）
- 网络失败静默降级（保留现有数据，记录失败状态）
- 更新结果写入 kb_data/.update_status.json 供前端展示
- 更新为增量合并去重，不破坏现有数据
"""
from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

KB_DIR = Path(__file__).resolve().parent.parent.parent / "kb_data"
DOMAINS_FILE = KB_DIR / "malicious_domains.txt"
IPS_FILE = KB_DIR / "malicious_ips.txt"
STATUS_FILE = KB_DIR / ".update_status.json"

URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv/"
FIREHOL_URL = "https://iplists.firehol.org/files/firehol_level1.netset"

TIMEOUT = 30


def _read_existing(path: Path) -> set[str]:
    """读取现有黑名单（跳过 # 注释行）。"""
    if not path.exists():
        return set()
    return {ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.startswith("#")}


def _write_file(path: Path, items: set[str], header: str) -> None:
    """写回黑名单文件（保持排序 + 头部注释）。"""
    body = "\n".join(sorted(items))
    path.write_text(f"{header}\n{body}\n", encoding="utf-8")


def _parse_urlhaus(text: str) -> set[str]:
    """URLhaus CSV：第 3 列是域名（跳过 # 注释头）。"""
    domains: set[str] = set()
    for ln in text.splitlines():
        if ln.startswith("#") or not ln.strip():
            continue
        parts = ln.split(",")
        if len(parts) >= 3:
            domain = parts[2].strip().strip('"').lower()
            if domain and "." in domain:
                domains.add(domain)
    return domains


def _parse_firehol(text: str) -> set[str]:
    """FireHOL netset：每行一个 IP 或 CIDR（跳过 # 注释）。"""
    ips: set[str] = set()
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        if "/" in ln or ln.count(".") == 3:  # CIDR 或单个 IPv4
            ips.add(ln)
    return ips


def _save_status(status: dict) -> None:
    STATUS_FILE.write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8")


def _read_status() -> dict:
    if STATUS_FILE.exists():
        try:
            return json.loads(STATUS_FILE.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            pass
    return {"sources": {}, "last_update": None}


def update_knowledge() -> dict:
    """主动汲取：URLhaus 恶意域名 + FireHOL 恶意 IP + MalwareBazaar 病毒哈希。"""
    status = _read_status()
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    result = {"domains": 0, "ips": 0, "hashes": 0, "ok": False, "detail": ""}
    try:
        with httpx.Client(timeout=TIMEOUT, verify=False) as client:
            # 1) URLhaus 恶意域名
            try:
                r = client.get(URLHAUS_URL)
                r.raise_for_status()
                fresh = _parse_urlhaus(r.text)
                existing = _read_existing(DOMAINS_FILE)
                merged = existing | fresh
                _write_file(DOMAINS_FILE, merged,
                            f"# OpenGuardian 恶意域名黑名单（来源: abuse.ch URLhaus）\n# {len(merged)} 个域名 · {now}（主动汲取）")
                result["domains"] = len(merged)
                status["sources"]["urlhaus"] = {"total": len(merged), "updated": now, "ok": True}
            except Exception as exc:  # noqa: BLE001
                logger.warning("URLhaus 更新失败: %s", exc)
                status["sources"]["urlhaus"] = {"total": len(_read_existing(DOMAINS_FILE)), "updated": now, "ok": False, "error": str(exc)[:80]}

            # 2) FireHOL 恶意 IP
            try:
                r = client.get(FIREHOL_URL)
                r.raise_for_status()
                fresh = _parse_firehol(r.text)
                existing = _read_existing(IPS_FILE)
                merged = existing | fresh
                _write_file(IPS_FILE, merged,
                            f"# OpenGuardian 恶意 IP 黑名单（来源: FireHOL level1 + Emerging Threats）\n# {len(merged)} 条 · {now}（主动汲取）")
                result["ips"] = len(merged)
                status["sources"]["firehol"] = {"total": len(merged), "updated": now, "ok": True}
            except Exception as exc:  # noqa: BLE001
                logger.warning("FireHOL 更新失败: %s", exc)
                status["sources"]["firehol"] = {"total": len(_read_existing(IPS_FILE)), "updated": now, "ok": False, "error": str(exc)[:80]}

        result["ok"] = bool(status["sources"].get("urlhaus", {}).get("ok")) or bool(
            status["sources"].get("firehol", {}).get("ok"))
        status["last_update"] = now
        _save_status(status)
        logger.info("威胁情报主动汲取完成: 域名 %d / IP %d", result["domains"], result["ips"])
    except Exception as exc:  # noqa: BLE001
        logger.warning("威胁情报汲取整体失败: %s", exc)
        result["detail"] = str(exc)[:120]

    # 3) 病毒库：MalwareBazaar 恶意软件哈希（独立容错）
    try:
        from .virus_hashes import fetch_virus_hashes, invalidate_cache

        hr = fetch_virus_hashes()
        result["hashes"] = hr.get("total", 0)
        status["sources"]["malwarebazaar"] = {"total": hr.get("total", 0), "updated": now, "ok": hr.get("ok", False)}
        if hr.get("ok"):
            invalidate_cache()  # 哈希库更新后清缓存
        _save_status(status)
    except Exception as exc:  # noqa: BLE001
        logger.warning("病毒库汲取失败: %s", exc)
    return result


def start_background_update(delay: float = 5.0) -> None:
    """后台线程启动主动汲取（daemon，不阻塞服务）。"""

    def _run() -> None:
        time.sleep(delay)
        try:
            update_knowledge()
        except Exception as exc:  # noqa: BLE001
            logger.warning("主动汲取线程异常: %s", exc)

    t = threading.Thread(target=_run, daemon=True, name="kb-updater")
    t.start()


def kb_stats() -> dict:
    """知识库状态（供 /api/stats 展示）。"""
    status = _read_status()
    from .virus_hashes import hash_stats

    return {
        "domains": len(_read_existing(DOMAINS_FILE)),
        "ips": len(_read_existing(IPS_FILE)),
        "hashes": hash_stats()["total"],
        "last_update": status.get("last_update"),
        "sources": status.get("sources", {}),
    }
