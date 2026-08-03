"""黑名单知识库：恶意 IP / 恶意域名加载与查询。

数据源：
- malicious_ips.txt      恶意 IP/CIDR（Emerging Threats + FireHOL，百万级）
- malicious_domains.txt  恶意域名（abuse.ch URLhaus 等）

性能设计：
- 精确 IP 用 set 查表（O(1)）
- CIDR 用 netaddr.IPSet（O(log n) 前缀树查询）
- 懒加载 + 缓存，首次查询才加载
"""
from __future__ import annotations

import ipaddress
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

_KB_DIR = Path(__file__).resolve().parent.parent.parent / "kb_data"
# PyInstaller 打包修正
import sys as _sys
if getattr(_sys, "frozen", False) and hasattr(_sys, "_MEIPASS"):
    _KB_DIR = Path(_sys._MEIPASS) / "backend" / "kb_data"

_cache: dict[str, object] = {}


def _load_file(name: str) -> list[str]:
    path = _KB_DIR / name
    if not path.exists():
        return []
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return [
                line.strip() for line in f
                if line.strip() and not line.startswith("#")
            ]
    except Exception as exc:  # noqa: BLE001
        logger.warning("黑名单 %s 加载失败: %s", name, exc)
        return []


def _get_domains() -> set[str]:
    if "domains" not in _cache:
        _cache["domains"] = set(_load_file("malicious_domains.txt"))
        logger.info("恶意域名黑名单: %d 个", len(_cache["domains"]))
    return _cache["domains"]  # type: ignore[return-value]


def _get_ip_set():
    """返回 (精确IP set, CIDR IPSet)。"""
    if "ips" in _cache:
        return _cache["ips"]  # type: ignore[return-value]
    exact: set[str] = set()
    cidrs: list[str] = []
    for entry in _load_file("malicious_ips.txt"):
        if "/" in entry:
            cidrs.append(entry)
        else:
            exact.add(entry)
    ip_set = None
    if cidrs:
        try:
            from netaddr import IPSet

            ip_set = IPSet(cidrs)
        except Exception as exc:  # noqa: BLE001
            logger.warning("CIDR 解析失败: %s（%d 条保留为精确匹配）", exc, len(cidrs))
            exact.update(c for c in cidrs if "/" not in c)
    result = (exact, ip_set)
    _cache["ips"] = result
    logger.info("恶意 IP 黑名单: %d 精确 + %d CIDR 段", len(exact), len(cidrs))
    return result


def is_malicious_ip(ip_str: str) -> bool:
    """判断 IP 是否命中黑名单（精确 set + CIDR IPSet）。"""
    if not ip_str:
        return False
    exact, ip_set = _get_ip_set()
    if ip_str in exact:
        return True
    if ip_set is not None:
        try:
            from netaddr import IPAddress

            return IPAddress(ip_str) in ip_set
        except Exception:  # noqa: BLE001
            return False
    return False


def is_malicious_domain(domain: str) -> bool:
    """判断域名是否命中黑名单（含子域后缀匹配）。"""
    domain = domain.lower().rstrip(".")
    domains = _get_domains()
    if not domains:
        return False
    if domain in domains:
        return True
    # 子域匹配：xxx.malicious.com → 检查 malicious.com
    parts = domain.split(".")
    for i in range(1, len(parts) - 1):
        if ".".join(parts[i:]) in domains:
            return True
    return False
