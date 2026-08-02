"""检测 Agent：终端安全状态扫描（进程 / 网络 / 资源）。

风险分级逻辑：
- 特征库命中（已知恶意软件特征）→ critical / high
- 资源占用异常（CPU/内存超阈值）→ medium
- 可疑但无法确认（未知外联端口等）→ low
"""
from __future__ import annotations

import logging
import socket

import psutil

from ..config import settings
from ..schemas import AgentResult, AgentTask, RiskItem, RiskLevel
from .base import BaseAgent

logger = logging.getLogger(__name__)

# ---- 轻量特征库（MVP 版，可扩展）----
# 已知恶意软件进程名 / 路径片段
MALWARE_PATTERNS: list[tuple[str, str, str]] = [
    # (匹配关键字, 名称, 描述)
    ("miner", "挖矿程序", "加密货币挖矿木马，会持续占用 CPU/GPU"),
    ("xmrig", "XMRig 挖矿器", "门罗币挖矿程序，常被植入他人电脑"),
    ("cryptominer", "挖矿程序", "加密货币挖矿恶意软件"),
    ("keylogger", "键盘记录器", "记录你输入的所有内容，可窃取密码"),
    ("trojan", "木马程序", "伪装成正常软件的恶意程序"),
    ("rat.exe", "远控木马", "允许黑客远程控制你的电脑"),
    ("backdoor", "后门程序", "黑客预留的远程入侵通道"),
]

# 常见反弹 shell / 恶意端口
SUSPICIOUS_PORTS: dict[int, str] = {
    4444: "常见反弹 shell 端口（Metasploit）",
    5555: "常见反弹 shell / 远控端口",
    6666: "IRC 僵尸网络常用端口",
    1337: "黑客常用玩笑端口（leet）",
    31337: "经典后门端口（Back Orifice）",
    12345: "经典远控木马端口（NetBus）",
}

# 系统关键进程（永不标记，白名单）
SYSTEM_PROCESSES = {
    "svchost.exe", "System", "Idle", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "smss.exe", "explorer.exe",
    "dwm.exe", "fontdrvhost.exe", "Registry", "Memory Compression",
}

# 用户白名单（可扩展）
USER_WHITELIST: set[str] = set()


def _match_pattern(name: str, path: str) -> tuple[str, str] | None:
    """命中特征库则返回 (名称, 描述)，否则 None。"""
    haystack = f"{name.lower()} {path.lower()}"
    for keyword, label, desc in MALWARE_PATTERNS:
        if keyword in haystack:
            return label, desc
    return None


class DetectorAgent(BaseAgent):
    name = "detect"
    description = "终端安全检测：异常进程、可疑网络连接、资源健康"

    def handle(self, task: AgentTask) -> AgentResult:
        scope = task.params.get("scope", "all")  # all / process / network / resource
        risks: list[RiskItem] = []
        if scope in ("all", "process"):
            risks.extend(self._scan_processes())
        if scope in ("all", "network"):
            risks.extend(self._scan_network())
        if scope in ("all", "resource"):
            risks.extend(self._scan_resources())

        summary = (
            f"检测完成：发现 {len(risks)} 项风险"
            f"（高危 {sum(1 for r in risks if r.level in (RiskLevel.HIGH, RiskLevel.CRITICAL))} 项）"
        )
        return AgentResult(
            agent=self.name,
            success=True,
            message=summary,
            risks=risks,
            data={"scan_scope": scope, "count": len(risks)},
        )

    # ---- 进程扫描 ----
    def _scan_processes(self) -> list[RiskItem]:
        risks: list[RiskItem] = []
        seen: set[int] = set()
        try:
            for proc in psutil.process_iter(["pid", "name", "exe", "cpu_percent", "memory_percent"]):
                try:
                    pid = proc.info["pid"]
                    if pid in seen:
                        continue
                    seen.add(pid)
                    name = proc.info["name"] or ""
                    exe = proc.info["exe"] or ""
                    cpu = proc.info["cpu_percent"] or 0.0
                    mem = proc.info["memory_percent"] or 0.0

                    if name in SYSTEM_PROCESSES or name in USER_WHITELIST:
                        continue

                    # 1) 特征库命中
                    hit = _match_pattern(name, exe)
                    if hit:
                        label, desc = hit
                        risks.append(RiskItem(
                            item_type="process",
                            name=name,
                            detail=f"进程名/路径匹配已知恶意特征；CPU {cpu:.1f}%，内存 {mem:.1f}%",
                            level=RiskLevel.CRITICAL,
                            suggestion=f"强烈建议立即结束该进程并运行全盘杀毒扫描。{desc}",
                            pid=pid,
                        ))
                        continue

                    # 2) 资源占用异常
                    if cpu > settings.CPU_ALERT_PCT:
                        risks.append(RiskItem(
                            item_type="process",
                            name=name,
                            detail=f"CPU 占用 {cpu:.1f}%（阈值 {settings.CPU_ALERT_PCT:.0f}%）",
                            level=RiskLevel.MEDIUM,
                            suggestion="该进程占用过高，可能是挖矿木马或异常程序，建议检查来源。",
                            pid=pid,
                        ))
                    elif mem > 50:
                        risks.append(RiskItem(
                            item_type="process",
                            name=name,
                            detail=f"内存占用 {mem:.1f}%（超过 50%）",
                            level=RiskLevel.LOW,
                            suggestion="内存占用偏高，若不需要可考虑关闭该程序。",
                            pid=pid,
                        ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as exc:  # noqa: BLE001
            logger.warning("process scan error: %s", exc)
        return risks

    # ---- 网络扫描 ----
    def _scan_network(self) -> list[RiskItem]:
        risks: list[RiskItem] = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                try:
                    if conn.status != "ESTABLISHED":
                        continue
                    lport = conn.lport or 0
                    rport = conn.raddr.port if conn.raddr else 0
                    r_ip = conn.raddr.ip if conn.raddr else ""

                    # 可疑本地监听端口
                    if lport in SUSPICIOUS_PORTS:
                        risks.append(RiskItem(
                            item_type="network",
                            name=f"端口 {lport}",
                            detail=f"本地监听端口 {lport}：{SUSPICIOUS_PORTS[lport]}",
                            level=RiskLevel.HIGH,
                            suggestion="该端口常被恶意软件用于通信，请检查对应进程。",
                            pid=conn.pid,
                        ))
                    # 可疑外联（非 443/80/53 等常规端口）
                    if rport and rport not in (80, 443, 53, 853) and r_ip:
                        try:
                            host = socket.gethostbyaddr(r_ip)[0]
                        except Exception:  # noqa: BLE001
                            host = r_ip
                        risks.append(RiskItem(
                            item_type="network",
                            name=f"{r_ip}:{rport}",
                            detail=f"存在到 {host}:{rport} 的外部连接",
                            level=RiskLevel.LOW,
                            suggestion="如果这不是你主动使用的软件（如更新、游戏），建议留意。",
                            pid=conn.pid,
                        ))
                except Exception:  # noqa: BLE001
                    continue
        except Exception as exc:  # noqa: BLE001
            logger.warning("network scan error: %s", exc)
        # 去重：同一 pid 同端口只报一次
        dedup: set[tuple] = set()
        uniq: list[RiskItem] = []
        for r in risks:
            key = (r.item_type, r.name, r.pid)
            if key not in dedup:
                dedup.add(key)
                uniq.append(r)
        return uniq

    # ---- 资源扫描 ----
    def _scan_resources(self) -> list[RiskItem]:
        risks: list[RiskItem] = []
        try:
            cpu = psutil.cpu_percent(interval=0.5)
            mem = psutil.virtual_memory().percent
            disk = psutil.disk_usage("/").percent

            if cpu > settings.CPU_ALERT_PCT:
                risks.append(RiskItem(
                    item_type="resource",
                    name="CPU",
                    detail=f"整体 CPU 使用率 {cpu:.1f}%（阈值 {settings.CPU_ALERT_PCT:.0f}%）",
                    level=RiskLevel.MEDIUM,
                    suggestion="CPU 持续满载可能是挖矿木马，建议运行检测查看占用最高的进程。",
                ))
            if mem > settings.MEM_ALERT_PCT:
                risks.append(RiskItem(
                    item_type="resource",
                    name="内存",
                    detail=f"内存使用率 {mem:.1f}%（阈值 {settings.MEM_ALERT_PCT:.0f}%）",
                    level=RiskLevel.MEDIUM,
                    suggestion="内存占用过高，可关闭不用的软件，或检查是否有异常进程。",
                ))
            if disk > settings.DISK_ALERT_PCT:
                risks.append(RiskItem(
                    item_type="resource",
                    name="磁盘",
                    detail=f"磁盘使用率 {disk:.1f}%（阈值 {settings.DISK_ALERT_PCT:.0f}%）",
                    level=RiskLevel.LOW,
                    suggestion="磁盘空间不足，建议清理临时文件和不用的软件。",
                ))
        except Exception as exc:  # noqa: BLE001
            logger.warning("resource scan error: %s", exc)
        return risks
