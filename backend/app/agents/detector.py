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

# ---- 恶意软件特征库（按威胁分类）----
# 格式: (匹配关键字, 名称, 描述, 风险级别)
# 关键字小写，匹配"进程名+路径"组合；同族软件聚合为一条
MALWARE_PATTERNS: list[tuple[str, str, str, RiskLevel]] = [
    # ---- 挖矿类（CPU 侵占）----
    ("xmrig", "挖矿木马", "门罗币挖矿器，常被静默植入他人电脑挖矿", RiskLevel.CRITICAL),
    ("minergate", "挖矿程序", "自带图形界面的挖矿工具，也常被捆绑安装", RiskLevel.HIGH),
    ("ethminer", "以太坊挖矿器", "ETH 挖矿程序，异常占用 GPU", RiskLevel.HIGH),
    ("claymore", "挖矿程序", "Claymore 双挖矿器，常被木马携带", RiskLevel.HIGH),
    ("ccminer", "挖矿程序", "NVIDIA GPU 挖矿器变体", RiskLevel.HIGH),
    ("cpuminer", "挖矿程序", "CPU 挖矿器，导致电脑卡顿发热", RiskLevel.CRITICAL),
    ("lolminer", "挖矿程序", "LOLMiner 挖矿器", RiskLevel.HIGH),
    ("nbminer", "挖矿程序", "NBMiner 挖矿器，常隐藏运行", RiskLevel.HIGH),
    ("teamredminer", "挖矿程序", "AMD GPU 挖矿器", RiskLevel.HIGH),
    ("phoenixminer", "挖矿程序", "PhoenixMiner 挖矿器", RiskLevel.HIGH),
    ("t-rex", "挖矿程序", "T-Rex 挖矿器，GPU 占用异常", RiskLevel.HIGH),
    ("wildrig", "挖矿程序", "WildRig 挖矿器", RiskLevel.HIGH),
    ("nanominer", "挖矿程序", "NanoMiner 挖矿器", RiskLevel.HIGH),
    ("gminer", "挖矿程序", "Gminer 多算法挖矿器", RiskLevel.HIGH),
    ("cryptonight", "挖矿内核", "Cryptonight 挖矿算法内核，常用于木马捆绑", RiskLevel.CRITICAL),
    ("miner", "挖矿程序", "通用挖矿程序特征", RiskLevel.HIGH),
    ("cryptominer", "挖矿木马", "加密货币挖矿恶意软件", RiskLevel.CRITICAL),

    # ---- 远控/木马类（远程控制）----
    ("njrat", "NjRAT 远控木马", "中东地区流行的远控木马，可开摄像头、录键盘", RiskLevel.CRITICAL),
    ("asyncrat", "AsyncRAT 远控木马", "开源远控木马，常通过钓鱼邮件传播", RiskLevel.CRITICAL),
    ("quasar", "Quasar RAT", "开源远控木马，可窃取文件与屏幕", RiskLevel.CRITICAL),
    ("darkcomet", "DarkComet 远控", "老牌远控木马，功能全面", RiskLevel.CRITICAL),
    ("remcos", "Remcos RAT", "商业级远控木马，常被恶意利用", RiskLevel.CRITICAL),
    ("nanocore", "NanoCore RAT", ".NET 远控木马，窃取凭据", RiskLevel.CRITICAL),
    ("orcus", "Orcus RAT", "功能强大的远控木马", RiskLevel.CRITICAL),
    ("lime", "LimeRAT", "轻量远控木马，窃取浏览器密码", RiskLevel.CRITICAL),
    ("gh0st", "Gh0st 远控", "经典中国红队/黑产远控木马", RiskLevel.CRITICAL),
    ("pcshare", "PCShare 远控", "灰鸽子同源远控木马", RiskLevel.CRITICAL),
    ("trojan", "木马程序", "通用木马特征", RiskLevel.CRITICAL),
    ("rat.exe", "远控木马", "允许黑客远程控制你的电脑", RiskLevel.CRITICAL),
    ("backdoor", "后门程序", "黑客预留的远程入侵通道", RiskLevel.CRITICAL),
    ("hacktool", "黑客工具", "可能被恶意利用的黑客工具", RiskLevel.HIGH),
    ("cobaltstrike", "Cobalt Strike", "红队渗透工具，常被黑客用来控制服务器", RiskLevel.CRITICAL),
    ("mimikatz", "Mimikatz", "窃取 Windows 密码哈希的工具，常被木马携带", RiskLevel.CRITICAL),

    # ---- 勒索类（文件加密）----
    ("wannacry", "WannaCry 勒索病毒", "2017 年席卷全球的勒索蠕虫", RiskLevel.CRITICAL),
    ("locky", "Locky 勒索病毒", "通过邮件附件传播的勒索病毒", RiskLevel.CRITICAL),
    ("cerber", "Cerber 勒索病毒", "RaaS 模式勒索病毒", RiskLevel.CRITICAL),
    ("gandcrab", "GandCrab 勒索病毒", "曾是最活跃的勒索病毒家族", RiskLevel.CRITICAL),
    ("ryuk", "Ryuk 勒索病毒", "定向攻击企业的勒索病毒", RiskLevel.CRITICAL),
    ("netwalker", "NetWalker 勒索病毒", "勒索即服务家族", RiskLevel.CRITICAL),
    ("revil", "REvil 勒索病毒", "重大勒索攻击的幕后黑手", RiskLevel.CRITICAL),
    ("darkside", "DarkSide 勒索病毒", "曾攻击美国输油管道", RiskLevel.CRITICAL),
    ("conti", "Conti 勒索病毒", "活跃的勒索即服务团伙", RiskLevel.CRITICAL),
    ("lockbit", "LockBit 勒索病毒", "自动化程度极高的勒索家族", RiskLevel.CRITICAL),
    ("maze", "Maze 勒索病毒", "双重勒索模式的先驱", RiskLevel.CRITICAL),
    ("petya", "Petya 勒索病毒", "加密整个磁盘的勒索病毒", RiskLevel.CRITICAL),
    ("notpetya", "NotPetya", "伪装成勒索的破坏性蠕虫", RiskLevel.CRITICAL),
    ("badrabbit", "Bad Rabbit 勒索", "通过伪 Flash 更新传播", RiskLevel.CRITICAL),
    ("ransomware", "勒索软件", "通用勒索软件特征", RiskLevel.CRITICAL),

    # ---- 间谍/键盘记录类（信息窃取）----
    ("keylogger", "键盘记录器", "记录你输入的所有内容，可窃取密码", RiskLevel.CRITICAL),
    ("ardamax", "Ardamax Keylogger", "商业键盘记录器", RiskLevel.CRITICAL),
    ("spyrix", "Spyrix 间谍软件", "监控+键盘记录间谍软件", RiskLevel.CRITICAL),
    ("refog", "Refog 监控软件", "键盘记录与屏幕监控软件", RiskLevel.HIGH),
    ("elitekeylogger", "Elite 键盘记录器", "隐藏式键盘记录器", RiskLevel.CRITICAL),
    ("spyware", "间谍软件", "通用间谍软件特征", RiskLevel.HIGH),
    ("stealer", "信息窃取木马", "专门窃取浏览器密码/钱包的木马", RiskLevel.CRITICAL),
    ("redline", "RedLine 窃密木马", "流行的信息窃取木马", RiskLevel.CRITICAL),
    ("raccoon", "Raccoon 窃密木马", "Stealer 即服务家族的窃密木马", RiskLevel.CRITICAL),
    ("azorult", "Azorult 窃密木马", "窃取凭据与加密货币的木马", RiskLevel.CRITICAL),
    ("formbook", "FormBook 窃密木马", "通过钓鱼邮件传播的窃密木马", RiskLevel.CRITICAL),
    ("agenttesla", "Agent Tesla", "流行的键盘记录+窃密木马", RiskLevel.CRITICAL),

    # ---- 僵尸网络/银行木马类 ----
    ("mirai", "Mirai 僵尸网络", "物联网僵尸网络，也可感染 PC", RiskLevel.CRITICAL),
    ("zeus", "Zeus 银行木马", "老牌银行木马，窃取网银凭据", RiskLevel.CRITICAL),
    ("citadel", "Citadel 银行木马", "Zeus 变体银行木马", RiskLevel.CRITICAL),
    ("spyeye", "SpyEye 银行木马", "银行信息窃取木马", RiskLevel.CRITICAL),
    ("trickbot", "TrickBot 银行木马", "模块化银行木马，常投递勒索软件", RiskLevel.CRITICAL),
    ("emotet", "Emotet 木马", "顶级恶意软件分发平台", RiskLevel.CRITICAL),
    ("qakbot", "QakBot 银行木马", "活跃的银行木马与分发器", RiskLevel.CRITICAL),
    ("botnet", "僵尸网络客户端", "被黑客远程控制的木马客户端", RiskLevel.CRITICAL),

    # ---- 补充特征库（来源：Neo23x0/signature-base yara 家族名）----
    ("netwire_rat", "NetWire 远控木马", "商业远控木马，窃取键盘记录与文件", RiskLevel.CRITICAL),
    ("exile_rat", "Exile RAT", "轻量远控木马，常用于鱼叉攻击", RiskLevel.CRITICAL),
    ("revenge_rat", "Revenge RAT", "远控木马，支持键盘记录与屏幕捕获", RiskLevel.CRITICAL),
    ("pupy_rat", "Pupy RAT", "跨平台远控木马（Python 编写）", RiskLevel.CRITICAL),
    ("crimson_rat", "Crimson RAT", "针对中东地区的远控木马", RiskLevel.CRITICAL),
    ("crunchrat", "CrunchRAT", "开源远控木马", RiskLevel.CRITICAL),
    ("hizor_rat", "Hizor RAT", "远控木马，窃取浏览器凭据", RiskLevel.CRITICAL),
    ("khrat", "KHRAT 远控", "韩语环境远控木马", RiskLevel.CRITICAL),
    ("uboat_rat", "UBoat RAT", "远控木马，可下载执行任意载荷", RiskLevel.CRITICAL),
    ("xtreme_rat", "Xtreme RAT", "老牌远控木马", RiskLevel.CRITICAL),
    ("parallax_rat", "Parallax RAT", "隐蔽远控木马，反分析能力强", RiskLevel.CRITICAL),
    ("xrat", "XRat", "轻量远控木马", RiskLevel.CRITICAL),
    ("dridex", "Dridex 银行木马", "著名银行木马，通过宏文档传播", RiskLevel.CRITICAL),
    ("qbot", "QakBot 银行木马", "银行木马与勒索投递平台（同 QakBot）", RiskLevel.CRITICAL),
    ("gozi", "Gozi 银行木马", "老牌银行木马（Ursnif 家族）", RiskLevel.CRITICAL),
    ("loki_bot", "Loki Bot 窃密木马", "窃取浏览器密码与加密货币钱包", RiskLevel.CRITICAL),
    ("zloader", "ZLoader 银行木马", "Zeus 变体，常投递勒索软件", RiskLevel.CRITICAL),
    ("bazarbackdoor", "BazarBackdoor", "Conti 团伙的后门木马", RiskLevel.CRITICAL),
    ("shifu_trojan", "Shifu 银行木马", "针对网银的攻击木马", RiskLevel.CRITICAL),
    ("katz_stealer", "凭据窃取器", "窃取 Windows 凭据与浏览器密码", RiskLevel.CRITICAL),
    ("goldenspy", "GoldenSpy 间谍软件", "政府级间谍软件，窃取屏幕与键盘", RiskLevel.CRITICAL),
    ("poshspy", "PoshSpy 间谍软件", "PowerShell 编写的间谍软件", RiskLevel.HIGH),
    ("lockbit", "LockBit 勒索病毒", "自动化勒索即服务家族", RiskLevel.CRITICAL),
    ("lorenz", "Lorenz 勒索病毒", "双重勒索模式", RiskLevel.CRITICAL),
    ("prolock", "ProLock 勒索病毒", "企业定向勒索", RiskLevel.CRITICAL),
    ("ragna_locker", "RagnaLocker 勒索", "企业定向勒索", RiskLevel.CRITICAL),
    ("vicesociety", "Vice Society 勒索", "教育/医疗行业勒索团伙", RiskLevel.CRITICAL),
    ("robinhood", "RobinHood 勒索", "伪装成合法软件的勒索病毒", RiskLevel.CRITICAL),
    ("darkbit", "DarkBit 勒索", "新兴勒索家族", RiskLevel.CRITICAL),
    ("wadharma", "Dharma 变体勒索", "Dharma 勒索家族变体", RiskLevel.CRITICAL),
    ("nopetya", "NoPetya", "类 Petya 破坏性病毒", RiskLevel.CRITICAL),
    ("dearcry", "DearCry 勒索", "利用 Exchange 漏洞传播的勒索", RiskLevel.CRITICAL),
    ("moonlightmaze", "MoonlightMaze 勒索", "Maze 家族变体", RiskLevel.CRITICAL),
    ("hermes_ransom", "Hermes 勒索病毒", "勒索病毒家族", RiskLevel.CRITICAL),
    ("h2miner_kinsing", "Kinsing 挖矿木马", "利用漏洞入侵后植入挖矿程序", RiskLevel.CRITICAL),
    ("nkminer", "NKMiner 挖矿", "挖矿木马", RiskLevel.HIGH),
    ("crypto_miner", "挖矿程序", "通用挖矿程序特征", RiskLevel.HIGH),
    ("guloader", "GuLoader 下载器", "恶意软件下载器，投递勒索与窃密木马", RiskLevel.CRITICAL),
    ("babbleloader", "BabbleLoader", "恶意软件加载器", RiskLevel.HIGH),
    ("octowave_loader", "OctoWave 加载器", "恶意软件加载器", RiskLevel.HIGH),
    ("plead_downloader", "Plead 下载器", "下载并执行恶意载荷", RiskLevel.HIGH),
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

# 用户白名单（SQLite 持久化；此处为内存兜底）
USER_WHITELIST: set[str] = set()


def _get_user_whitelist() -> set[str]:
    """读取用户白名单（DB 优先，失败回退内存集）。"""
    try:
        from ..db import get_db

        stored = get_db().get_whitelist()
        if stored:
            return stored
    except Exception:  # noqa: BLE001
        pass
    return USER_WHITELIST


def _match_pattern(name: str, path: str) -> tuple[str, str, RiskLevel] | None:
    """命中特征库则返回 (名称, 描述, 级别)，否则 None。"""
    haystack = f"{name.lower()} {path.lower()}"
    for keyword, label, desc, level in MALWARE_PATTERNS:
        if keyword in haystack:
            return label, desc, level
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

                    if name in SYSTEM_PROCESSES or name in _get_user_whitelist():
                        continue

                    # 1) 特征库命中
                    hit = _match_pattern(name, exe)
                    if hit:
                        label, desc, level = hit
                        risks.append(RiskItem(
                            item_type="process",
                            name=name,
                            detail=f"进程名/路径匹配已知恶意特征；CPU {cpu:.1f}%，内存 {mem:.1f}%",
                            level=level,
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
                        # 黑名单命中：恶意 IP / 恶意域名
                        from ..kb.blacklists import is_malicious_domain, is_malicious_ip

                        if is_malicious_ip(r_ip) or is_malicious_domain(host):
                            risks.append(RiskItem(
                                item_type="network",
                                name=f"{r_ip}:{rport}",
                                detail=f"连接到黑名单中的恶意地址 {host}:{rport}",
                                level=RiskLevel.HIGH,
                                suggestion="该地址在威胁情报黑名单中，立即断网并查杀！",
                                pid=conn.pid,
                            ))
                            continue
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
