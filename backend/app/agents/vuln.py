"""漏洞扫描器（系统补丁/配置类漏洞，面向小白可解释）。

真实检测项（Windows）：
- 系统补丁状态（PowerShell Get-HotFix 数量 + 最近更新）
- SMBv1 协议（注册表，永恒之蓝 MS17-010 利用通道）
- Windows 防火墙（netsh advfirewall 三配置文件状态）
- Guest 账户（net user guest 是否启用）
- UAC 用户账户控制（注册表 EnableLUA）
- 危险共享文件夹（net share，排除系统默认管理共享）

设计：所有命令带超时、失败静默降级（不可用项跳过，不影响整体检测）。
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
import winreg
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class VulnItem:
    item_type: str
    name: str
    detail: str
    level: str  # critical / high / medium / low
    suggestion: str = ""
    pid: int | None = None


def _run(cmd: list[str], timeout: float = 4.0) -> str:
    """执行命令并返回输出，失败返回空串（兼容中文系统 GBK 输出）。"""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=timeout,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return (r.stdout or "") + (r.stderr or "")
    except Exception as exc:  # noqa: BLE001
        logger.debug("漏洞扫描命令失败 %s: %s", cmd[0], exc)
        return ""


def _reg_value(path: str, name: str, default: int | None = None) -> int | None:
    """读注册表 DWORD 值，失败返回 default。"""
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return int(value)
    except OSError:
        return default


def _scan_patches() -> VulnItem | None:
    """系统补丁状态：已装补丁数 + 最近更新（无补丁信息 = 疑似关闭自动更新）。"""
    out = _run(["powershell", "-NoProfile", "-Command",
                "[Console]::OutputEncoding=[Text.Encoding]::UTF8; (Get-HotFix | Measure-Object).Count; (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn"],
               timeout=6.0)
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if len(lines) < 1:
        return VulnItem("vuln_patch", "系统补丁状态", "无法读取系统补丁信息（权限不足或系统受限）",
                        "medium", "在 Windows 设置 → 更新和安全 → 检查更新，确保系统已更新")
    count = lines[0]
    recent = lines[1] if len(lines) > 1 else "未知"
    try:
        n = int(count)
    except ValueError:
        return None
    if n < 30:
        return VulnItem("vuln_patch", "系统补丁不足", f"已安装 {n} 个系统补丁（最近更新：{recent}）。补丁不足意味着已知漏洞未被修复，是勒索病毒/蠕虫入侵的主因",
                        "high", "打开 Windows 设置 → 更新和安全 → 检查更新并安装全部补丁，开启自动更新")
    return VulnItem("vuln_patch", "系统补丁良好", f"已安装 {n} 个系统补丁（最近更新：{recent}），持续更新即可保持防护",
                    "low", "保持自动更新开启，每月例行检查")


def _scan_smb1() -> VulnItem | None:
    """SMBv1 协议状态（永恒之蓝 MS17-010 利用通道）。"""
    val = _reg_value(r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1")
    if val is None:
        val = _reg_value(r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start", 3)
        if val == 4:  # 已禁用
            return None
        return VulnItem("vuln_smb1", "SMBv1 协议可能启用", "SMBv1 是永恒之蓝（WannaCry 勒索病毒）的利用通道，建议禁用",
                        "high", "打开控制面板 → 程序和功能 → 启用或关闭 Windows 功能 → 取消勾选 SMB 1.0/CIFS 文件共享支持")
    if val == 0:
        return VulnItem("vuln_smb1", "SMBv1 协议已启用", "SMBv1 存在严重漏洞（永恒之蓝 MS17-010），WannaCry 勒索病毒正是通过它传播",
                        "critical", "打开控制面板 → 程序和功能 → 启用或关闭 Windows 功能 → 取消勾选 SMB 1.0/CIFS 文件共享支持，然后重启")
    return None


def _scan_firewall() -> VulnItem | None:
    """防火墙状态（三个配置文件）。"""
    out = _run(["netsh", "advfirewall", "show", "allprofiles", "state"], timeout=5.0)
    # 兼容中英文输出：State ON/OFF 或 状态 启用/禁用
    states = re.findall(r"(?:State|状态)\s+(\w+)", out, re.IGNORECASE)
    states = [s.upper() for s in states if s.upper() in ("ON", "OFF", "启用", "禁用", "开", "关")]
    if not states:
        return VulnItem("vuln_firewall", "防火墙状态未知", "无法读取防火墙状态（可能权限不足）",
                        "medium", "打开 Windows 安全中心 → 防火墙和网络保护，确认防火墙开启")
    off = sum(1 for s in states if s in ("OFF", "关", "禁用"))
    if off >= 2:
        return VulnItem("vuln_firewall", "防火墙已关闭", f"Windows 防火墙在 {off}/3 个网络配置文件中处于关闭状态，恶意软件更容易入侵",
                        "critical", "打开 Windows 安全中心 → 防火墙和网络保护 → 全部开启（域/专用/公用）")
    if off >= 1:
        return VulnItem("vuln_firewall", "部分网络防火墙关闭", f"Windows 防火墙有 {off} 个配置文件处于关闭状态",
                        "medium", "打开 Windows 安全中心 → 防火墙和网络保护，将关闭的配置文件开启")
    return None


def _scan_guest() -> VulnItem | None:
    """Guest 账户状态。"""
    out = _run(["net", "user", "guest"], timeout=5.0)
    # 精确匹配 "Account active  Yes" / "帐户启用  Yes"（中英文系统）
    if re.search(r"Account active\s+Yes", out) or re.search(r"帐户启用\s+Yes", out):
        return VulnItem("vuln_guest", "Guest 账户已启用", "Guest（来宾）账户处于启用状态，可能被攻击者利用获得低权限访问",
                        "medium", "以管理员运行命令提示符：net user guest /active:no，禁用来宾账户")
    return None


def _scan_uac() -> VulnItem | None:
    """UAC 用户账户控制状态。"""
    val = _reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
    if val == 0:
        return VulnItem("vuln_uac", "UAC 已关闭", "用户账户控制（UAC）被关闭，恶意软件可无提示获得管理员权限",
                        "high", "打开控制面板 → 用户账户 → 更改用户账户控制设置 → 拉高到默认级别并确定，重启生效")
    return None


def _scan_shares() -> VulnItem | None:
    """危险共享文件夹（排除系统默认管理共享）。"""
    out = _run(["net", "share"], timeout=5.0)
    shares = [ln.split()[0] for ln in out.splitlines() if ln.strip() and not ln.startswith(("-", "共享名")) and len(ln.split()) >= 1 and "\\\\" in ln]
    # 排除默认管理共享
    dangerous = [s for s in shares if s not in ("ADMIN$", "C$", "D$", "E$", "IPC$") and not s.endswith("$")]
    if dangerous:
        return VulnItem("vuln_share", "存在共享文件夹", f"检测到 {len(dangerous)} 个共享文件夹：{', '.join(dangerous[:3])}。局域网内其他设备可访问，可能泄露文件",
                        "medium", "确认哪些共享是必要的；不需要的在文件夹属性 → 共享 → 停止共享")
    return None


def _scan_autoruns() -> VulnItem | None:
    """启动项检测：注册表 Run 键 + 启动文件夹。"""
    suspicious: list[str] = []
    # 注册表自启动键（HKCU 和 HKLM）
    run_keys = [
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ]
    for hkey, path in run_keys:
        try:
            with winreg.OpenKey(hkey, path) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        low_name = str(name).lower()
                        low_val = str(value).lower()
                        # 白名单：安全软件和系统自带
                        if any(safe in low_val for safe in
                               ("windows defender", "securityhealth", "onedrive", "dropbox",
                                "skype", "teams", "slack", "steam", "epic", "discord",
                                "chrome", "firefox", "edge", "office", "adobe")):
                            i += 1
                            continue
                        # 恶意特征：排除合法 rundll32.exe（仅匹配伪造变体）
                        is_sys_rundll = ("\\system32\\rundll32.exe" in low_val or
                                          "\\syswow64\\rundll32.exe" in low_val)
                        if is_sys_rundll:
                            i += 1
                            continue
                        if any(bad in low_val + low_name for bad in
                               ("svch0st", "expl0rer", "rundll.exe", "rundl32", "rundlll",
                                "temp\\", "\\appdata\\local\\temp",
                                "powershell -enc", "wscript", "cscript", ".vbs", ".bat", ".ps1",
                                "crack", "keygen", "loader", "activator")):
                            suspicious.append(f"启动项「{name}」→ {value[:60]}")
                        i += 1
                    except OSError:
                        break
        except OSError:
            pass

    # 启动文件夹
    safe_names = ("onenote", "one note", "microsoft", "office", "chrome",
                  "firefox", "edge", "wechat", "qq", "dingtalk", "wps",
                  "dropbox", "skype", "teams", "slack", "steam", "epic",
                  "discord", "cloud", "syncthing", "intel", "nvidia", "amd")
    for env in ("APPDATA", "PROGRAMDATA"):
        try:
            startup_dir = Path(os.environ.get(env, "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
            if startup_dir.exists():
                for f in startup_dir.iterdir():
                    if f.suffix.lower() not in (".lnk", ".exe", ".bat", ".cmd", ".vbs", ".ps1"):
                        continue
                    fname = f.stem.lower()
                    # 已知安全软件豁免
                    if any(s in fname for s in safe_names):
                        continue
                    suspicious.append(f"启动文件夹 → {f.name}")
        except Exception:  # noqa: BLE001
            pass

    if suspicious:
        return VulnItem("vuln_autorun", "发现可疑启动项", f"检测到 {len(suspicious)} 个可疑自启动项：{'; '.join(suspicious[:3])}。恶意软件常通过自启动实现持久化",
                        "high", "打开任务管理器 → 启动 选项卡，禁用可疑项；或运行 msconfig 检查启动配置")
    return None


def _scan_hosts() -> VulnItem | None:
    """HOSTS 文件劫持检测。"""
    hosts_path = Path("C:/Windows/System32/drivers/etc/hosts")
    try:
        content = hosts_path.read_text(encoding="utf-8-sig", errors="ignore")
    except Exception:  # noqa: BLE001
        return None
    hijack: list[str] = []
    for ln in content.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split()
        if len(parts) >= 2:
            ip = parts[0]
            if ip not in ("127.0.0.1", "0.0.0.0", "::1"):
                hijack.append(ln)
    if hijack:
        return VulnItem("vuln_hosts", "HOSTS 文件被篡改", f"检测到 {len(hijack)} 条非标准 HOSTS 映射：{'; '.join(hijack[:3])}。DNS 劫持常用于钓鱼和屏蔽安全网站",
                        "critical", "以管理员身份打开 C:\\Windows\\System32\\drivers\\etc\\hosts，删除可疑行后保存")
    return None


def _scan_runonce() -> VulnItem | None:
    """RunOnce 注册表键检测（常被恶意软件用于一次性持久化）。"""
    runonce_keys = [
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    suspicious: list[str] = []
    for hkey, path in runonce_keys:
        try:
            with winreg.OpenKey(hkey, path) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        low_val = str(value).lower()
                        if any(bad in low_val for bad in
                               ("powershell -enc", "wscript", "cscript", ".vbs", ".bat",
                                "temp\\", "\\appdata\\local\\temp", "cmd.exe /c")):
                            suspicious.append(f"RunOnce「{name}」→ {str(value)[:80]}")
                        i += 1
                    except OSError:
                        break
        except OSError:
            pass
    if suspicious:
        return VulnItem("vuln_runonce", "发现可疑 RunOnce 项",
                        f"注册表 RunOnce 中存在 {len(suspicious)} 条可疑条目：{'; '.join(suspicious[:2])}。恶意软件常用 RunOnce 实现一次性自启动",
                        "high", "打开注册表编辑器删除对应 RunOnce 键值，或运行 Autoruns 工具检查")
    return None


def _scan_scheduled_tasks() -> VulnItem | None:
    """计划任务检测：查找可疑的 schtasks 条目。

    注意：schtasks /fo csv 输出的第一列是【机器名】，任务名在第二列。
    只对非系统目录的任务执行命令做关键词匹配，避免误报。
    """
    out = _run(["schtasks", "/query", "/fo", "csv", "/v"], timeout=8.0)
    if not out.strip():
        return None

    import csv as _csv
    import io as _io

    suspicious: list[str] = []
    try:
        rows = list(_csv.reader(_io.StringIO(out)))
    except Exception:
        return None

    for row in rows[1:]:  # 跳过表头
        if len(row) < 2:
            continue
        task_name = row[1].strip().strip('"')  # 第 2 列 = 任务名
        # 系统任务豁免（Microsoft 官方任务）
        if task_name.lower().startswith(("\\microsoft\\", "\\windows\\")):
            continue
        # 拼接任务名+命令供匹配
        cmd = " ".join(row[4:6]).lower()  # 命令列 + 启动目录
        haystack = f"{task_name.lower()} {cmd}"

        if any(bad in haystack for bad in
               ("powershell -enc", "-encodedcommand", "wscript", "cscript",
                ".vbs", ".bat", "\\temp\\", "\\appdata\\local\\temp",
                "cmd.exe /c", "downloader", "backdoor", "trojan",
                "mshta", "regsvr32 /s", "certutil -urlcache")):
            suspicious.append(task_name[:60])

    if suspicious:
        return VulnItem("vuln_task", "发现可疑计划任务",
                        f"检测到 {len(suspicious)} 条可疑计划任务：{'; '.join(suspicious[:3])}。APT 和勒索软件常通过计划任务维持持久化",
                        "critical", "运行 taskschd.msc 打开任务计划程序，禁用可疑任务；或运行 schtasks /Delete 删除")
    return None


def _scan_wmi_events() -> VulnItem | None:
    """WMI 事件订阅检测（文件无持久化，高级 APT 手法）。"""
    out = _run(["powershell", "-NoProfile", "-Command",
                "Get-WmiObject -Namespace 'root\\Subscription' -Class "
                "__EventFilter,__EventConsumer,__FilterToConsumerBinding 2>$null | "
                "Select-Object __CLASS,Name,CommandLine | ConvertTo-Json -Compress"],
               timeout=8.0)
    if not out.strip() or "null" in out.lower():
        return None
    try:
        import json as _json
        items = _json.loads(out)
        if not isinstance(items, list):
            items = [items] if items else []
        if items:
            names = [i.get("Name", "未知") for i in items[:3]]
            return VulnItem("vuln_wmi", "检测到 WMI 事件订阅",
                            f"发现 {len(items)} 个 WMI 持久化订阅：{', '.join(names)}。这是高级 APT 常用无文件持久化技术",
                            "critical",
                            "以管理员运行 PowerShell：Get-WmiObject -Namespace root\\Subscription -Class __EventFilter | Remove-WmiObject")
    except Exception:
        pass
    return None


def scan_vulnerabilities() -> list[VulnItem]:
    """执行全部漏洞检测，返回发现的风险项（0 风险返回空列表）。"""
    items: list[VulnItem] = []
    scanners = [_scan_patches, _scan_smb1, _scan_firewall, _scan_guest, _scan_uac, _scan_shares,
                _scan_autoruns, _scan_hosts, _scan_runonce, _scan_scheduled_tasks, _scan_wmi_events]
    for fn in scanners:
        try:
            item = fn()
            if item:
                items.append(item)  # 包含 low 级别（如补丁良好确认信息）
        except Exception as exc:  # noqa: BLE001
            logger.debug("漏洞检测项异常 %s: %s", fn.__name__, exc)
    return items
