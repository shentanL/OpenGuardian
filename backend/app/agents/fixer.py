"""一键修复模块 —— 检测到的常见风险提供自动修复方案。

修复前强制弹窗确认，仅执行安全的系统配置修改。
"""

from __future__ import annotations

import subprocess

# risk item_type → (修复命令, 说明, 是否需管理员)
FIX_COMMANDS: dict[str, dict] = {
    "vuln_smb1": {
        "cmd": 'powershell -NoProfile -Command "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"',
        "desc": "禁用 SMBv1 协议（永恒之蓝/WannaCry 攻击入口）",
        "admin": True,
    },
    "vuln_firewall": {
        "cmd": 'netsh advfirewall set allprofiles state on',
        "desc": "启用 Windows 防火墙所有配置文件",
        "admin": True,
    },
    "vuln_guest": {
        "cmd": 'net user guest /active:no',
        "desc": "禁用 Guest 账户",
        "admin": True,
    },
    "defender": {
        "cmd": 'powershell -NoProfile -Command "Set-MpPreference -DisableRealtimeMonitoring \\$false"',
        "desc": "启用 Windows Defender 实时保护",
        "admin": True,
    },
    "vuln_task": {
        "cmd": None,  # 计划任务需指定名称，手动处理
        "desc": "计划任务清理需手动在 taskschd.msc 中禁用",
        "admin": True,
        "manual": True,
    },
    "vuln_uac": {
        "cmd": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA /t REG_DWORD /d 1 /f',
        "desc": "启用 UAC 用户账户控制",
        "admin": True,
    },
}

# 通用修复建议（无需执行命令，仅提示）
FIX_SUGGESTIONS: dict[str, str] = {
    "vuln_patch": "打开 Windows Update → 检查更新 → 安装所有重要/可选更新",
    "vuln_autorun": "运行 msconfig → 启动 → 禁用可疑项；打开 regedit → HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run → 删除可疑键值",
    "vuln_hosts": "以管理员身份编辑 C:\\Windows\\System32\\drivers\\etc\\hosts → 删除可疑行 → 保存",
    "vuln_share": "运行 compmgmt.msc → 共享文件夹 → 共享 → 右键可疑共享 → 停止共享",
    "malicious_ip": "Windows 防火墙新建出站规则 → 阻止该 IP 所有出站连接",
    "malicious_domain": "Windows 防火墙或路由器 DNS 层面封禁该域名",
}


def get_fix(item_type: str) -> dict | None:
    """获取修复方案。返回 {"cmd": ..., "desc": ..., "admin": bool} 或仅建议。"""
    if item_type in FIX_COMMANDS:
        return FIX_COMMANDS[item_type]
    if item_type in FIX_SUGGESTIONS:
        return {"cmd": None, "desc": FIX_SUGGESTIONS[item_type], "admin": False, "manual": True}
    return None


def execute_fix(item_type: str) -> dict:
    """执行一键修复（需用户已确认）。"""
    if item_type not in FIX_COMMANDS:
        return {"ok": False, "error": "该风险类型暂不支持自动修复", "suggestion": FIX_SUGGESTIONS.get(item_type, "")}

    entry = FIX_COMMANDS[item_type]
    if entry.get("manual"):
        return {"ok": False, "error": "该修复需手动操作", "suggestion": entry["desc"]}

    try:
        result = subprocess.run(
            entry["cmd"],
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return {"ok": True, "desc": entry["desc"], "output": result.stdout[:200]}
        else:
            return {
                "ok": False,
                "desc": entry["desc"],
                "error": result.stderr[:200],
                "hint": "可能需要以管理员身份运行 OpenGuardian",
            }
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:200], "desc": entry["desc"]}
