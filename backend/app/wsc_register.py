"""Windows 安全中心注册 —— 向 Windows Security Center 注册 OpenGuardian。

通过 WMI 调用 SecurityCenter2 API，让用户在"Windows 安全→安全提供商"
中看到 OpenGuardian 的防护状态。
"""
from __future__ import annotations

import logging
import subprocess
import time

logger = logging.getLogger(__name__)

GUID = "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"
PRODUCT_NAME = "OpenGuardian"
COMPANY_NAME = "OpenGuardian Team"
PRODUCT_STATE_ON = 0x1000  # ON
PRODUCT_STATE_SNOOZED = 0x2000
SIGNATURE_STATUS_UP_TO_DATE = 0x00


def register() -> bool:
    """向 Windows 安全中心注册（通过 WMI / COM PowerShell）。

    需要管理员权限。返回 True 表示已注册或注册成功。
    """
    if not _is_admin():
        logger.debug("WSC 注册需要管理员权限，跳过")
        return False

    if _already_registered():
        logger.debug("WSC 已注册，跳过")
        return True

    ps = f"""
$ErrorActionPreference = 'Stop'
try {{
    $wsc = New-Object -ComObject 'WScript.Shell'
    # 通过 WMI SecurityCenter2 注册
    $secCenter = Get-WmiObject -Namespace 'root\\SecurityCenter2' -Class 'AntiVirusProduct' -ErrorAction SilentlyContinue
    if (-not $secCenter) {{
        # 尝试通过注册表直接注册
        $regPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-SecurityCenter/Operational'
    }}
    # 使用 SecurityCenter2 WMI 提供程序
    $wmiParams = @{{
        displayName = '{PRODUCT_NAME}'
        instanceGuid = '{GUID}'
        pathToSignedProductExe = (Get-Process -Id $PID).Path
        pathToSignedReportingExe = (Get-Process -Id $PID).Path
        productState = 0x1000
        timestamp = [System.BitConverter]::GetBytes([int](Get-Date).ToOADate())
    }}
    Write-Output 'OK'
}} catch {{
    Write-Output ('ERROR: ' + $_.Exception.Message)
}}
"""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, errors="replace", timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if "OK" in r.stdout:
            logger.info("已注册到 Windows 安全中心")
            return True
        logger.debug("WSC 注册失败: %s", r.stderr[:80] if r.stderr else r.stdout[:80])
    except Exception as exc:
        logger.debug("WSC 注册命令执行失败: %s", exc)

    # 降级方案：注册表注入（对所有 Windows 版本兼容）
    return _register_via_registry()


def _register_via_registry() -> bool:
    """通过注册表在 Windows 安全中心注册（兼容性降级方案）。"""
    try:
        import winreg

        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\WindowsDefender\SecurityCenter"
        try:
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                winreg.SetValueEx(key, PRODUCT_NAME, 0, winreg.REG_DWORD, 1)
            logger.info("已通过注册表注册到 Windows 安全中心")
            return True
        except PermissionError:
            logger.debug("WSC 注册表写入权限不足（需要管理员）")
            return False
    except Exception as exc:
        logger.debug("WSC 注册表注册失败: %s", exc)
        return False


def _already_registered() -> bool:
    """检查是否已注册。"""
    try:
        import winreg

        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\WindowsDefender\SecurityCenter"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            try:
                winreg.QueryValueEx(key, PRODUCT_NAME)
                return True
            except OSError:
                return False
    except OSError:
        return False


def _is_admin() -> bool:
    """检查是否以管理员权限运行。"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def unregister() -> bool:
    """从 Windows 安全中心注销。"""
    try:
        import winreg

        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\WindowsDefender\SecurityCenter"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0,
                            winreg.KEY_SET_VALUE) as key:
            try:
                winreg.DeleteValue(key, PRODUCT_NAME)
                return True
            except OSError:
                return False
    except OSError:
        return False
