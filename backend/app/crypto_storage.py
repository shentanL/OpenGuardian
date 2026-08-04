r"""API Key 加密存储（Windows 机器绑定加密，纯标准库）。

加密方案：
- 密钥派生：MachineGuid (HKLM\SOFTWARE\Microsoft\Cryptography) + 固定盐 → PBKDF2-SHA256
- 加密：AES-256-GCM 的纯 Python 实现备选 → XOR + HMAC 认证加密
- 绑定本机：加密密钥依赖 Windows 安装的唯一 GUID，更换机器/重装系统后无法解密

安全级别：中等（非硬件安全模块级别，但远优于明文存储，适合个人桌面应用）。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets as _secrets
from pathlib import Path
from typing import Optional, Tuple


# ---- 机器唯一标识 ----

def _get_machine_guid() -> str:
    """获取 Windows 机器唯一 GUID（注册表 MachineGuid）。"""
    import sys
    if sys.platform != "win32":
        # 非 Windows：回退到主机名 + 用户名哈希
        import socket
        return hashlib.sha256(
            f"{socket.gethostname()}:{os.environ.get('USER', 'unknown')}".encode()
        ).hexdigest()

    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography"
        ) as key:
            guid, _ = winreg.QueryValueEx(key, "MachineGuid")
            return str(guid)
    except OSError:
        # 注册表不可用时回退
        import socket
        return hashlib.sha256(
            f"{socket.gethostname()}:{os.environ.get('COMPUTERNAME', 'unknown')}".encode()
        ).hexdigest()


# ---- 密钥派生 ----

_SALT = b"OpenGuardian:crypto-v1"  # 固定盐（非机密，用于防彩虹表）


def _derive_key(machine_guid: str) -> bytes:
    """从 MachineGuid + 固定盐派生 32 字节加密密钥（PBKDF2-SHA256）。"""
    return hashlib.pbkdf2_hmac(
        "sha256",
        machine_guid.encode("utf-8"),
        _SALT,
        iterations=200_000,  # OWASP 推荐 ≥ 130,000
        dklen=32,
    )


# ---- XOR + HMAC 认证加密 ----


def _encrypt(plaintext: str, key: bytes) -> str:
    """XOR 加密 + HMAC-SHA256 认证。

    密文格式: base64(nonce:16 + ciphertext + hmac:32)
    """
    data = plaintext.encode("utf-8")
    nonce = _secrets.token_bytes(16)
    # 用 nonce + key 生成密钥流
    stream_key = hashlib.sha256(nonce + key).digest()
    # XOR（循环使用密钥流）
    ciphertext = bytes(
        data[i] ^ stream_key[i % len(stream_key)] for i in range(len(data))
    )
    # HMAC 认证
    mac = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    # 格式: nonce | ciphertext | hmac
    packed = nonce + ciphertext + mac
    return base64.b64encode(packed).decode("ascii")


def _decrypt(encrypted: str, key: bytes) -> Optional[str]:
    """解密，HMAC 不匹配或格式错误返回 None。"""
    try:
        packed = base64.b64decode(encrypted.encode("ascii"))
    except Exception:
        return None

    if len(packed) < 16 + 1 + 32:  # nonce + 至少 1 字节数据 + hmac
        return None

    nonce = packed[:16]
    mac_received = packed[-32:]
    ciphertext = packed[16:-32]

    # 验证 HMAC
    mac_expected = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac_received, mac_expected):
        return None  # 数据被篡改或密钥不匹配

    # 解密
    stream_key = hashlib.sha256(nonce + key).digest()
    plaintext = bytes(
        ciphertext[i] ^ stream_key[i % len(stream_key)] for i in range(len(ciphertext))
    )
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError:
        return None


# ---- 单例密钥缓存 ----

_key_cache: dict[str, bytes] = {}


def _get_crypto_key() -> bytes:
    """获取或派生本机加密密钥（带缓存）。"""
    guid = _get_machine_guid()
    if guid not in _key_cache:
        _key_cache[guid] = _derive_key(guid)
    return _key_cache[guid]


# ---- 公开 API ----


def encrypt_api_key(plaintext_key: str) -> Tuple[str, str]:
    """加密 API Key，返回 (encrypted_value, marker)。

    encrypted_value — base64 密文
    marker — 固定前缀，用于识别已加密的值
    """
    if not plaintext_key or not plaintext_key.strip():
        return "", ""
    key = _get_crypto_key()
    encrypted = _encrypt(plaintext_key.strip(), key)
    marker = "og_enc_v1:"
    return f"{marker}{encrypted}", marker


def decrypt_api_key(stored_value: str) -> str:
    """解密 API Key。

    - 如果值以加密标记开头 → 解密返回
    - 如果是明文旧值 → 直接返回（兼容老配置）
    - 解密失败 → 返回空字符串
    """
    if not stored_value or not stored_value.strip():
        return ""

    val = stored_value.strip()
    marker = "og_enc_v1:"

    if val.startswith(marker):
        encrypted = val[len(marker):]
        key = _get_crypto_key()
        result = _decrypt(encrypted, key)
        return result or ""

    # 明文旧值（兼容性）：直接返回，并提示升级
    return val


def migrate_to_encrypted(config_path: Path) -> bool:
    """将 config.json 中的明文 API Key 升级为加密存储。

    返回 True 表示已迁移（或无需迁移）。
    """
    import json
    config_path = Path(config_path) if not isinstance(config_path, Path) else config_path
    if not config_path.exists():
        return False

    try:
        cfg = json.loads(config_path.read_text(encoding="utf-8"))
        api_key = cfg.get("api_key", "")
        if not api_key:
            return False
        if api_key.startswith("og_enc_v1:"):
            return True  # 已经加密

        # 加密并写回
        encrypted, _ = encrypt_api_key(api_key)
        if encrypted:
            cfg["api_key"] = encrypted
            config_path.write_text(
                json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            return True
    except Exception:
        pass
    return False
