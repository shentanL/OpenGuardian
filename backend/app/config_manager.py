"""应用配置管理器：读写 config.json（多提供商支持）。

优先级：config.json > .env 环境变量 > 默认值
首次启动未配置时提示 setup 向导。
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from .crypto_storage import decrypt_api_key, encrypt_api_key, migrate_to_encrypted
from .llm.providers import DEFAULT_PROVIDER, PROVIDERS

logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config.json"
# PyInstaller 打包修正：config.json 允许写入 AppData
import sys as _sys
if getattr(_sys, "frozen", False):
    CONFIG_PATH = Path.home() / "AppData" / "Local" / "OpenGuardian" / "config.json"
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)


def _read() -> dict:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            pass
    return {}


def _write(cfg: dict) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")


def get_provider() -> str:
    """当前选中的提供商 key。"""
    cfg = _read()
    return cfg.get("provider") or DEFAULT_PROVIDER


def get_api_key() -> str:
    """获取 API Key（config.json → .env 环境变量 → 自动迁移明文为加密）。"""
    cfg = _read()
    stored = cfg.get("api_key") or ""
    if stored:
        # 首次读取时自动将明文迁移为加密存储
        if not stored.startswith("og_enc_v1:"):
            encrypted, _ = encrypt_api_key(stored)
            if encrypted:
                cfg["api_key"] = encrypted
                _write(cfg)
                logger.info("API Key 已自动从明文升级为加密存储")
                return stored  # 返回原始明文
        else:
            decrypted = decrypt_api_key(stored)
            if decrypted:
                return decrypted
            # 解密失败（换了机器/重装系统）→ 密钥已失效
            logger.warning("API Key 解密失败（机器绑定密钥不匹配），请重新配置")
            return ""
    # 回退：从 .env 读取
    import os as _os
    key = ""
    try:
        from dotenv import load_dotenv
        # frozen 时 .env 在 _MEIPASS/backend/，dev 时在 backend/
        import sys as _sys
        if getattr(_sys, "frozen", False):
            env_path = Path(_sys._MEIPASS) / "backend" / ".env"
        else:
            env_path = Path(__file__).resolve().parent.parent / ".env"
        if env_path.exists():
            load_dotenv(env_path)
            key = _os.getenv("DEEPSEEK_API_KEY") or ""
            if key:
                cfg["api_key"] = key
                CONFIG_PATH.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass
    return key


def get_base_url() -> str:
    """获取 API 端点（优先 config 中自定义，其次提供商默认值）。"""
    cfg = _read()
    provider = cfg.get("provider") or DEFAULT_PROVIDER
    return cfg.get("base_url") or PROVIDERS.get(provider, {}).get("base_url", "")


def get_model() -> str:
    """获取模型名（优先 config 中自定义，其次提供商默认值）。"""
    cfg = _read()
    provider = cfg.get("provider") or DEFAULT_PROVIDER
    return cfg.get("model") or PROVIDERS.get(provider, {}).get("default_model", "")


def get_format() -> str:
    """API 格式：openai 或 anthropic。"""
    cfg = _read()
    provider = cfg.get("provider") or DEFAULT_PROVIDER
    return PROVIDERS.get(provider, {}).get("format", "openai")


def is_configured() -> bool:
    """是否已完成配置（有 API Key 或安装了本地模型）。"""
    cfg = _read()
    provider = cfg.get("provider") or DEFAULT_PROVIDER
    if provider == "ollama":
        return True  # 本地模型不需要 Key
    return bool(cfg.get("api_key"))


def save_config(provider: str, api_key: str = "", base_url: str = "", model: str = "") -> dict:
    """保存配置到 config.json。

    api_key 为空字符串时保留旧值（用于设置面板留空不变更的场景）。
    base_url / model 同理。
    """
    old = _read()
    pdef = PROVIDERS.get(provider, PROVIDERS[DEFAULT_PROVIDER])
    # 仅当提供商相同时才保留旧 Key（防止 DeepSeek Key 被写入 OpenAI 配置）
    preserved_key = old.get("api_key", "") if old.get("provider") == provider else ""
    # 加密存储 API Key
    final_key = ""
    if api_key.strip():
        encrypted, _ = encrypt_api_key(api_key.strip())
        final_key = encrypted or api_key.strip()  # 加密失败则回退明文
    else:
        final_key = preserved_key  # 保留旧值（已加密或明文）
    cfg = {
        "provider": provider,
        "api_key": final_key,
        "base_url": base_url.strip() or pdef.get("base_url", ""),
        "model": model.strip() or pdef.get("default_model", ""),
    }
    _write(cfg)
    # 使 LLM 客户端失效，下次请求自动使用新配置
    try:
        from .llm.client import invalidate_llm_client
        invalidate_llm_client()
    except Exception:
        pass
    return {"ok": True, **cfg}


def get_all_providers() -> list[dict]:
    """获取所有提供商信息（供前端选择器渲染）。"""
    result: list[dict] = []
    for key, pdef in PROVIDERS.items():
        result.append({
            "key": key,
            "name": pdef["name"],
            "description": pdef.get("description", ""),
            "default_model": pdef.get("default_model", ""),
            "models": pdef.get("models", []),
        })
    return result
