"""应用配置管理器：读写 config.json（多提供商支持）。

优先级：config.json > .env 环境变量 > 默认值
首次启动未配置时提示 setup 向导。
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

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
    """获取 API Key（优先 config.json，其次环境变量）。"""
    cfg = _read()
    return cfg.get("api_key") or ""


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
    """保存配置到 config.json。"""
    pdef = PROVIDERS.get(provider, PROVIDERS[DEFAULT_PROVIDER])
    cfg = {
        "provider": provider,
        "api_key": api_key.strip(),
        "base_url": base_url.strip() or pdef.get("base_url", ""),
        "model": model.strip() or pdef.get("default_model", ""),
    }
    _write(cfg)
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
