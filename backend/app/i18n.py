"""国际化框架 —— 中英双语支持。

当前为 MVP 版：常见 UI 字符串映射表。
未来可扩展为 gettext 或 JSON 翻译文件。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

TRANSLATIONS: dict[str, dict[str, str]] = {
    "connect_error": {
        "zh": "连接服务器失败",
        "en": "Connection to server failed",
    },
    "no_reply": {
        "zh": "未收到有效回复",
        "en": "No valid response received",
    },
    "server_error": {
        "zh": "服务器内部错误，请重试",
        "en": "Internal server error, please retry",
    },
    "thinking": {
        "zh": "正在思考",
        "en": "Thinking…",
    },
    "scan_complete_clean": {
        "zh": "检测完成，未发现明显风险",
        "en": "Scan complete — no significant risks found",
    },
    "scan_complete_risks": {
        "zh": "检测完成：发现 {count} 项风险",
        "en": "Scan complete: {count} risks found",
    },
    "session_load_failed": {
        "zh": "加载会话失败",
        "en": "Failed to load session",
    },
    "update_available": {
        "zh": "发现新版本 v{version}",
        "en": "New version v{version} available",
    },
    "wsc_registered": {
        "zh": "已注册到 Windows 安全中心",
        "en": "Registered with Windows Security Center",
    },
    "kb_updating": {
        "zh": "威胁情报自动更新：等待首次同步…",
        "en": "Threat intelligence auto-update: awaiting first sync…",
    },
    "kb_synced": {
        "zh": "威胁情报自动更新 · 病毒库 {hashes} 样本 · 恶意域名 {domains}",
        "en": "Threat intel auto-update · {hashes} hashes · {domains} malicious domains",
    },
}

_current_lang: str = "zh"


def set_language(lang: str) -> None:
    global _current_lang
    _current_lang = lang if lang in ("zh", "en") else "zh"


def t(key: str, **kwargs) -> str:
    """翻译指定 key，支持 {var} 插值。"""
    entry = TRANSLATIONS.get(key, {})
    text = entry.get(_current_lang, entry.get("zh", key))
    if kwargs:
        for k, v in kwargs.items():
            text = text.replace(f"{{{k}}}", str(v))
    return text


def detect_language(accept_header: Optional[str] = None) -> str:
    """从 Accept-Language 头检测语言。"""
    if not accept_header:
        return "zh"
    if "zh" in accept_header.lower():
        return "zh"
    if "en" in accept_header.lower():
        return "en"
    return "zh"
