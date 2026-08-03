"""API 提供商定义：多模型支持（DeepSeek/OpenAI/Anthropic/Ollama/自定义）。

参考 GitHub 开源项目（Open WebUI/Lobe Chat 等）的多提供商模式。
"""
from __future__ import annotations

PROVIDERS: dict[str, dict] = {
    "deepseek": {
        "name": "DeepSeek",
        "base_url": "https://api.deepseek.com/anthropic",
        "models": ["deepseek-v4-pro", "deepseek-v4-flash", "deepseek-chat"],
        "default_model": "deepseek-v4-pro",
        "format": "anthropic",  # DeepSeek 使用 Anthropic 兼容格式
        "description": "DeepSeek 官方 API，国内推荐",
    },
    "openai": {
        "name": "OpenAI",
        "base_url": "https://api.openai.com/v1",
        "models": ["gpt-4o", "gpt-4o-mini", "gpt-4.1"],
        "default_model": "gpt-4o-mini",
        "format": "openai",
        "description": "OpenAI 官方 API（需要境外访问）",
    },
    "anthropic": {
        "name": "Anthropic Claude",
        "base_url": "https://api.anthropic.com/v1",
        "models": ["claude-sonnet-4-20250514", "claude-3.5-sonnet"],
        "default_model": "claude-sonnet-4-20250514",
        "format": "anthropic",
        "description": "Anthropic 官方 API（需要境外访问）",
    },
    "ollama": {
        "name": "Ollama（本地）",
        "base_url": "http://localhost:11434/v1",
        "models": ["llama3", "qwen2.5", "mistral", "gemma2"],
        "default_model": "qwen2.5",
        "format": "openai",
        "description": "本地运行，免费且数据不出本机",
    },
    "custom": {
        "name": "自定义（OpenAI 兼容）",
        "base_url": "",
        "models": [],
        "default_model": "",
        "format": "openai",
        "description": "填入任意兼容 OpenAI 格式的 API 地址",
    },
}

# 配置默认值
DEFAULT_PROVIDER = "deepseek"
