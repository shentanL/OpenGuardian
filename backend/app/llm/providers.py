"""API 提供商定义：多模型支持（DeepSeek/OpenAI/Anthropic/Ollama/自定义）。

参考 GitHub 开源项目（Open WebUI/Lobe Chat 等）的多提供商模式。
"""
from __future__ import annotations

PROVIDERS: dict[str, dict] = {
    # ---- 🇨🇳 国内主流 ----
    "deepseek": {
        "name": "DeepSeek（深度求索）",
        "base_url": "https://api.deepseek.com/anthropic",
        "models": ["deepseek-v4-pro", "deepseek-v4-flash", "deepseek-chat"],
        "default_model": "deepseek-v4-pro",
        "format": "anthropic",
        "description": "DeepSeek 官方 API，推荐首选",
    },
    "kimi": {
        "name": "Kimi（月之暗面）",
        "base_url": "https://api.moonshot.cn/v1",
        "models": ["moonshot-v1-8k", "moonshot-v1-32k", "moonshot-v1-128k"],
        "default_model": "moonshot-v1-32k",
        "format": "openai",
        "description": "月之暗面 Kimi，支持超长上下文（128K）",
    },
    "zhipu": {
        "name": "智谱 GLM（清言）",
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "models": ["glm-4-flash", "glm-4-plus", "glm-4-air"],
        "default_model": "glm-4-flash",
        "format": "openai",
        "description": "智谱 AI GLM 系列，国内高校免费额度最友好",
    },
    "qwen": {
        "name": "通义千问（阿里云）",
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "models": ["qwen-plus", "qwen-max", "qwen-turbo"],
        "default_model": "qwen-plus",
        "format": "openai",
        "description": "阿里云通义千问，国内可用",
    },
    "doubao": {
        "name": "豆包/DeepSeek（字节跳动）",
        "base_url": "https://ark.cn-beijing.volces.com/api/v3",
        "models": ["ep-deepseek-v4", "doubao-pro-32k", "doubao-lite-32k"],
        "default_model": "ep-deepseek-v4",
        "format": "openai",
        "description": "字节豆包模型或火山引擎接入的 DeepSeek",
    },
    "minimax": {
        "name": "MiniMax（海螺 AI）",
        "base_url": "https://api.minimax.chat/v1",
        "models": ["abab6.5s-chat", "abab6.5t-chat"],
        "default_model": "abab6.5s-chat",
        "format": "openai",
        "description": "MiniMax 海螺 AI，国内可用",
    },
    "baichuan": {
        "name": "百川智能",
        "base_url": "https://api.baichuan-ai.com/v1",
        "models": ["Baichuan4-Air", "Baichuan4", "Baichuan3-Turbo"],
        "default_model": "Baichuan4-Air",
        "format": "openai",
        "description": "百川智能大模型，国内可用",
    },
    "ernie": {
        "name": "文心一言（百度）",
        "base_url": "https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/chat",
        "models": ["ernie-4.0-8k", "ernie-speed-128k"],
        "default_model": "ernie-speed-128k",
        "format": "openai",
        "description": "百度文心大模型，国内可用",
    },
    # ---- 🌍 国际 ----
    "openai": {
        "name": "OpenAI（ChatGPT）",
        "base_url": "https://api.openai.com/v1",
        "models": ["gpt-4o", "gpt-4o-mini", "gpt-4.1"],
        "default_model": "gpt-4o-mini",
        "format": "openai",
        "description": "OpenAI 官方 API，需要境外网络",
    },
    "anthropic": {
        "name": "Anthropic Claude",
        "base_url": "https://api.anthropic.com/v1",
        "models": ["claude-sonnet-4-20250514", "claude-3.5-sonnet"],
        "default_model": "claude-sonnet-4-20250514",
        "format": "anthropic",
        "description": "Anthropic 官方 API，需要境外网络",
    },
    # ---- 本地 / 其他 ----
    "ollama": {
        "name": "Ollama（本地运行）",
        "base_url": "http://localhost:11434/v1",
        "models": ["llama3", "qwen2.5", "mistral", "gemma2"],
        "default_model": "qwen2.5",
        "format": "openai",
        "description": "完全免费，数据不出本机，无需 API Key",
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
