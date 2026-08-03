"""API 提供商定义：多模型支持（12 家，模型名来自各官方文档）。

格式说明：
- openai: 标准 OpenAI 兼容 → POST /v1/chat/completions
- anthropic: Anthropic 兼容 → POST /v1/messages（仅 DeepSeek 使用）
- 文心一言使用非标准 API，标记为 advanced 格式（需单独适配）
"""
from __future__ import annotations

PROVIDERS: dict[str, dict] = {
    # ---- 🇨🇳 国内主流（OpenAI 兼容） ----
    "deepseek": {
        "name": "DeepSeek（深度求索）",
        "base_url": "https://api.deepseek.com/anthropic",
        "models": ["deepseek-chat", "deepseek-reasoner"],
        "default_model": "deepseek-chat",
        "format": "anthropic",
        "description": "DeepSeek 官方 API（Anthropic 兼容端点）。deepseek-chat=V3, deepseek-reasoner=R1",
    },
    "kimi": {
        "name": "Kimi（月之暗面）",
        "base_url": "https://api.moonshot.cn/v1",
        "models": ["moonshot-v1-8k", "moonshot-v1-32k", "moonshot-v1-128k"],
        "default_model": "moonshot-v1-32k",
        "format": "openai",
        "description": "月之暗面 Kimi。128k 版支持超长上下文",
    },
    "zhipu": {
        "name": "智谱 GLM",
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "models": ["glm-4-flash", "glm-4-plus", "glm-4-air", "glm-4"],
        "default_model": "glm-4-flash",
        "format": "openai",
        "description": "智谱 AI GLM 系列。glm-4-flash 免费额度最友好",
    },
    "qwen": {
        "name": "通义千问（阿里云）",
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "models": ["qwen-turbo", "qwen-plus", "qwen-max", "qwen-long"],
        "default_model": "qwen-turbo",
        "format": "openai",
        "description": "阿里云百炼平台。qwen-turbo 性价比最高",
    },
    "doubao": {
        "name": "豆包（字节跳动）",
        "base_url": "https://ark.cn-beijing.volces.com/api/v3",
        "models": ["doubao-pro-32k", "doubao-lite-32k", "doubao-pro-4k"],
        "default_model": "doubao-lite-32k",
        "format": "openai",
        "description": "字节火山引擎豆包大模型",
    },
    "minimax": {
        "name": "MiniMax（海螺 AI）",
        "base_url": "https://api.minimax.chat/v1",
        "models": ["abab6.5s-chat", "abab6.5t-chat", "abab7-chat-preview"],
        "default_model": "abab6.5s-chat",
        "format": "openai",
        "description": "MiniMax 海螺 AI。abab6.5s 为标准版",
    },
    "baichuan": {
        "name": "百川智能",
        "base_url": "https://api.baichuan-ai.com/v1",
        "models": ["Baichuan4-Air", "Baichuan4", "Baichuan3-Turbo"],
        "default_model": "Baichuan4-Air",
        "format": "openai",
        "description": "百川智能大模型",
    },
    # ---- 🌍 国际 ----
    "openai": {
        "name": "OpenAI（ChatGPT）",
        "base_url": "https://api.openai.com/v1",
        "models": ["gpt-4o", "gpt-4o-mini", "gpt-4.1"],
        "default_model": "gpt-4o-mini",
        "format": "openai",
        "description": "OpenAI 官方 API。gpt-4o-mini 性价比最高",
    },
    "anthropic": {
        "name": "Anthropic Claude",
        "base_url": "https://api.anthropic.com/v1",
        "models": ["claude-sonnet-4-20250514", "claude-3.5-sonnet"],
        "default_model": "claude-sonnet-4-20250514",
        "format": "anthropic",
        "description": "Anthropic 官方 API（Anthropic 原生格式）",
    },
    # ---- 本地 / 自定义 ----
    "ollama": {
        "name": "Ollama（本地运行）",
        "base_url": "http://localhost:11434/v1",
        "models": ["llama3.2", "qwen2.5", "mistral", "gemma2"],
        "default_model": "qwen2.5",
        "format": "openai",
        "description": "完全免费、数据不出本机、无需 Key。需先安装 Ollama 并拉取模型",
    },
    "custom": {
        "name": "自定义（OpenAI 兼容）",
        "base_url": "",
        "models": [],
        "default_model": "",
        "format": "openai",
        "description": "填入任意兼容 OpenAI 格式的 API 地址和模型名",
    },
}

DEFAULT_PROVIDER = "deepseek"
