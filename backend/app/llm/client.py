"""LLM 客户端：封装 DeepSeek API（OpenAI 兼容格式）。

设计要点：
- 所有调用带超时与异常捕获，失败返回 None，由调用方降级。
- chat_json() 强制模型输出 JSON（用于意图识别）。
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

DEFAULT_SYSTEM = (
    "你是 OpenGuardian——一个面向普通用户的个人数字安全助手。"
    "你的回答必须：通俗易懂（避免专业术语堆砌）、简洁（一般不超过150字）、"
    "实用（给出可操作的建议）。"
)


class LLMClient:
    def __init__(self) -> None:
        from ..config_manager import get_api_key, get_base_url, get_format, get_model

        self.api_key = get_api_key() or settings.DEEPSEEK_API_KEY
        self.base_url = get_base_url() or settings.DEEPSEEK_BASE_URL
        self.model = get_model() or settings.LLM_MODEL
        self.api_format = get_format() or "anthropic"  # openai 或 anthropic
        self.timeout = settings.LLM_TIMEOUT
        # 动态 API 端点（多提供商支持）
        self.chat_url = f"{self.base_url.rstrip('/')}/chat/completions" if self.base_url else "https://api.deepseek.com/chat/completions"

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    async def chat(
        self,
        messages: list[dict],
        system: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: float = 0.7,
    ) -> Optional[str]:
        """普通对话，返回文本。失败返回 None。支持 OpenAI/Anthropic/Gemini 格式。"""
        if not self.available:
            logger.warning("LLM not configured: API key missing")
            return None

        payload_messages: list[dict] = []
        if system:
            payload_messages.append({"role": "system", "content": system})
        payload_messages.extend(messages)

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                headers = {"Authorization": f"Bearer {self.api_key}"}
                json_body: dict = {
                    "model": self.model,
                    "temperature": temperature,
                    "max_tokens": max_tokens or settings.LLM_MAX_TOKENS,
                }
                url = self.chat_url

                # 格式适配（仅 Anthropic 需特殊处理）
                if self.api_format == "anthropic":
                    headers = {
                        "x-api-key": self.api_key,
                        "anthropic-version": "2023-06-01",
                    }
                    url = f"{self.base_url.rstrip('/')}/v1/messages"
                    # Anthropic 用 system 字段（不是 role:system 的消息）
                    sys_text = None
                    filtered_msgs = []
                    for m in payload_messages:
                        if m["role"] == "system":
                            sys_text = m["content"]
                        else:
                            filtered_msgs.append(m)
                    json_body["system"] = sys_text or ""
                    json_body["messages"] = filtered_msgs
                else:
                    # OpenAI 兼容格式（默认）
                    json_body["messages"] = payload_messages

                resp = await client.post(url, headers=headers, json=json_body)
                resp.raise_for_status()
                data = resp.json()

                # 响应解析
                if self.api_format == "anthropic":
                    # Anthropic: content[0].text
                    content = data.get("content", [])
                    if isinstance(content, list) and content:
                        return content[0].get("text", "")
                    return str(content)
                else:
                    # OpenAI 兼容: choices[0].message.content
                    return data["choices"][0]["message"]["content"]

        except Exception as exc:  # noqa: BLE001
            logger.warning("LLM chat failed (attempt 1): %s", exc)
            # 重试一次
            try:
                async with httpx.AsyncClient(timeout=self.timeout + 10) as client:
                    resp = await client.post(url, headers=headers, json=json_body)
                    resp.raise_for_status()
                    data = resp.json()
                    if self.api_format == "anthropic":
                        content = data.get("content", [])
                        return content[0].get("text", "") if isinstance(content, list) and content else str(content)
                    return data["choices"][0]["message"]["content"]
            except Exception as exc2:
                logger.warning("LLM chat failed (attempt 2): %s", exc2)
                return None

    async def chat_json(
        self,
        messages: list[dict],
        system: str,
        fallback: dict,
        temperature: float = 0.2,
    ) -> dict[str, Any]:
        """要求模型输出 JSON；失败或解析失败返回 fallback。"""
        text = await self.chat(
            messages,
            system=system + "\n请只输出 JSON，不要输出任何其他文字。",
            temperature=temperature,
        )
        if not text:
            return fallback
        try:
            # 兼容模型偶尔用 ```json 包裹
            cleaned = text.strip()
            if cleaned.startswith("```"):
                cleaned = cleaned.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
            return json.loads(cleaned)
        except json.JSONDecodeError:
            logger.warning("LLM JSON parse failed, using fallback: %r", text[:100])
            return fallback

    async def stream_chat(
        self,
        messages: list[dict],
        system: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: float = 0.7,
    ):
        """流式对话：异步生成器，逐块产出文本。失败时产出 None 结束。"""
        if not self.available:
            logger.warning("LLM not configured: DEEPSEEK_API_KEY missing")
            return
        payload_messages: list[dict] = []
        if system:
            payload_messages.append({"role": "system", "content": system})
        payload_messages.extend(messages)

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                async with client.stream(
                    "POST",
                    self.chat_url,
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json={
                        "model": self.model,
                        "messages": payload_messages,
                        "temperature": temperature,
                        "max_tokens": max_tokens or settings.LLM_MAX_TOKENS,
                        "stream": True,
                    },
                ) as resp:
                    resp.raise_for_status()
                    async for line in resp.aiter_lines():
                        if not line.startswith("data:"):
                            continue
                        data = line[5:].strip()
                        if data == "[DONE]":
                            break
                        try:
                            chunk = json.loads(data)
                            delta = chunk["choices"][0]["delta"].get("content")
                            if delta:
                                yield delta
                        except (json.JSONDecodeError, KeyError, IndexError):
                            continue
        except Exception as exc:  # noqa: BLE001
            logger.warning("LLM stream failed: %s", exc)


_llm_client: Optional[LLMClient] = None


def get_llm_client() -> LLMClient:
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClient()
    return _llm_client
