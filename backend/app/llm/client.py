"""LLM 客户端：连接池复用 + 指数退避重试 + 流降级。

设计要点：
- 单例 httpx.AsyncClient 连接池（避免每次请求重建 TCP）
- 3 次指数退避重试（1s/2s/4s），自动处理网络波动
- 流式失败自动降级为非流式
- 支持 OpenAI/Anthropic 多格式
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, AsyncIterator, Optional

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
RETRY_BASE_DELAY = 1.0  # 秒


class LLMClient:
    def __init__(self) -> None:
        from ..config_manager import get_api_key, get_base_url, get_format, get_model

        self.api_key = get_api_key() or settings.DEEPSEEK_API_KEY
        self.base_url = get_base_url() or settings.DEEPSEEK_BASE_URL
        self.model = get_model() or settings.LLM_MODEL
        self.api_format = get_format() or "openai"
        self.timeout = settings.LLM_TIMEOUT

        # 共享连接池（复用 TCP 连接）
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout, connect=10.0),
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=20),
        )

        # 构建端点
        if self.api_format == "anthropic":
            self.chat_url = f"{self.base_url.rstrip('/')}/v1/messages"
        else:
            self.chat_url = f"{self.base_url.rstrip('/')}/chat/completions" if self.base_url else "https://api.deepseek.com/chat/completions"

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    # ═══ 内部工具 ═══

    def _build_request(
        self, messages: list[dict], system: Optional[str] = None,
        max_tokens: Optional[int] = None, temperature: float = 0.7, stream: bool = False,
    ) -> tuple[dict, dict, str]:
        """构建请求头、请求体、URL。"""
        payload_messages: list[dict] = []
        if system:
            payload_messages.append({"role": "system", "content": system})
        payload_messages.extend(messages)

        json_body: dict = {
            "model": self.model,
            "temperature": temperature,
            "max_tokens": max_tokens or settings.LLM_MAX_TOKENS,
        }
        if stream:
            json_body["stream"] = True

        url = self.chat_url

        if self.api_format == "anthropic":
            headers = {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"}
            url = f"{self.base_url.rstrip('/')}/v1/messages"
            sys_text = ""
            filtered = [m for m in payload_messages if m["role"] != "system"]
            for m in payload_messages:
                if m["role"] == "system":
                    sys_text = m["content"]
            json_body["system"] = sys_text
            json_body["messages"] = filtered
            if stream:
                del json_body["stream"]  # Anthropic uses different streaming
        else:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            json_body["messages"] = payload_messages

        return headers, json_body, url

    @staticmethod
    def _parse_response(data: dict, api_format: str) -> str:
        """解析 LLM 响应，返回文本。"""
        if api_format == "anthropic":
            content = data.get("content", [])
            if isinstance(content, list) and content:
                return content[0].get("text", "")
            return str(content)
        return data["choices"][0]["message"]["content"]

    async def _request_with_retry(
        self, headers: dict, json_body: dict, url: str,
    ) -> Optional[dict]:
        """POST 请求 + 指数退避重试，返回 JSON 或 None。"""
        last_exc = None
        for attempt in range(MAX_RETRIES):
            try:
                resp = await self._client.post(url, headers=headers, json=json_body)
                resp.raise_for_status()
                return resp.json()
            except Exception as exc:
                last_exc = exc
                if attempt < MAX_RETRIES - 1:
                    delay = RETRY_BASE_DELAY * (2 ** attempt)
                    logger.warning("LLM retry %d/%d in %.1fs: %s", attempt + 1, MAX_RETRIES, delay, exc)
                    await asyncio.sleep(delay)
        logger.warning("LLM failed after %d retries: %s", MAX_RETRIES, last_exc)
        return None

    # ═══ 公开 API ═══

    async def chat(
        self,
        messages: list[dict],
        system: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: float = 0.7,
    ) -> Optional[str]:
        """普通对话，返回文本。带指数退避重试。失败返回 None。"""
        if not self.available:
            return None

        headers, json_body, url = self._build_request(messages, system, max_tokens, temperature)
        data = await self._request_with_retry(headers, json_body, url)
        if data:
            return self._parse_response(data, self.api_format)
        return None

    async def chat_json(
        self,
        messages: list[dict],
        system: str,
        fallback: dict,
        temperature: float = 0.2,
    ) -> dict[str, Any]:
        """要求模型输出 JSON；失败返回 fallback。"""
        text = await self.chat(
            messages,
            system=system + "\n请只输出 JSON，不要输出任何其他文字。",
            temperature=temperature,
        )
        if not text:
            return fallback
        try:
            cleaned = text.strip()
            if cleaned.startswith("```"):
                cleaned = cleaned.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
            return json.loads(cleaned)
        except json.JSONDecodeError:
            logger.warning("LLM JSON parse failed, using fallback")
            return fallback

    async def stream_chat(
        self,
        messages: list[dict],
        system: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: float = 0.7,
    ) -> AsyncIterator[str]:
        """流式对话：异步生成器，逐块产出文本。

        失败时自动降级为非流式 chat() + 保底提示。
        """
        if not self.available:
            yield "（AI 服务未配置，请先在设置中填写 API Key）"
            return

        headers, json_body, url = self._build_request(messages, system, max_tokens, temperature, stream=True)

        # 尝试流式（重试 2 次）
        last_exc = None
        for attempt in range(2):
            try:
                async with self._client.stream("POST", url, headers=headers, json=json_body) as resp:
                    resp.raise_for_status()
                    async for line in resp.aiter_lines():
                        if not line.startswith("data:"):
                            continue
                        data = line[5:].strip()
                        if data == "[DONE]":
                            return
                        try:
                            chunk = json.loads(data)
                            delta = chunk["choices"][0]["delta"].get("content")
                            if delta:
                                yield delta
                        except (json.JSONDecodeError, KeyError, IndexError):
                            continue
                    return  # 正常结束
            except Exception as exc:
                last_exc = exc
                if attempt < 1:
                    await asyncio.sleep(1.0)
                    logger.warning("LLM stream retry %d/2: %s", attempt + 1, exc)

        # 流式失败 → 降级为非流式
        logger.warning("LLM stream failed after retries, falling back to non-stream")
        text = await self.chat(messages, system=system, max_tokens=max_tokens, temperature=temperature)
        if text:
            yield text
        else:
            yield "（服务暂时无法连接 AI，请稍后重试。提示：检查网络或更换 API 提供商）"


# 全局单例
_llm_client: Optional[LLMClient] = None


def get_llm_client() -> LLMClient:
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClient()
    return _llm_client
