"""LLM 客户端：连接池复用 + 指数退避重试 + 流降级。

设计要点：
- 单例 httpx.AsyncClient 连接池（避免每次请求重建 TCP）
- 3 次指数退避重试（1s/2s/4s），自动处理网络波动
- 流式失败自动降级为非流式
- 支持 OpenAI/Anthropic 多格式
- 线程安全的单例生命周期管理
"""
from __future__ import annotations

import asyncio
import json
import logging
import threading
from typing import Any, AsyncIterator, Optional

import httpx

from ..config import settings
from ..prompts import FALLBACK_AI_UNAVAILABLE, FALLBACK_AI_RETRY

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
RETRY_BASE_DELAY = 1.0  # 秒


class LLMClient:
    def _offline_reply(self, messages: list[dict]) -> str:
        """LLM 彻底不可用时，用离线规则引擎生成有意义的回复。"""
        try:
            from .offline_fallback import smart_reply
            user_text = ""
            for m in reversed(messages or []):
                if m.get("role") == "user":
                    user_text = str(m.get("content", ""))
                    break
            return smart_reply(user_text or "")
        except Exception:
            return FALLBACK_AI_RETRY

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
                json_body["stream"] = True
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
        max_tokens: Optional[int] = None,
    ) -> dict[str, Any]:
        """要求模型输出 JSON；失败返回 fallback。"""
        text = await self.chat(
            messages,
            system=system + "\n请只输出 JSON，不要输出任何其他文字。",
            temperature=temperature,
            max_tokens=max_tokens,
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
        支持 OpenAI 和 Anthropic 两种 SSE 格式。
        """
        if not self.available:
            yield FALLBACK_AI_UNAVAILABLE
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
                        data_str = line[5:].strip()
                        if data_str == "[DONE]":
                            return
                        try:
                            chunk = json.loads(data_str)
                            # OpenAI 格式: {"choices": [{"delta": {"content": "..."}}]}
                            if "choices" in chunk:
                                delta = chunk["choices"][0].get("delta", {})
                                if "content" in delta and delta["content"]:
                                    yield delta["content"]
                            # Anthropic 格式: {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "..."}}
                            elif chunk.get("type") == "content_block_delta":
                                delta = chunk.get("delta", {})
                                if delta.get("type") == "text_delta":
                                    text = delta.get("text", "")
                                    if text:
                                        yield text
                            # Anthropic message_start / content_block_start / message_delta / ping — 忽略
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
            # 彻底失败 → 离线智能降级（规则引擎 + 知识库，非"废物"文案）
            yield self._offline_reply(messages)


# 全局单例（线程安全）
_llm_client: Optional[LLMClient] = None
_llm_lock = threading.Lock()


def get_llm_client() -> LLMClient:
    """获取 LLM 客户端单例（线程安全）。"""
    global _llm_client
    if _llm_client is not None:
        return _llm_client
    with _llm_lock:
        if _llm_client is None:
            _llm_client = LLMClient()
            logger.info("LLM client initialized: %s", _llm_client.model)
        return _llm_client


def invalidate_llm_client() -> None:
    """配置变更后使 LLM 客户端失效（下次调用自动重新创建并读取新配置）。

    线程安全：加锁替换，旧客户端在新线程中异步关闭。
    """
    global _llm_client
    with _llm_lock:
        old = _llm_client
        _llm_client = None

    if old is None:
        return

    # 在新线程中安全关闭旧客户端的连接池
    def _close_client(client: httpx.AsyncClient) -> None:
        try:
            loop = asyncio.new_event_loop()
            loop.run_until_complete(client.aclose())
            loop.close()
        except Exception:
            pass

    threading.Thread(
        target=_close_client,
        args=(old._client,),
        daemon=True,
        name="llm-cleanup",
    ).start()
    logger.info("LLM client invalidated, new config will be loaded on next request")
