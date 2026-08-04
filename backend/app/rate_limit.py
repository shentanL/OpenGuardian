"""轻量级 API 速率限制中间件（纯标准库，零依赖）。

使用滑动窗口 + 内存存储，适合单机部署场景。
"""
from __future__ import annotations

import time
import threading
from collections import defaultdict
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class RateLimiter:
    """滑动窗口速率限制器。"""

    def __init__(self, max_requests: int = 30, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._clients: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def _clean(self, client_id: str, now: float) -> list[float]:
        """清理过期记录，返回窗口内的请求时间戳列表。"""
        cutoff = now - self.window_seconds
        timestamps = self._clients.get(client_id, [])
        # 保留窗口内的记录；若全部过期则清理 client 条目防止内存泄漏
        filtered = [t for t in timestamps if t > cutoff]
        if not filtered and client_id in self._clients:
            del self._clients[client_id]
        return filtered

    def is_allowed(self, client_id: str) -> tuple[bool, int]:
        """检查是否允许请求。返回 (允许, 剩余次数)。"""
        now = time.time()
        with self._lock:
            timestamps = self._clean(client_id, now)
            if len(timestamps) < self.max_requests:
                timestamps.append(now)
                self._clients[client_id] = timestamps
                return True, self.max_requests - len(timestamps)
            self._clients[client_id] = timestamps
            # 计算最早过期时间
            oldest = min(timestamps)
            reset_in = int(self.window_seconds - (now - oldest))
            return False, reset_in

    def remaining(self, client_id: str) -> int:
        """当前剩余可用次数。"""
        now = time.time()
        with self._lock:
            timestamps = self._clean(client_id, now)
            return max(0, self.max_requests - len(timestamps))


# 默认限流器实例（30 次/分钟/IP）
_default_limiter = RateLimiter(max_requests=30, window_seconds=60.0)

# 各端点的限流配置（可根据实际负载调整）
ENDPOINT_LIMITS: dict[str, RateLimiter] = {
    # 聊天 → 更严限制（LLM API 消耗大）
    "/api/chat": RateLimiter(max_requests=20, window_seconds=60.0),
    "/api/chat/stream": RateLimiter(max_requests=20, window_seconds=60.0),
}


def _get_client_id(request: Request) -> str:
    """提取客户端标识：优先 X-Forwarded-For，其次直接 IP。"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    client = request.client
    if client:
        return client.host
    return "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI 中间件：对 API 端点施加速率限制。"""

    def __init__(self, app, default_limiter: RateLimiter | None = None):
        super().__init__(app)
        self.default_limiter = default_limiter or _default_limiter

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # 仅限制 /api/ 路径
        path = request.url.path
        if not path.startswith("/api/"):
            return await call_next(request)

        # 跳过健康检查、配置读取等安全端点
        if path in ("/api/health", "/api/config", "/api/agents"):
            return await call_next(request)

        client_id = _get_client_id(request)
        limiter = ENDPOINT_LIMITS.get(path, self.default_limiter)
        allowed, info = limiter.is_allowed(client_id)

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "请求过于频繁，请稍后再试",
                    "retry_after_seconds": info,
                },
                headers={"Retry-After": str(info), "X-RateLimit-Limit": str(limiter.max_requests)},
            )

        response = await call_next(request)
        remaining = limiter.remaining(client_id)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Limit"] = str(limiter.max_requests)
        return response
