"""企业级中间件：请求追踪 + 安全头 + 访问日志 + 性能计时。

大厂标准中间件栈：
- Request ID 注入与传播（X-Request-ID → 响应头 + 日志上下文）
- 安全响应头（X-Content-Type-Options, X-Frame-Options, etc.）
- 结构化访问日志（JSON 格式，含延迟、状态码、UA）
- 性能计时（p50/p95/p99 延迟统计）
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from collections import defaultdict
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("openguardian.access")

# ─── 延迟统计 ───

class LatencyStats:
    """滑动窗口延迟统计（p50/p95/p99）。保留最近 1000 个请求。"""

    def __init__(self, max_samples: int = 1000):
        self._samples: list[float] = []
        self._max = max_samples
        self._by_route: dict[str, list[float]] = defaultdict(list)

    def record(self, route: str, latency_ms: float) -> None:
        self._samples.append(latency_ms)
        if len(self._samples) > self._max:
            self._samples = self._samples[-self._max:]
        self._by_route[route].append(latency_ms)
        if len(self._by_route[route]) > self._max:
            self._by_route[route] = self._by_route[route][-self._max:]

    def percentile(self, pct: float, samples: list[float] | None = None) -> float:
        data = sorted(samples or self._samples)
        if not data:
            return 0.0
        idx = int(len(data) * pct / 100)
        return data[min(idx, len(data) - 1)]

    @property
    def p50(self) -> float:
        return self.percentile(50)

    @property
    def p95(self) -> float:
        return self.percentile(95)

    @property
    def p99(self) -> float:
        return self.percentile(99)

    def route_stats(self, route: str) -> dict:
        samples = self._by_route.get(route, [])
        if not samples:
            return {"count": 0}
        return {
            "count": len(samples),
            "avg_ms": round(sum(samples) / len(samples), 2),
            "p50_ms": round(self.percentile(50, samples), 2),
            "p95_ms": round(self.percentile(95, samples), 2),
            "p99_ms": round(self.percentile(99, samples), 2),
        }

    def summary(self) -> dict:
        return {
            "total_requests": len(self._samples),
            "p50_ms": round(self.p50, 2),
            "p95_ms": round(self.p95, 2),
            "p99_ms": round(self.p99, 2),
        }


_latency = LatencyStats()


def get_latency_stats() -> LatencyStats:
    return _latency


# ─── 安全响应头 ───

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


# ─── 中间件 ───


class RequestTracingMiddleware(BaseHTTPMiddleware):
    """请求追踪：注入 Request ID + 记录结构化访问日志 + 收集延迟统计。

    请求头：X-Request-ID（若无则自动生成 UUID7 风格）
    响应头：X-Request-ID, X-Response-Time-Ms
    日志：JSON 格式，每请求一行
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # 生成/传播 Request ID
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:16]
        request.state.request_id = request_id

        start = time.perf_counter()

        # 安全头 + 请求 ID 注入到响应
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-Ms"] = str(round((time.perf_counter() - start) * 1000))

        # 安全头
        for header, value in SECURITY_HEADERS.items():
            if header not in response.headers:
                response.headers[header] = value

        # 记录延迟
        elapsed_ms = (time.perf_counter() - start) * 1000
        route = request.url.path
        _latency.record(route, elapsed_ms)

        # 结构化访问日志（仅 API 端点，跳过静态资源）
        if request.url.path.startswith("/api/"):
            log_entry = {
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "latency_ms": round(elapsed_ms, 2),
                "client": request.client.host if request.client else "-",
                "user_agent": request.headers.get("User-Agent", "-")[:120],
            }
            if 400 <= response.status_code < 500:
                logger.warning(json.dumps(log_entry, ensure_ascii=False))
            elif response.status_code >= 500:
                logger.error(json.dumps(log_entry, ensure_ascii=False))
            else:
                logger.info(json.dumps(log_entry, ensure_ascii=False))

        return response
