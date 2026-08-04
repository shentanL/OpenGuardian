"""安全异步工具：兼容有/无事件循环的场景。

核心问题：FastAPI 端点使用 `def`（非 `async def`）时运行在线程池中，
asyncio.run() 通常是安全的。但当第三方库/managed context 已创建事件循环时，
asyncio.run() 会抛出 RuntimeError。

本模块提供 `run_async()` 安全包装器，自动检测并适配。
"""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Awaitable, TypeVar

T = TypeVar("T")


# 共享线程池（避免每次调用创建新池）
_EXECUTOR = ThreadPoolExecutor(max_workers=4)


def run_async(coro: Awaitable[T], timeout: float | None = 60.0) -> T:
    """安全地运行异步协程，返回结果。

    策略：
    1. 无运行中事件循环 → 直接用 asyncio.run()（最快路径）
    2. 有运行中事件循环 → 用独立线程 + asyncio.run()（避免冲突）

    timeout: 超时秒数，None 表示不超时
    """
    try:
        # 检查是否已有运行中的事件循环
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # 没有运行中的事件循环 — 安全路径
        try:
            # Python 3.10+ 支持 asyncio.Runner
            if hasattr(asyncio, "Runner"):
                with asyncio.Runner() as runner:
                    return runner.run(coro)
            return asyncio.run(coro)
        except Exception:
            raise
    else:
        # 有运行中的事件循环 — 在新线程中运行，避免嵌套冲突
        # 注意：这会导致原事件循环阻塞等待新线程结果，但避免了 RuntimeError
        future = _EXECUTOR.submit(_run_in_new_loop, coro, timeout)
        try:
            return future.result(timeout=timeout)
        except Exception:
            raise


def _run_in_new_loop(coro: Awaitable[T], timeout: float | None) -> T:
    """在新线程的新事件循环中运行协程。"""
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        if timeout:
            return loop.run_until_complete(
                asyncio.wait_for(coro, timeout=timeout)
            )
        return loop.run_until_complete(coro)
    finally:
        loop.close()
