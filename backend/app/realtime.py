"""WebSocket 实时监控推送。

大厂标准：WebSocket 推送替代前端轮询。
- 系统资源实时流（CPU/内存/磁盘，1s 间隔）
- 威胁告警实时推送
- 客户端数量统计
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import psutil
from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger("openguardian.realtime")

# ─── 连接管理 ───


class RealtimeHub:
    """WebSocket 连接池 + 广播。"""

    def __init__(self) -> None:
        self._connections: dict[str, WebSocket] = {}
        self._counter = 0
        self._broadcast_task: asyncio.Task | None = None
        self._running = False

    @property
    def client_count(self) -> int:
        return len(self._connections)

    async def connect(self, ws: WebSocket) -> str:
        await ws.accept()
        self._counter += 1
        client_id = f"ws-{self._counter}"
        self._connections[client_id] = ws
        logger.info("WebSocket connected: %s (total: %d)", client_id, self.client_count)
        self._ensure_broadcasting()
        return client_id

    def disconnect(self, client_id: str) -> None:
        self._connections.pop(client_id, None)
        logger.info("WebSocket disconnected: %s (total: %d)", client_id, self.client_count)

    async def broadcast(self, event_type: str, payload: dict[str, Any]) -> None:
        """向所有已连接客户端广播事件。"""
        if not self._connections:
            return
        message = json.dumps({"type": event_type, "data": payload, "ts": time.time()}, ensure_ascii=False)
        dead: list[str] = []
        for cid, ws in list(self._connections.items()):
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(cid)
        for cid in dead:
            self.disconnect(cid)

    def _ensure_broadcasting(self) -> None:
        """确保后台广播任务在运行。"""
        if self._broadcast_task is None or self._broadcast_task.done():
            self._running = True
            self._broadcast_task = asyncio.create_task(self._broadcast_loop())

    async def _broadcast_loop(self) -> None:
        """后台循环：每秒推送系统资源数据。"""
        while self._running and self._connections:
            try:
                await self._push_resource_snapshot()
            except Exception as exc:
                logger.warning("Realtime broadcast error: %s", exc)
            await asyncio.sleep(1)

    async def _push_resource_snapshot(self) -> None:
        cpu = psutil.cpu_percent(interval=0.2)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent
        net = psutil.net_io_counters()
        await self.broadcast("resource_snapshot", {
            "cpu": round(cpu, 1),
            "mem": round(mem, 1),
            "disk": round(disk, 1),
            "net_sent_mb": round(net.bytes_sent / 1024 / 1024, 1) if net else 0,
            "net_recv_mb": round(net.bytes_recv / 1024 / 1024, 1) if net else 0,
            "time": time.strftime("%H:%M:%S"),
        })

    async def push_alert(self, level: str, title: str, message: str, pid: int | None = None) -> None:
        """推送安全告警给所有客户端。"""
        await self.broadcast("security_alert", {
            "level": level,
            "title": title,
            "message": message,
            "pid": pid,
            "time": time.strftime("%H:%M:%S"),
        })

    async def stop(self) -> None:
        self._running = False
        for ws in list(self._connections.values()):
            try:
                await ws.close()
            except Exception:
                pass
        self._connections.clear()


# ─── 全局单例 ───

_hub: RealtimeHub | None = None


def get_hub() -> RealtimeHub:
    global _hub
    if _hub is None:
        _hub = RealtimeHub()
    return _hub


# ─── WebSocket 端点处理 ───


async def ws_endpoint(websocket: WebSocket) -> None:
    """WebSocket 端点：客户端连接后持续接收资源快照直到断开。"""
    hub = get_hub()
    client_id = await hub.connect(websocket)
    try:
        # 保持连接，等待客户端消息（心跳/指令）
        while True:
            data = await websocket.receive_text()
            # 客户端可发送 {"type": "ping"} 保持活跃
            if data and "ping" in data:
                await websocket.send_text(json.dumps({"type": "pong", "ts": time.time()}))
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.debug("WebSocket error for %s: %s", client_id, exc)
    finally:
        hub.disconnect(client_id)
