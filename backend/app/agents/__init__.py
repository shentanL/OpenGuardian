"""Agent 工厂：组装 5 个专项 Agent + 消息总线。"""
from __future__ import annotations

from ..bus import MessageBus
from .analyst import AnalystAgent
from .consultant import ConsultantAgent
from .detector import DetectorAgent
from .educator import EducatorAgent
from .executor import ExecutorAgent

__all__ = ["build_bus", "build_consultant"]


def build_bus() -> MessageBus:
    """构建消息总线，注册 4 个专项 Agent（不含咨询 Agent，它独立编排）。"""
    bus = MessageBus()
    bus.register_all(
        [
            DetectorAgent(),
            AnalystAgent(),
            ExecutorAgent(),
            EducatorAgent(),
        ]
    )
    return bus


def build_consultant(bus: MessageBus) -> ConsultantAgent:
    """构建咨询 Agent（编排中枢）。"""
    return ConsultantAgent(bus)
