"""Agent 工厂：组装 5 个专项 Agent + 验证/反思 Agent + 消息总线。"""
from __future__ import annotations

from ..bus import MessageBus
from .analyst import AnalystAgent
from .consultant import ConsultantAgent
from .detector import DetectorAgent
from .educator import EducatorAgent
from .executor import ExecutorAgent
from .reflector import ReflectorAgent, get_reflector
from .verifier import VerifierAgent, get_verifier

__all__ = ["build_bus", "build_consultant",
           "get_verifier", "get_reflector",
           "VerifierAgent", "ReflectorAgent"]


def build_bus() -> MessageBus:
    """构建消息总线，注册所有专项 Agent。"""
    bus = MessageBus()
    bus.register_all(
        [
            DetectorAgent(),
            AnalystAgent(),
            ExecutorAgent(),
            EducatorAgent(),
        ]
    )
    # Verifier 和 Reflector 不注册到总线——它们由 Consultant 直接编排调用
    return bus


def build_consultant(bus: MessageBus) -> ConsultantAgent:
    """构建咨询 Agent（编排中枢，集成验证+反思+记忆+工具）。"""
    return ConsultantAgent(bus)
