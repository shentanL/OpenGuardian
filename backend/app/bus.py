"""消息总线：Agent 注册与任务分发。"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .schemas import AgentResult, AgentTask

if TYPE_CHECKING:
    from .agents.base import BaseAgent

logger = logging.getLogger(__name__)


class MessageBus:
    """按 intent 分发任务到对应 Agent。"""

    def __init__(self) -> None:
        self._agents: dict[str, BaseAgent] = {}

    def register(self, agent: "BaseAgent") -> None:
        self._agents[agent.name] = agent
        logger.info("Agent registered: %s (%s)", agent.name, agent.description)

    def register_all(self, agents: list["BaseAgent"]) -> None:
        for agent in agents:
            self.register(agent)

    def dispatch(self, task: AgentTask) -> AgentResult:
        agent = self._agents.get(task.intent.value)
        if agent is None:
            return AgentResult(
                agent="bus",
                success=False,
                message=f"没有找到处理 {task.intent.value} 的 Agent",
            )
        try:
            logger.info("Dispatch %s -> %s", task.intent.value, agent.name)
            return agent.handle(task)
        except Exception as exc:  # noqa: BLE001 —— Agent 异常不应击穿服务
            logger.exception("Agent %s failed: %s", agent.name, exc)
            return AgentResult(
                agent=agent.name,
                success=False,
                message=f"处理失败：{exc}",
            )

    def list_agents(self) -> list[dict]:
        return [
            {"name": a.name, "description": a.description}
            for a in self._agents.values()
        ]
