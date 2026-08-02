"""Agent 基类。"""
from __future__ import annotations

import abc

from ..schemas import AgentResult, AgentTask


class BaseAgent(abc.ABC):
    """所有专项 Agent 的统一接口。

    子类必须定义 name / description 并实现 handle()。
    """

    name: str = "base"
    description: str = ""

    @abc.abstractmethod
    def handle(self, task: AgentTask) -> AgentResult:
        """处理一个任务，返回结果。"""
        raise NotImplementedError
