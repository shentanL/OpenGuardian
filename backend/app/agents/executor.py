"""执行 Agent：一键处置（结束进程等）。

安全设计（申报书关键问题之一）：
1. 白名单校验：系统关键进程 / 用户白名单永不处置
2. 必须显式传参（由前端二次确认后调用），不接收自然语言直接执行
3. 所有处置写入审计日志
"""
from __future__ import annotations

import logging
from datetime import datetime

import psutil

from ..schemas import AgentResult, AgentTask, RiskLevel, RiskItem
from .base import BaseAgent
from .detector import SYSTEM_PROCESSES, USER_WHITELIST

logger = logging.getLogger(__name__)

AUDIT_LOG: list[dict] = []  # MVP 用内存审计日志，后续可落 SQLite


class ExecutorAgent(BaseAgent):
    name = "execute"
    description = "一键处置：安全地结束可疑进程（白名单保护 + 审计）"

    def handle(self, task: AgentTask) -> AgentResult:
        pid = task.params.get("pid")
        action = task.params.get("action", "terminate")

        if not isinstance(pid, int) or pid <= 0:
            return AgentResult(
                agent=self.name,
                success=False,
                message="缺少有效的目标进程 PID",
            )

        try:
            proc = psutil.Process(pid)
            name = proc.name()
        except psutil.NoSuchProcess:
            return AgentResult(
                agent=self.name,
                success=False,
                message=f"进程 {pid} 已不存在（可能已被结束）",
            )
        except psutil.AccessDenied:
            return AgentResult(
                agent=self.name,
                success=False,
                message=f"没有权限操作进程 {pid}，请以管理员身份运行",
            )

        # ---- 白名单保护 ----
        if name in SYSTEM_PROCESSES or name in USER_WHITELIST:
            return AgentResult(
                agent=self.name,
                success=False,
                message=f"进程 {name}（PID {pid}）在保护名单中，拒绝处置",
            )

        if action == "terminate":
            try:
                proc.terminate()
                proc.wait(timeout=5)
                self._audit("terminate", pid, name, "ok")
                return AgentResult(
                    agent=self.name,
                    success=True,
                    message=f"已安全结束进程 {name}（PID {pid}）",
                    data={"action": "terminate", "pid": pid, "name": name},
                )
            except psutil.AccessDenied:
                return AgentResult(
                    agent=self.name,
                    success=False,
                    message=f"权限不足，无法结束 {name}（PID {pid}），请以管理员身份运行",
                )
            except psutil.TimeoutExpired:
                proc.kill()
                self._audit("terminate(force)", pid, name, "ok")
                return AgentResult(
                    agent=self.name,
                    success=True,
                    message=f"进程 {name} 未响应，已强制结束（PID {pid}）",
                )
            except Exception as exc:  # noqa: BLE001
                logger.exception("terminate failed: %s", exc)
                return AgentResult(
                    agent=self.name,
                    success=False,
                    message=f"结束进程失败：{exc}",
                )

        return AgentResult(
            agent=self.name,
            success=False,
            message=f"不支持的处置动作：{action}",
        )

    @staticmethod
    def _audit(action: str, pid: int, name: str, result: str) -> None:
        entry = {
            "time": datetime.now().isoformat(timespec="seconds"),
            "action": action,
            "pid": pid,
            "name": name,
            "result": result,
        }
        AUDIT_LOG.append(entry)
        logger.info("AUDIT %s", entry)
