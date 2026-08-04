"""OpenGuardian 数据模型（Pydantic）。"""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Intent(str, Enum):
    """用户意图。"""

    CONSULT = "consult"    # 安全咨询
    DETECT = "detect"      # 风险检测
    EXECUTE = "execute"    # 一键处置
    ASSET = "asset"        # 资产防护
    EDUCATE = "educate"    # 安全教育
    CREDENTIAL = "credential"  # 凭据泄露检测


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskItem(BaseModel):
    """单条风险项。"""

    item_type: str = Field(..., description="process / network / resource / asset")
    name: str = Field(..., description="风险对象名称")
    detail: str = Field(..., description="技术细节")
    level: RiskLevel = RiskLevel.LOW
    suggestion: str = Field("", description="通俗化处置建议")
    pid: Optional[int] = None
    attack_tech: str = Field("", description="MITRE ATT&CK 技术编号（如 T1053.005 Scheduled Task）")
    extra: dict = Field(default_factory=dict)


class AgentTask(BaseModel):
    """发给 Agent 的任务。"""

    intent: Intent
    params: dict = Field(default_factory=dict)
    user_input: str = ""


class AgentResult(BaseModel):
    """Agent 处理结果。"""

    agent: str
    success: bool = True
    data: Any = None
    message: str = ""
    risks: list[RiskItem] = Field(default_factory=list)


class ChatRequest(BaseModel):
    """前端聊天请求。"""

    message: str = Field(..., min_length=1, max_length=4000)
    session_id: Optional[str] = None


class ExecuteRequest(BaseModel):
    """处置确认请求。"""

    pid: Optional[int] = Field(None, description="目标进程 PID（缺省时返回友好提示）")
    action: str = Field("terminate", description="处置动作")


class ChatResponse(BaseModel):
    """前端聊天响应。"""

    reply: str = Field(..., description="面向用户的通俗回复")
    intent: Intent = Intent.CONSULT
    risks: list[RiskItem] = Field(default_factory=list)
    needs_confirmation: bool = False
    execute_hint: Optional[dict] = None
    session_id: str = ""


class HealthResponse(BaseModel):
    status: str = "ok"
    app: str = "OpenGuardian"
    version: str = "0.1.0"
