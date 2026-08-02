"""OpenGuardian FastAPI 主入口。"""
from __future__ import annotations

import logging
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from .agents import build_bus, build_consultant
from .config import settings
from .schemas import (
    AgentTask,
    ChatRequest,
    ChatResponse,
    ExecuteRequest,
    HealthResponse,
    Intent,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- 组装 Agent 系统 ----
bus = build_bus()
consultant = build_consultant(bus)

# ---- 会话内存（MVP；后续可落 SQLite）----
sessions: dict[str, list[dict]] = {}


def _get_history(session_id: str, limit: int = 8) -> list[dict]:
    history = sessions.setdefault(session_id, [])
    return history[-limit:]


@app.on_event("startup")
async def _startup() -> None:
    logger.info(
        "%s v%s started — LLM %s, agents: %s",
        settings.APP_NAME,
        settings.APP_VERSION,
        "configured" if consultant.llm.available else "NOT CONFIGURED (fallback mode)",
        [a["name"] for a in bus.list_agents()] + ["consultant"],
    )


# ---- API ----
# 注意：端点使用同步 def（非 async def），FastAPI 会将其放入线程池执行。
# Agent 内部用 asyncio.run() 调用 LLM，同步端点可避免
# "asyncio.run() cannot be called from a running event loop" 错误。
@app.get("/api/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(app=settings.APP_NAME, version=settings.APP_VERSION)


@app.get("/api/agents")
def list_agents() -> dict:
    return {"agents": bus.list_agents() + [{"name": "consult", "description": "交互中枢"}]}


@app.post("/api/chat", response_model=ChatResponse)
def chat(req: ChatRequest) -> ChatResponse:
    session_id = req.session_id or uuid.uuid4().hex[:12]
    history = _get_history(session_id)
    history.append({"role": "user", "content": req.message})

    task = AgentTask(
        intent=Intent.CONSULT,
        params={},
        user_input=req.message,
    )
    result = consultant.handle(task)

    history.append({"role": "assistant", "content": result.message})
    sessions[session_id] = history[-40:]

    data = result.data or {}
    return ChatResponse(
        reply=result.message,
        intent=Intent(data.get("intent", "consult")),
        risks=result.risks,
        needs_confirmation=bool(data.get("needs_confirmation", False)),
        execute_hint=data.get("execute_hint"),
        session_id=session_id,
    )


@app.post("/api/execute")
def execute(req: ExecuteRequest) -> dict:
    """处置执行（前端二次确认后调用）。"""
    result = bus.dispatch(
        AgentTask(intent=Intent.EXECUTE, params={"pid": req.pid, "action": req.action})
    )
    return {"success": result.success, "message": result.message}


@app.get("/api/audit")
def audit() -> dict:
    from .agents.executor import AUDIT_LOG

    return {"logs": AUDIT_LOG}


# ---- 前端静态托管 ----
FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(FRONTEND_DIR / "index.html")
