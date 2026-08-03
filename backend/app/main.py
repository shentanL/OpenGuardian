"""OpenGuardian FastAPI 主入口。"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from .agents import build_bus, build_consultant
from .config import settings
from .db import get_db
from .kb.updater import kb_stats, start_background_update
from .sampler import ResourceSampler
from .security import assess_security
from .schemas import (
    AgentTask,
    ChatRequest,
    ChatResponse,
    ExecuteRequest,
    HealthResponse,
    Intent,
    RiskLevel,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

_sampler: ResourceSampler | None = None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """服务生命周期：启动资源采样器，关闭时停止。"""
    global _sampler
    _sampler = ResourceSampler(get_db(), interval=1)  # 最短间隔：1s 连续采样
    _sampler.start()
    start_background_update(delay=5.0)  # 知识库主动汲取（URLhaus/FireHOL）
    try:
        yield
    finally:
        if _sampler:
            _sampler.stop()


app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- 组装 Agent 系统 ----
bus = build_bus()
consultant = build_consultant(bus)
db = get_db()

# ---- 会话（SQLite 持久化）----


def _get_history(session_id: str, limit: int = 8) -> list[dict]:
    history = db.load_session(session_id)
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
@app.get("/api/health")
def health() -> HealthResponse:
    return HealthResponse(app=settings.APP_NAME, version=settings.APP_VERSION)


# ---- 配置管理 ----
@app.get("/api/config")
def get_config() -> dict:
    """返回当前配置状态 + 所有可用提供商信息。"""
    from .config_manager import is_configured as _configured, get_all_providers, get_provider

    return {
        "configured": _configured(),
        "provider": get_provider(),
        "providers": get_all_providers(),
    }


@app.post("/api/config")
def set_config(payload: dict) -> dict:
    """保存提供商配置到 config.json。"""
    from .config_manager import save_config

    return save_config(
        provider=payload.get("provider", "deepseek"),
        api_key=payload.get("api_key", ""),
        base_url=payload.get("base_url", ""),
        model=payload.get("model", ""),
    )


@app.get("/api/agents")
def list_agents() -> dict:
    return {"agents": bus.list_agents() + [{"name": "consult", "description": "交互中枢"}]}


@app.post("/api/chat", response_model=ChatResponse)
def chat(req: ChatRequest) -> ChatResponse:
    session_id = req.session_id or uuid.uuid4().hex[:12]
    history = _get_history(session_id)
    history.append({"role": "user", "content": req.message})

    # 注入最近一次检测上下文（让 LLM 回答安全问题时引用检测结果）
    context = ""
    try:
        scans = db.get_scan_history(limit=1)
        if scans and scans[0].get("total", 0) > 0:
            s = scans[0]
            context = f"[最近一次检测结果：发现 {s.get('total', 0)} 项风险（高危 {s.get('high', 0)} 项）；{s.get('summary', '')[:80]}]"
        elif scans:
            context = "[最近一次检测结果：未发现明显风险]"
    except Exception:  # noqa: BLE001
        pass

    task = AgentTask(
        intent=Intent.CONSULT,
        params={"context": context},
        user_input=req.message,
    )
    result = consultant.handle(task)

    history.append({"role": "assistant", "content": result.message})
    db.save_session(session_id, history)

    data = result.data or {}
    # 检测类请求写入扫描历史 + 资源快照（供报告/仪表盘）
    if data.get("intent") == "detect":
        risks = result.risks
        db.add_scan(
            total_risks=len(risks),
            high_risks=sum(1 for r in risks if r.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)),
            summary=result.message[:200],
            risks=[r.model_dump() for r in risks],
        )
        try:
            import psutil

            db.add_resource_sample(
                psutil.cpu_percent(interval=0.2),
                psutil.virtual_memory().percent,
                psutil.disk_usage("/").percent,
            )
        except Exception:  # noqa: BLE001
            pass

    return ChatResponse(
        reply=result.message,
        intent=Intent(data.get("intent", "consult")),
        risks=result.risks,
        needs_confirmation=bool(data.get("needs_confirmation", False)),
        execute_hint=data.get("execute_hint"),
        session_id=session_id,
    )


@app.post("/api/chat/stream")
async def chat_stream(req: ChatRequest):
    """流式聊天（SSE）。咨询/教育类用 LLM 流式输出；其他意图先返回结构化 JSON 事件。

    事件格式（text/event-stream）：
      data: {"type": "intent", "intent": "consult"}
      data: {"type": "token", "text": "..."}     # 流式文本块
      data: {"type": "result", "reply": "...", "risks": [...], ...}  # 最终结果
      data: {"type": "done"}
    """
    from fastapi.responses import StreamingResponse
    from fastapi.concurrency import run_in_threadpool

    # 意图识别（同步方法丢线程池，避免阻塞事件循环）
    intent, _ = await run_in_threadpool(consultant._classify, req.message)

    async def event_gen():
        # 1) 先发意图事件
        yield f'data: {json.dumps({"type": "intent", "intent": intent.value}, ensure_ascii=False)}\n\n'

        if intent == Intent.CONSULT:
            # 咨询类：流式 LLM 输出
            system = (
                "你是 OpenGuardian——面向普通用户的个人数字安全助手。"
                "回答要求：通俗易懂、不超过 200 字、给出可操作建议。"
            )
            chunks: list[str] = []
            async for token in consultant.llm.stream_chat(
                [{"role": "user", "content": req.message}], system=system
            ):
                chunks.append(token)
                yield f'data: {json.dumps({"type": "token", "text": token}, ensure_ascii=False)}\n\n'
            reply = "".join(chunks) or "（AI 暂时无法响应，请稍后再试）"
            yield f'data: {json.dumps({"type": "result", "reply": reply, "risks": []}, ensure_ascii=False)}\n\n'

        elif intent == Intent.EDUCATE:
            # 教育：走 Agent 案例库（秒回） + 流式模拟
            task = AgentTask(intent=intent, params={}, user_input=req.message)
            result = await run_in_threadpool(consultant.handle, task)
            reply = result.message or "该话题暂无案例，尝试换个问法"
            # 逐字流式输出（模拟打字效果）
            for i in range(0, len(reply), 3):
                chunk = reply[i:i+3]
                yield f'data: {json.dumps({"type": "token", "text": chunk}, ensure_ascii=False)}\n\n'
                await asyncio.sleep(0.02)
            yield f'data: {json.dumps({"type": "result", "reply": reply, "risks": []}, ensure_ascii=False)}\n\n'

        else:
            # 检测/执行等其他意图：流式模拟处理过程
            yield f'data: {json.dumps({"type": "token", "text": "正在分析..."}, ensure_ascii=False)}\n\n'
            task = AgentTask(intent=intent, params={}, user_input=req.message)
            result = await run_in_threadpool(consultant.handle, task)
            data = result.data or {}
            reply = result.message
            yield f'data: {json.dumps({"type": "token", "text": reply or "分析完成"}, ensure_ascii=False)}\n\n'
            payload = {
                "type": "result",
                "reply": reply,
                "intent": data.get("intent", intent.value),
                "risks": [r.model_dump() for r in result.risks],
                "needs_confirmation": bool(data.get("needs_confirmation", False)),
                "execute_hint": data.get("execute_hint"),
            }
            yield f'data: {json.dumps(payload, ensure_ascii=False)}\n\n'

        yield "data: {\"type\": \"done\"}\n\n"

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
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
    return {"logs": db.get_audit()}


@app.get("/api/sessions")
def sessions_list() -> dict:
    return {"sessions": db.list_sessions()}


@app.get("/api/sessions/{session_id}/messages")
def session_messages(session_id: str) -> dict:
    """读取指定会话的完整消息历史（供前端切换会话时回显）。"""
    return {"session_id": session_id, "messages": db.load_session(session_id)}


@app.delete("/api/sessions/{session_id}")
def session_delete(session_id: str) -> dict:
    """删除会话（前端侧边栏管理）。"""
    deleted = db.delete_session(session_id)
    return {"success": deleted, "session_id": session_id}


@app.get("/api/scans")
def scans() -> dict:
    return {"history": db.get_scan_history()}


@app.get("/api/stats")
def stats() -> dict:
    """仪表盘聚合数据：最近检测风险分布 + 资源趋势 + 检测历史。

    语义（对齐 GitHub 监控台）：面板反映**当前（最近一次检测）**的安全状态，
    而非历史累计——避免"最近检测 0 风险但面板显示红色"的误导。
    """
    scans_all = db.get_scan_history(limit=200)
    latest = scans_all[0] if scans_all else None

    # 风险分布：基于最近一次检测的 risks（等级 × 7 类细分）
    levels = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    types = {"process": 0, "network": 0, "resource": 0, "asset": 0,
             "malicious_ip": 0, "malicious_domain": 0, "port": 0, "vuln": 0,
             "malware_hash": 0}
    if latest:
        for r in latest.get("risks", []):
            lv = str(r.get("level", "low")).lower()
            if lv in levels:
                levels[lv] += 1
            ty = str(r.get("item_type", "process")).lower()
            # 子类型归一化: vuln_patch → vuln, malicious_domain → malicious_domain 等
            if ty.startswith("vuln"):
                ty = "vuln"
            if ty in types:
                types[ty] += 1

    return {
        "risk_distribution": {
            "levels": levels,
            "types": types,
            "total": sum(levels.values()),
        },
        # 最近一次检测的风险明细（与分布一致，同一数据源）
        "last_risks": (latest.get("risks", []) if latest else []),
        "last_scan": latest,
        "resources": db.get_resource_history(limit=120),
        "scans": scans_all[:10],
        "audit_count": len(db.get_audit(limit=1000)),
        "kb_status": kb_stats(),  # 知识库主动汲取状态
        "security": assess_security(latest.get("risks", []) if latest else None),  # 安全系数+加固方案
    }


# ---- 前端静态托管 ----
FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"
# PyInstaller 打包环境修正：sys._MEIPASS 是解压根目录
if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    FRONTEND_DIR = Path(sys._MEIPASS) / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(FRONTEND_DIR / "index.html")

    @app.get("/config")
    async def config_page() -> FileResponse:
        return FileResponse(FRONTEND_DIR / "config.html")
