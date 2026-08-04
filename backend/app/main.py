"""OpenGuardian FastAPI 主入口 — 企业级架构。"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from .agents import build_bus, build_consultant
from .config import settings
from .db import get_db
from .errors import register_error_handlers
from .kb.ingestion import ingestion_stats, start_background_ingestion, force_refresh as kb_force_refresh
from .middleware import RequestTracingMiddleware, get_latency_stats
from .sampler import ResourceSampler
from .security import assess_security
from .prompts import CONSULT_STREAM, FALLBACK_AI_UNAVAILABLE, FALLBACK_AI_RETRY, FALLBACK_AI_TIMEOUT
from .rate_limit import RateLimitMiddleware
from .realtime import get_hub, ws_endpoint
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
_start_time: float | None = None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """服务生命周期：初始化记忆系统 + 资源采样器 + 实时推送。"""
    global _sampler, _start_time
    _start_time = time.time()
    from .memory import init_memory_schema, get_memory
    init_memory_schema(get_db())
    get_memory()
    _sampler = ResourceSampler(get_db(), interval=5)
    _sampler.start()
    start_background_ingestion(delay=5.0, interval_hours=6.0)
    # 后台检查更新（不阻塞启动）
    import threading as _thr
    _thr.Thread(target=lambda: _check_update_async(), daemon=True, name="update-check").start()
    # 向 Windows 安全中心注册（需管理员权限，失败不阻塞）
    _thr.Thread(target=lambda: _register_wsc(), daemon=True, name="wsc-register").start()
    # 启动 ETW 进程监控
    try:
        from .etw_monitor import get_monitor as _get_etw
        _etw = _get_etw()
        _etw.on_process(lambda evt: logger.debug("ETW: %s %s (PID %s)", evt["event"], evt["name"], evt["pid"]))
        _etw.start()
    except Exception:
        pass
    logger.info(
        "%s v%s started — LLM %s, agents: %s, ws: ready",
        settings.APP_NAME, settings.APP_VERSION,
        "configured" if consultant.llm.available else "NOT CONFIGURED",
        [a["name"] for a in bus.list_agents()] + ["consultant"],
    )
    try:
        yield
    finally:
        if _sampler:
            _sampler.stop()
        hub = get_hub()
        await hub.stop()


app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION, lifespan=lifespan)

# ── 中间件栈（顺序重要：后添加的先执行）──
# 1. 请求追踪 + 结构化日志 + 安全头
app.add_middleware(RequestTracingMiddleware)
# 2. CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8300", "http://localhost:8300",
        "http://127.0.0.1:8000", "http://localhost:8000",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)
# 3. 速率限制
app.add_middleware(RateLimitMiddleware)

# ── 全局错误处理 ──
register_error_handlers(app)

# ── 组装 Agent 系统 ──
bus = build_bus()
consultant = build_consultant(bus)
db = get_db()


def _get_history(session_id: str, limit: int = 20) -> list[dict]:
    history = db.load_session(session_id)
    return history[-limit:]


# ---- API ----
# 注意：端点使用同步 def（非 async def），FastAPI 会将其放入线程池执行。
# Agent 内部用 asyncio.run() / run_async() 调用 LLM。


# ---- 配置管理 ----
@app.get("/api/config")
def get_config() -> dict:
    """返回当前配置状态 + 所有可用提供商信息。"""
    from .config_manager import is_configured as _configured, get_all_providers, get_provider, get_model, get_base_url

    return {
        "configured": _configured(),
        "provider": get_provider(),
        "model": get_model(),
        "base_url": get_base_url(),
        "providers": get_all_providers(),
    }


@app.post("/api/config")
def set_config(payload: dict) -> dict:
    """保存提供商配置到 config.json（带基本校验）。"""
    # 基本校验：防止注入攻击和超大数据
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="请求体必须为 JSON 对象")
    provider = str(payload.get("provider", "")).strip()[:50]
    api_key = str(payload.get("api_key", "")).strip()[:512]
    base_url = str(payload.get("base_url", "")).strip()[:500]
    model = str(payload.get("model", "")).strip()[:200]
    from .config_manager import save_config

    return save_config(
        provider=provider or "deepseek",
        api_key=api_key,
        base_url=base_url,
        model=model,
    )


@app.post("/api/llm/test")
async def test_llm() -> dict:
    """实测 LLM 连通性：调用当前配置的模型发送测试消息。"""
    try:
        from .llm.client import get_llm_client
        llm = get_llm_client()
        if not llm.available:
            return {"ok": False, "error": "未配置 API Key"}
        reply = await llm.chat(
            [{"role": "user", "content": "请只回复：连接成功"}],
            max_tokens=64,
            temperature=0.1,
        )
        if reply:
            return {"ok": True, "reply": reply[:120]}
        return {"ok": False, "error": "模型无响应（检查模型名或网络）"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)[:200]}


@app.get("/api/system")
def system_info() -> dict:
    """本机实时状态（设置页关于/本机状态用）。"""
    import psutil
    import platform
    try:
        vm = psutil.virtual_memory()
        disk = psutil.disk_usage("C:")
        uptime = time.time() - _start_time if _start_time else 0
        return {
            "os": f"{platform.system()} {platform.release()}",
            "cpu_pct": psutil.cpu_percent(interval=0.3),
            "mem_pct": vm.percent,
            "mem_used_gb": round(vm.used / 1024**3, 1),
            "mem_total_gb": round(vm.total / 1024**3, 1),
            "disk_free_gb": round(disk.free / 1024**3, 1),
            "disk_total_gb": round(disk.total / 1024**3, 1),
            "process_count": len(psutil.pids()),
            "uptime_s": int(uptime),
        }
    except Exception:  # noqa: BLE001
        return {"error": "无法获取系统信息"}


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
        # 通过 WebSocket 推送仪表盘刷新事件（同步端点 → 线程中运行）
        try:
            hub = get_hub()
            import threading as _thr
            _thr.Thread(
                target=lambda: __import__('asyncio').run(hub.broadcast("dashboard_refresh", {"total": len(risks)})),
                daemon=True,
            ).start()
        except Exception:
            pass
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
        detect_result = None  # 捕获检测结果供后续持久化
        # 1) 先发意图事件
        yield f'data: {json.dumps({"type": "intent", "intent": intent.value}, ensure_ascii=False)}\n\n'

        if intent == Intent.CONSULT:
            # 咨询类：流式 LLM 输出（注入最近检测上下文）
            system = CONSULT_STREAM
            chunks: list[str] = []
            async for token in consultant.llm.stream_chat(
                [{"role": "user", "content": req.message}], system=system
            ):
                chunks.append(token)
                yield f'data: {json.dumps({"type": "token", "text": token}, ensure_ascii=False)}\n\n'
            reply = "".join(chunks) or FALLBACK_AI_TIMEOUT
            yield f'data: {json.dumps({"type": "result", "reply": reply, "intent": "consult", "risks": []}, ensure_ascii=False)}\n\n'

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
            yield f'data: {json.dumps({"type": "result", "reply": reply, "intent": "educate", "risks": []}, ensure_ascii=False)}\n\n'

        else:
            # 检测/执行等其他意图：流式展示处理阶段
            stages = {
                Intent.DETECT: ["🔍 正在检测进程安全...", "🌐 分析网络连接...", "📊 评估系统资源...", "🛡️ 扫描安全漏洞...", "🔐 检查账户安全...", "🛡️ 核查 Defender...", "📦 检查系统更新...", "⚙️ 审计后台服务..."],
                Intent.ASSET: ["🔐 检查密码策略...", "👤 验证账户状态...", "🔑 评估安全配置..."],
            }
            steps = stages.get(intent, ["处理中..."])
            for step in steps:
                yield f'data: {json.dumps({"type": "token", "text": step + " "}, ensure_ascii=False)}\n\n'
                await asyncio.sleep(0.15)

            task = AgentTask(intent=intent, params={}, user_input=req.message)
            result = await run_in_threadpool(consultant.handle, task)
            detect_result = result
            data = result.data or {}
            reply = result.message

            # ★ 先持久化检测结果到 DB，再发 SSE（避免前端 loadDashboard 读到旧数据）
            if intent == Intent.DETECT:
                try:
                    risks = result.risks
                    db.add_scan(
                        total_risks=len(risks),
                        high_risks=sum(1 for r in risks if r.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)),
                        summary=(result.message or "")[:200],
                        risks=[r.model_dump() for r in risks],
                    )
                    import psutil as _psutil
                    db.add_resource_sample(_psutil.cpu_percent(interval=0.2), _psutil.virtual_memory().percent, _psutil.disk_usage("/").percent)
                except Exception:
                    pass

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

            # WebSocket 推送仪表盘刷新（异步，不阻塞 SSE 流）
            if intent == Intent.DETECT:
                try:
                    hub = get_hub()
                    asyncio.create_task(hub.broadcast("dashboard_refresh", {"total": len(result.risks)}))
                except Exception:
                    pass

        # 流式结束后持久化会话
        session_id = req.session_id or uuid.uuid4().hex[:12]
        history = _get_history(session_id)
        history.append({"role": "user", "content": req.message})
        # 各意图分支已在上面设置了 reply 变量（CONSULT→流式拼接, EDUCATE→Agent结果, DETECT→检测摘要）
        # 此处不再覆盖，直接存入会话历史
        history.append({"role": "assistant", "content": reply})
        db.save_session(session_id, history)

        yield f'data: {json.dumps({"type": "session", "session_id": session_id}, ensure_ascii=False)}\n\n'
        yield "data: {\"type\": \"done\"}\n\n"

    async def safe_event_gen():
        import asyncio as _asyncio
        heartbeat_interval = 15  # 每 15 秒发心跳防代理超时
        last_heartbeat = time.time()
        try:
            async for event in event_gen():
                yield event
                # Keep-alive: 如果距离上次心跳超过间隔，插入 SSE 注释
                now = time.time()
                if now - last_heartbeat >= heartbeat_interval:
                    yield ": ping\n\n"
                    last_heartbeat = now
        except _asyncio.CancelledError:
            # 客户端断连 —— 记录日志后正确传播取消信号
            logger.info("SSE stream cancelled (client disconnected)")
            raise
        except Exception as exc:
            logger.exception("SSE stream error: %s", exc)
            yield f'data: {json.dumps({"type": "error", "message": "服务器内部错误，请重试"}, ensure_ascii=False)}\n\n'
            yield "data: {\"type\": \"done\"}\n\n"

    return StreamingResponse(
        safe_event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-store",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
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
             "malicious_ip": 0, "malicious_domain": 0, "port": 0, "vuln": 0, "malware_hash": 0,
             "defender": 0, "updates": 0, "services": 0}
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
        "kb_status": ingestion_stats(),  # 多源威胁情报摄入状态
        "security": assess_security(latest.get("risks", []) if latest else None),  # 安全系数+加固方案
    }


# ---- 知识库管理 ----

@app.get("/api/kb/status")
def kb_status() -> dict:
    """知识库详细状态（Feed 级别）。"""
    return ingestion_stats()


@app.post("/api/kb/refresh")
def kb_refresh() -> dict:
    """手动触发威胁情报立即刷新。"""
    result = kb_force_refresh()
    return {"ok": result.get("ok", False), "detail": result.get("detail", ""),
            "sources": result.get("sources", {}),
            "domain_count": result.get("domain_count", 0),
            "ip_count": result.get("ip_count", 0)}


# ---- 白名单管理 ----

@app.get("/api/whitelist")
def whitelist_get() -> dict:
    return {"items": sorted(db.get_whitelist())}


@app.post("/api/whitelist")
def whitelist_add(payload: dict) -> dict:
    name = str(payload.get("name", "")).strip()
    if not name:
        return {"ok": False, "error": "进程名不能为空"}
    ok = db.add_whitelist(name)
    return {"ok": ok, "name": name}


@app.delete("/api/whitelist/{name}")
def whitelist_remove(name: str) -> dict:
    ok = db.remove_whitelist(name)
    return {"ok": ok, "name": name}


# ---- 自动更新 ----

_update_result_cache: dict | None = None


def _register_wsc() -> None:
    """后台向 Windows 安全中心注册。"""
    try:
        from .wsc_register import register
        register()
    except Exception:
        pass


def _check_update_async() -> None:
    """后台检查更新并缓存结果。"""
    global _update_result_cache
    try:
        from .updater import check_update, set_current_version
        set_current_version(settings.APP_VERSION)
        _update_result_cache = check_update()
    except Exception:
        pass


@app.get("/api/update/check")
def update_check() -> dict:
    """检查是否有新版本可用。首次调用触发后台检查。"""
    global _update_result_cache
    if _update_result_cache is None:
        _check_update_async()
    return {
        "current_version": settings.APP_VERSION,
        "update_available": _update_result_cache is not None,
        "latest": _update_result_cache,
    }


# ---- 隐私声明 ----

@app.get("/api/privacy")
def privacy() -> dict:
    return {
        "policy_url": "https://github.com/OpenGuardian/OpenGuardian/blob/main/PRIVACY.md",
        "data_collected": ["process_names", "cpu_mem_disk_usage", "network_metadata",
                           "sha256_hashes", "chat_sessions"],
        "data_stored_locally": True,
        "external_services": ["configured_ai_api", "threat_intel_feeds", "github_releases_api"],
        "api_key_encrypted": True,
        "can_delete_all_data": True,
        "gdpr_compliant": True,
    }


# ---- 崩溃日志 ----

@app.get("/api/crashes")
def crash_logs() -> dict:
    try:
        from .crash_reporter import get_recent_crashes
        return {"crashes": get_recent_crashes(5)}
    except Exception:
        return {"crashes": []}


# ---- 健康检查（企业级：含依赖状态 + 延迟统计）----

@app.get("/api/health")
def health() -> dict:
    """增强健康检查：LLM 状态 + DB 状态 + WebSocket 连接数 + 延迟统计。"""
    latency = get_latency_stats()
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "uptime_seconds": round(time.time() - _start_time) if _start_time else 0,
        "llm": "configured" if consultant.llm.available else "unavailable",
        "db": "connected" if db.available else "degraded",
        "ws_clients": get_hub().client_count,
        "latency": latency.summary(),
    }


# ---- WebSocket 实时推送 ----

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket 端点：实时推送系统资源 + 安全告警。"""
    await ws_endpoint(websocket)


# ---- 性能统计（运维用）----

@app.get("/api/metrics")
def metrics() -> dict:
    """延迟统计 + 系统健康（供运维监控）。"""
    import psutil as _psutil
    latency = get_latency_stats()
    return {
        "latency": latency.summary(),
        "routes": {
            route: latency.route_stats(route)
            for route in ["/api/chat", "/api/chat/stream", "/api/stats", "/api/health"]
            if latency.route_stats(route)["count"] > 0
        },
        "system": {
            "cpu_percent": round(_psutil.cpu_percent(interval=0.1), 1),
            "memory_percent": round(_psutil.virtual_memory().percent, 1),
            "ws_clients": get_hub().client_count,
        },
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
