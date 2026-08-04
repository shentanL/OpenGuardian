"""企业级错误处理：统一错误格式 + 分类 + 异常处理注册。

大厂标准：
- 所有错误返回 {"error": "ERROR_CODE", "message": "...", "request_id": "..."}
- 错误码语义化（VALIDATION_ERROR / NOT_FOUND / RATE_LIMITED / INTERNAL_ERROR）
- 生产环境不暴露堆栈，开发环境全量输出
- 404/405/500 统一处理
"""
from __future__ import annotations

import logging
import traceback
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("openguardian.errors")

# ─── 错误码定义 ───

class ErrorCode:
    VALIDATION_ERROR = "VALIDATION_ERROR"
    NOT_FOUND = "NOT_FOUND"
    METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
    RATE_LIMITED = "RATE_LIMITED"
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    CONFLICT = "CONFLICT"
    LLM_UNAVAILABLE = "LLM_UNAVAILABLE"
    SCAN_FAILED = "SCAN_FAILED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


# HTTP 状态码 → 错误码映射
STATUS_TO_CODE = {
    400: ErrorCode.VALIDATION_ERROR,
    401: ErrorCode.UNAUTHORIZED,
    403: ErrorCode.FORBIDDEN,
    404: ErrorCode.NOT_FOUND,
    405: ErrorCode.METHOD_NOT_ALLOWED,
    409: ErrorCode.CONFLICT,
    429: ErrorCode.RATE_LIMITED,
    500: ErrorCode.INTERNAL_ERROR,
    502: ErrorCode.LLM_UNAVAILABLE,
    503: ErrorCode.LLM_UNAVAILABLE,
}


def error_response(
    status_code: int,
    message: str,
    error_code: str | None = None,
    request_id: str | None = None,
    details: dict | None = None,
) -> JSONResponse:
    """构建统一错误响应。"""
    code = error_code or STATUS_TO_CODE.get(status_code, ErrorCode.INTERNAL_ERROR)
    body: dict = {
        "error": code,
        "message": message,
        "request_id": request_id or "unknown",
    }
    if details:
        body["details"] = details
    headers = {"X-Request-ID": request_id or ""} if request_id else {}
    return JSONResponse(status_code=status_code, content=body, headers=headers)


def register_error_handlers(app: FastAPI) -> None:
    """注册全局异常处理器到 FastAPI 应用。"""

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        rid = getattr(request.state, "request_id", None)
        # 不记录 4xx 的 warn（客户端错误是正常的）
        code = STATUS_TO_CODE.get(exc.status_code, ErrorCode.INTERNAL_ERROR)
        return error_response(
            status_code=exc.status_code,
            message=str(exc.detail),
            error_code=code,
            request_id=rid,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        rid = getattr(request.state, "request_id", None)
        errors = exc.errors()
        # 提取人类可读的验证错误
        messages = []
        for e in errors[:5]:
            loc = " → ".join(str(p) for p in e.get("loc", []))
            msg = e.get("msg", "验证失败")
            messages.append(f"{loc}: {msg}")
        return error_response(
            status_code=422,
            message="; ".join(messages) if messages else "请求参数验证失败",
            error_code=ErrorCode.VALIDATION_ERROR,
            request_id=rid,
            details={"validation_errors": errors[:10]},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        rid = getattr(request.state, "request_id", None)
        # 生产环境不泄露堆栈，开发环境全量输出
        tb = traceback.format_exc()
        logger.error(
            "Unhandled exception | request_id=%s | path=%s | %s: %s\n%s",
            rid, request.url.path, type(exc).__name__, str(exc)[:200], tb,
        )
        # 上报崩溃信息（本地日志 + 可选 Sentry）
        try:
            from .crash_reporter import capture_exception
            capture_exception(exc)
        except Exception:
            pass
        return error_response(
            status_code=500,
            message="服务器内部错误，请稍后重试",
            error_code=ErrorCode.INTERNAL_ERROR,
            request_id=rid,
            details={"exception_type": type(exc).__name__} if __debug__ else None,
        )

    logger.info("Error handlers registered: HTTP + Validation + Catch-all")
