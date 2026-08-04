# -*- mode: python ; coding: utf-8 -*-
"""OpenGuardian v0.6.0 PyInstaller 打包配置（优化版）。

使用: pyinstaller OpenGuardian.spec
输出: dist/OpenGuardian/ (独立文件夹，可直接分发)

优化要点：
- 排除未使用的 GUI 后端（PyQt5/6、Tkinter、gi）→ 减小 10-20MB
- 排除 dev 工具包（pip/setuptools/pytest）→ 减小 5-10MB
- 指定 pywebview 的 hookspath → 确保 EdgeChromium 后端正确打包
- 精简 hiddenimports → 仅保留必须手动指定的
"""
from __future__ import annotations

import sys
from pathlib import Path

BASE = Path(SPECPATH)
BACKEND = BASE / "backend"
FRONTEND = BASE / "frontend"
KB_DATA = BACKEND / "kb_data"

# pywebview hook 路径（确保 JS API 文件正确打包）
import webview as _wv
_WEBVIEW_HOOKS = str(Path(_wv.__file__).parent / "__pyinstaller")

a = Analysis(
    [str(BASE / "desktop_app.py")],
    pathex=[str(BACKEND)],
    binaries=[],
    datas=[
        (str(FRONTEND), "frontend"),
        (str(KB_DATA), "backend/kb_data"),
        (str(BASE / "OpenGuardian.ico"), "."),
        (str(BASE / "assets"), "assets"),
        (str(BASE / "backend" / ".env"), "backend"),
        # pythonnet .NET 运行时（pywebview EdgeChromium 必需，97 DLLs）
        (str(BACKEND / ".venv" / "Lib" / "site-packages" / "pythonnet" / "runtime"), "pythonnet/runtime"),
        (str(BACKEND / ".venv" / "Lib" / "site-packages" / "clr_loader" / "ffi" / "dlls"), "clr_loader/ffi/dlls"),
    ],
    hiddenimports=[
        # Web 框架
        "uvicorn", "uvicorn.logging", "uvicorn.loops",
        "uvicorn.loops.auto", "uvicorn.protocols",
        "uvicorn.protocols.http", "uvicorn.protocols.http.auto",
        "fastapi", "starlette", "pydantic",
        # 系统
        "psutil", "httpx", "netaddr", "dotenv",
        # pywebview 依赖
        "pythonnet", "clr", "clr_loader",
        "webview", "webview.platforms.edgechromium",
        # App 核心
        "app", "app.main", "app.config", "app.db", "app.schemas",
        "app.bus", "app.config_manager", "app.sampler", "app.security",
        # Agent 系统
        "app.agents", "app.agents.base",
        "app.agents.consultant", "app.agents.detector",
        "app.agents.analyst", "app.agents.educator",
        "app.agents.executor", "app.agents.vuln",
        "app.agents.patterns_ext",
        "app.agents.verifier", "app.agents.reflector",
        "app.agents.tools",
        # LLM
        "app.llm", "app.llm.client", "app.llm.providers",
        # KB
        "app.kb", "app.kb.blacklists", "app.kb.glossary",
        "app.kb.updater", "app.kb.virus_hashes", "app.kb.ingestion",
        # 基础设施
        "app.async_util", "app.crypto_storage", "app.rate_limit",
        "app.prompts", "app.memory", "app.triage",
        "app.middleware", "app.errors", "app.realtime",
        "app.updater", "app.etw_monitor", "app.wsc_register",
        "app.i18n", "app.crash_reporter",
        "app.agents.attack_chain", "app.agents.cve_check",
        "app.kb.vector_search", "app.kb.fuzzy_hash",
        "app.agents.behavioral",
        "app.llm.offline_fallback",
        # pywebview（仅 Windows EdgeChromium 后端）
        "webview",
        "webview.platforms.edgechromium",
        # 可选桌面依赖
        "pystray", "PIL", "PIL.Image", "PIL.ImageDraw",
    ],
    hookspath=[_WEBVIEW_HOOKS],
    hooksconfig={},
    runtime_hooks=[str(BACKEND / "runtime_hook.py")],
    excludes=[
        # 未使用的 GUI 后端 —— 减小 10-20MB
        "PyQt5", "PyQt6", "PySide2", "PySide6", "gi",
        "tkinter", "_tkinter", "tcl", "tk",
        "matplotlib", "numpy", "scipy", "pandas",
        # Dev 工具 —— 减小 5-10MB
        "pip", "setuptools", "wheel", "pkg_resources",
        "pytest", "unittest", "coverage",
        # 不需要的 webview 后端（保留 winforms——pywebview 的 EdgeChromium 需要它做 fallback）
        "webview.platforms.cocoa",
        "webview.platforms.gtk",
        "webview.platforms.qt",
        "webview.platforms.cef",
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="OpenGuardian",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(BASE / "OpenGuardian.ico"),
)

coll = COLLECT(
    exe, a.binaries, a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="OpenGuardian",
)
