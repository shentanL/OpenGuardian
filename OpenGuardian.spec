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

# 可选数据文件：存在才打包（CI 环境兼容）
_datas = [
    (str(FRONTEND), "frontend"),
    (str(KB_DATA), "backend/kb_data"),
]
if (BASE / "OpenGuardian.ico").exists():
    _datas.append((str(BASE / "OpenGuardian.ico"), "."))
if (BASE / "assets").exists():
    _datas.append((str(BASE / "assets"), "assets"))

# pythonnet 运行时（本机 .venv 或 CI site-packages，存在才打包）
import site
_site_candidates = [
    BACKEND / ".venv" / "Lib" / "site-packages" / "pythonnet" / "runtime",
    Path(site.getsitepackages()[0]) / "pythonnet" / "runtime",
]
_pythonnet_runtime = next((p for p in _site_candidates if p.exists()), None)
if _pythonnet_runtime:
    _datas.append((str(_pythonnet_runtime), "pythonnet/runtime"))

_clr_candidates = [
    BACKEND / ".venv" / "Lib" / "site-packages" / "clr_loader" / "ffi" / "dlls",
    Path(site.getsitepackages()[0]) / "clr_loader" / "ffi" / "dlls",
]
_clr_dlls = next((p for p in _clr_candidates if p.exists()), None)
if _clr_dlls:
    _datas.append((str(_clr_dlls), "clr_loader/ffi/dlls"))

a = Analysis(
    [str(BASE / "desktop_app.py")],
    pathex=[str(BACKEND)],
    binaries=[],
    datas=_datas,
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
        # 新增模块（v0.7.0）
        "app.kb.attack_map", "app.kb.geoip",
        "app.agents.credential", "app.agents.fixer",
        "app.report",
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
