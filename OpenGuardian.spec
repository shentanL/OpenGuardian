# -*- mode: python ; coding: utf-8 -*-
"""OpenGuardian PyInstaller 打包配置（Windows 软件安装包）。

使用: pyinstaller OpenGuardian.spec
输出: dist/OpenGuardian/ (包含所有依赖和数据文件)
"""
from __future__ import annotations

import sys
from pathlib import Path

# 项目根目录（spec 文件即在此目录）
BASE = Path(SPECPATH)
BACKEND = BASE / "backend"
FRONTEND = BASE / "frontend"
KB_DATA = BACKEND / "kb_data"

a = Analysis(
    [str(BASE / "desktop_app.py")],
    pathex=[str(BACKEND)],
    binaries=[],
    datas=[
        (str(FRONTEND), "frontend"),     # 前端文件（HTML/CSS/JS/icons）
        (str(KB_DATA), "backend/kb_data"),  # 知识库数据文件
        (str(BASE / "OpenGuardian.ico"), "."),  # 图标
        (str(BASE / "backend" / ".env"), "backend"),  # .env 环境变量（API Key）
    ],
    hiddenimports=[
        "uvicorn", "uvicorn.logging", "uvicorn.loops",
        "uvicorn.loops.auto", "uvicorn.protocols",
        "uvicorn.protocols.http", "uvicorn.protocols.http.auto",
        "fastapi", "starlette", "psutil", "httpx", "netaddr",
        "pydantic", "pydantic_settings",
        "app", "app.main", "app.config", "app.db", "app.schemas",
        "app.bus", "app.agents", "app.agents.base",
        "app.agents.consultant", "app.agents.detector",
        "app.agents.analyst", "app.agents.educator",
        "app.agents.vuln", "app.agents.patterns_ext",
        "app.llm", "app.llm.client", "app.llm.providers",
        "app.kb", "app.kb.blacklists", "app.kb.glossary",
        "app.kb.updater", "app.kb.virus_hashes",
        "app.config_manager", "app.sampler", "app.security",
        "dotenv",  # python-dotenv（.env 读取）
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
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

# 输出目录（独立文件夹，可直接分发）
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="OpenGuardian",
)
