@echo off
chcp 65001 >nul
title OpenGuardian 打包构建
cd /d "%~dp0"
echo.
echo   ╔══════════════════════════════════╗
echo   ║   OpenGuardian 打包构建工具      ║
echo   ╚══════════════════════════════════╝
echo.
echo   [1] 打包为独立文件夹（PyInstaller）
echo   [2] 打包为单个 EXE 文件
echo   [3] 生成 NSIS 安装包（需要安装 NSIS）
echo   [4] 清理构建文件
echo.
set /p choice="请选择 (1-4): "

if "%choice%"=="1" (
    echo   正在打包为独立文件夹...
    backend\.venv\Scripts\pyinstaller OpenGuardian.spec --clean --noconfirm
    echo.
    echo   ✅ 打包完成！输出目录: dist\OpenGuardian\
    echo   双击 dist\OpenGuardian\OpenGuardian.exe 启动
)

if "%choice%"=="2" (
    echo   正在打包为单文件 EXE（可能需要几分钟）...
    backend\.venv\Scripts\pyinstaller --onefile --windowed ^
        --name OpenGuardian --icon OpenGuardian.ico ^
        --add-data "frontend;frontend" ^
        --add-data "backend/kb_data;backend/kb_data" ^
        --add-data "OpenGuardian.ico;." ^
        --paths backend ^
        --hidden-import uvicorn --hidden-import fastapi ^
        --hidden-import app.main --hidden-import app.config ^
        --hidden-import psutil --hidden-import httpx --hidden-import netaddr ^
        desktop_app.py
    echo   ✅ 单文件打包完成！输出文件: dist\OpenGuardian.exe
)

if "%choice%"=="3" (
    echo   正在生成 NSIS 安装脚本...
    if not exist "dist\OpenGuardian" (
        echo   ❌ 请先执行步骤 1 打包为独立文件夹！
        goto end
    )
    echo   ＞ 安装脚本模板已生成: OpenGuardian.nsi
    echo   ＞ 请用 NSIS 编译器打开 OpenGuardian.nsi 生成安装包
)

if "%choice%"=="4" (
    echo   正在清理...
    rmdir /s /q build 2>nul
    rmdir /s /q dist 2>nul
    del /q *.spec.bak 2>nul
    echo   ✅ 已清理
)

:end
echo.
pause
