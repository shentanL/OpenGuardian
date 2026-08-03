@echo off
chcp 65001 >nul
title OpenGuardian
echo.
echo   ╔══════════════════════════════════╗
echo   ║   OpenGuardian v0.5.8          ║
echo   ║   AI 个人数字安全服务平台       ║
echo   ╚══════════════════════════════════╝
echo.
echo   正在启动服务...
cd /d "%~dp0backend"

REM 启动后端服务
start "" /B .venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8300

REM 等待服务就绪后打开浏览器
echo   等待服务就绪...
timeout /t 4 /nobreak >nul
start "" http://127.0.0.1:8300

echo.
echo   ✅ 服务已启动在 http://127.0.0.1:8300
echo   关闭此窗口不会停止服务
echo.
pause
