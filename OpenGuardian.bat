@echo off
chcp 65001 >nul
title OpenGuardian 桌面版
cd /d "%~dp0"
echo.
echo   OpenGuardian 桌面版 v0.5.8
echo   正在启动...
echo.
backend\.venv\Scripts\python.exe desktop_app.py
