"""PyInstaller runtime hook — 确保 pythonnet + pywebview 能在 frozen 环境中运行。

关键：pythonnet 依赖系统安装的 .NET Desktop Runtime（不能捆绑）。
此 hook 只做路径修正，不强制设置 PYTHONNET_RUNTIME。
"""
import os
import sys


def _fixup():
    if not getattr(sys, "frozen", False):
        return

    base = getattr(sys, "_MEIPASS", "") or ""

    # 将 pythonnet runtime DLL 目录加入 PATH（让 Windows 能找到 Python.Runtime.dll）
    runtime_dir = os.path.join(base, "pythonnet", "runtime")
    if os.path.isdir(runtime_dir):
        path = os.environ.get("PATH", "")
        if runtime_dir not in path:
            os.environ["PATH"] = runtime_dir + ";" + path

    # clr_loader DLL 目录
    clr_dir = os.path.join(base, "clr_loader", "ffi", "dlls", "amd64")
    if os.path.isdir(clr_dir):
        path = os.environ.get("PATH", "")
        if clr_dir not in path:
            os.environ["PATH"] = clr_dir + ";" + path

    # 确保 pythonnet 根目录在 sys.path 中
    py_dir = os.path.join(base, "pythonnet")
    if os.path.isdir(py_dir) and py_dir not in sys.path:
        sys.path.insert(0, py_dir)

    # ★ 不设置 PYTHONNET_RUNTIME —— 让 pythonnet 自动检测系统 .NET
    # 如果系统没有 .NET Desktop Runtime，会回退到 Web 模式
    # 用户需安装 .NET 8.0 Desktop Runtime: https://dotnet.microsoft.com/en-us/download/dotnet/8.0


_fixup()
