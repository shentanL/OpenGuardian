"""OpenGuardian 桌面版 —— PyWebView 原生窗口 + 系统托盘。

双击运行此文件启动桌面应用：
- 后台启动 FastAPI 服务（端口 8300）
- 打开原生桌面窗口加载应用界面
- 关闭窗口时最小化到系统托盘（不退出进程）
- 右击托盘图标 → 显示窗口 / 退出
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

import uvicorn
import webview
from PIL import Image
import pystray
import os as _os

PROJECT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = PROJECT_DIR / "backend"
PORT = 8300
URL = f"http://127.0.0.1:{PORT}"
TITLE = "OpenGuardian · AI 数字安全平台"
ICO_PATH = PROJECT_DIR / "OpenGuardian.ico"

# 全局窗口引用
_window = None
_server_thread = None
_tray_icon = None


def _start_server() -> None:
    """后台线程启动 FastAPI 服务。"""
    sys.path.insert(0, str(BACKEND_DIR))
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=PORT,
        log_level="warning",
    )


def _load_icon():
    """加载托盘图标（从 ico 文件提取合适尺寸）。"""
    if ICO_PATH.exists():
        img = Image.open(ICO_PATH)
        # 取最大的尺寸做托盘图标
        if hasattr(img, "size"):
            return img
    # 后备：生成简单图标
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    # 简单绿色方块
    from PIL import ImageDraw
    draw = ImageDraw.Draw(img)
    draw.rectangle([8, 8, size - 8, size - 8], fill=(118, 185, 0))
    return img


def _show_window(icon=None, item=None):
    """显示/恢复桌面窗口。"""
    global _window
    if _window is None:
        return
    try:
        if not _window.evaluate_js("true"):  # 窗口还存在？
            return
    except Exception:
        return
    # webview 没有直接的 show/hide，创建一个新窗口
    # 实际用 pywebview 的窗口管理
    _window.show()
    _window.restore()


def _exit_app(icon=None, item=None):
    """完全退出应用——强制终止所有线程（解决 sys.exit() 杀不掉后台线程的问题）。"""
    global _window, _tray_icon
    if _tray_icon:
        try:
            _tray_icon.stop()
        except Exception:
            pass
    if _window:
        try:
            _window.destroy()
        except Exception:
            pass
    # os._exit() 立即终止进程，不等待守护线程
    _os._exit(0)


def _on_closing():
    """窗口关闭时最小化到托盘，不退出。"""
    global _window
    if _window:
        _window.hide()
    return False  # 阻止 webview 默认关闭行为


def main() -> None:
    global _window, _server_thread, _tray_icon

    # 1. 启动后端服务
    _server_thread = threading.Thread(target=_start_server, daemon=True)
    _server_thread.start()

    import time
    time.sleep(2)

    # 2. 检查配置 → 决定打开哪个页面
    try:
        import urllib.request, json as _json
        with urllib.request.urlopen(f"{URL}/api/config") as r:
            cfg = _json.loads(r.read())
        target_url = URL if cfg.get("configured") else f"{URL}/config"
    except Exception:
        target_url = URL

    # 3. 启动系统托盘图标
    tray_icon = _load_icon()
    menu = pystray.Menu(
        pystray.MenuItem("显示 OpenGuardian", _show_window, default=True),
        pystray.MenuItem("退出", _exit_app),
    )
    _tray_icon = pystray.Icon("OpenGuardian", tray_icon, TITLE, menu)
    threading.Thread(target=_tray_icon.run, daemon=True).start()

    # 4. 打开桌面窗口
    _window = webview.create_window(
        TITLE, target_url,
        width=1280, height=900,
        min_size=(900, 600),
        on_top=False,
    )

    # 绑定关闭事件 → 最小化到托盘
    try:
        _window.events.closing += _on_closing
    except Exception:
        pass

    webview.start()

    # 窗口关闭后（通常不会走到这里，因为 closing 被拦截）
    sys.exit(0)


if __name__ == "__main__":
    main()
