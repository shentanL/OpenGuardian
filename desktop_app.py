"""OpenGuardian 桌面版 —— PyWebView 原生窗口包装。

双击运行此文件启动桌面应用：
- 后台启动 FastAPI 服务（端口 8300）
- 打开原生桌面窗口加载应用界面
- 关闭窗口时自动停止服务
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

import uvicorn
import webview


PROJECT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = PROJECT_DIR / "backend"
PORT = 8300
URL = f"http://127.0.0.1:{PORT}"
TITLE = "OpenGuardian · AI 数字安全平台"


def _start_server() -> None:
    """后台线程启动 FastAPI 服务。"""
    sys.path.insert(0, str(BACKEND_DIR))
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=PORT,
        log_level="warning",
    )


def main() -> None:
    # 启动后端服务（后台线程）
    server = threading.Thread(target=_start_server, daemon=True)
    server.start()

    # 等待服务就绪
    import time

    time.sleep(2)

    # 检查配置状态 → 决定打开哪个页面
    try:
        import urllib.request, json as _json

        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/api/config") as r:
            cfg = _json.loads(r.read())
        target_url = URL if cfg.get("configured") else f"{URL}/config"
    except Exception:  # noqa: BLE001
        target_url = URL

    # 打开桌面窗口
    webview.create_window(TITLE, target_url, width=1280, height=900, min_size=(900, 600))
    webview.start()

    # 窗口关闭后停止服务
    sys.exit(0)


if __name__ == "__main__":
    main()
