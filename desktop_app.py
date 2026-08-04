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
import time
from pathlib import Path

import uvicorn

# 可选依赖（桌面模式需要 pip install pywebview pystray Pillow）
try:
    import webview
    _WEBVIEW_OK = True
except ImportError:
    _WEBVIEW_OK = False

try:
    from PIL import Image, ImageDraw
    _PIL_OK = True
except ImportError:
    Image = None  # type: ignore
    ImageDraw = None  # type: ignore
    _PIL_OK = False

try:
    import pystray
    _PYSTRAY_OK = True
except ImportError:
    pystray = None  # type: ignore
    _PYSTRAY_OK = False

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


def _get_asset_path(relative_path: str) -> str:
    """获取打包后的资源文件路径（兼容 PyInstaller 和开发模式）。"""
    import sys as _sys
    if getattr(_sys, "frozen", False) and hasattr(_sys, "_MEIPASS"):
        p = Path(_sys._MEIPASS) / relative_path
    else:
        p = PROJECT_DIR / relative_path
    return str(p) if p.exists() else ""


def _kill_port(port: int) -> None:
    """杀死占用指定端口的进程（Windows）。"""
    import subprocess
    try:
        r = subprocess.run(
            ["netstat", "-ano"], capture_output=True, text=True, errors="replace", timeout=5,
        )
        for line in r.stdout.splitlines():
            if f":{port}" in line and "LISTENING" in line:
                pid = line.strip().split()[-1]
                subprocess.run(["taskkill", "/F", "/PID", pid],
                    capture_output=True, timeout=5)
                break
    except Exception:
        pass


def _start_server() -> None:
    """后台线程启动 FastAPI 服务（启动前先清理旧进程）。"""
    sys.path.insert(0, str(BACKEND_DIR))
    _kill_port(PORT)
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=PORT,
        log_level="warning",
    )


def _load_icon():
    """加载托盘图标（从 ico 文件提取合适尺寸）。"""
    if ICO_PATH.exists() and _PIL_OK:
        img = Image.open(ICO_PATH)
        if hasattr(img, "size"):
            return img
    # 后备：生成简单图标
    if not _PIL_OK:
        return None
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
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


def _build_launch_html(target_url: str) -> str:
    """构建启动页 HTML：粒子动画 2s 后自动跳转到目标页。"""
    return """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#000;display:flex;align-items:center;justify-content:center;
height:100vh;overflow:hidden;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
-webkit-app-region:drag;user-select:none;}
canvas{position:fixed;inset:0;z-index:0}
.splash{position:relative;z-index:1;text-align:center;display:flex;flex-direction:column;align-items:center;gap:20px}
.icon-wrap{position:relative;width:120px;height:120px}
.icon-wrap svg{width:120px;height:120px;position:relative;z-index:2}
.scan-ring{position:absolute;inset:-12px;border-radius:50%;border:2px solid rgba(118,185,0,0.2);animation:scan-pulse 2s ease-in-out infinite;z-index:1}
.scan-ring:nth-child(2){animation-delay:.5s}
.scan-ring:nth-child(3){animation-delay:1s}
@keyframes scan-pulse{0%{transform:scale(.9);opacity:.8;border-color:rgba(118,185,0,.4)}50%{transform:scale(1.15);opacity:.2;border-color:rgba(191,242,48,.1)}100%{transform:scale(.9);opacity:.8;border-color:rgba(118,185,0,.4)}}
.brand{font-size:32px;font-weight:800;letter-spacing:3px;color:#fff;text-shadow:0 0 30px rgba(118,185,0,.5);animation:text-flicker 3s ease-in-out infinite}
.brand span{color:#76b900}
@keyframes text-flicker{0%,100%{opacity:1}93%{opacity:1}94%{opacity:.6}95%{opacity:1}96%{opacity:.5}97%{opacity:1}}
.tagline{font-size:12px;color:#757575;letter-spacing:4px;animation:fade-up .8s ease-out .3s both}
.progress-wrap{width:280px;height:2px;background:#1a1a1a;border-radius:1px;overflow:hidden;animation:fade-up .8s ease-out .5s both}
.progress-bar{height:100%;width:0%;background:linear-gradient(90deg,#76b900,#bff230);border-radius:1px;transition:width .4s ease;box-shadow:0 0 8px rgba(118,185,0,.6)}
.status{font-size:11px;color:#a7a7a7;letter-spacing:1px;font-family:ui-monospace,monospace;animation:fade-up .8s ease-out .7s both}
@keyframes fade-up{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.version{position:fixed;bottom:20px;font-size:9px;color:#3a3a3a;letter-spacing:2px}
</style></head><body>
<canvas id="bg"></canvas>
<div class="splash">
<div class="icon-wrap">
<div class="scan-ring"></div><div class="scan-ring"></div><div class="scan-ring"></div>
<svg viewBox="0 0 256 256">
<circle cx="128" cy="128" r="120" fill="none" stroke="#1a1a1a" stroke-width="1"/>
<path d="M128 20 L218 50 L218 130 C218 190 170 228 128 244 C86 228 38 190 38 130 L38 50 Z" fill="#0a0a0a" stroke="#76b900" stroke-width="3"/>
<circle cx="128" cy="120" r="8" fill="#76b900"/>
<circle cx="128" cy="80" r="4" fill="#bff230"/><line x1="128" y1="112" x2="128" y2="84" stroke="#76b900" stroke-width="1.5"/>
<circle cx="100" cy="120" r="4" fill="#bff230"/><line x1="120" y1="120" x2="104" y2="120" stroke="#76b900" stroke-width="1.5"/>
<circle cx="156" cy="120" r="4" fill="#bff230"/><line x1="136" y1="120" x2="152" y2="120" stroke="#76b900" stroke-width="1.5"/>
<circle cx="128" cy="160" r="4" fill="#bff230"/><line x1="128" y1="128" x2="128" y2="156" stroke="#76b900" stroke-width="1.5"/>
<path d="M108 182 L122 196 L152 164" fill="none" stroke="#76b900" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
</div>
<div class="brand"><span>Open</span>Guardian</div>
<div class="tagline">AI 数字安全平台</div>
<div class="progress-wrap"><div class="progress-bar" id="progress"></div></div>
<div class="status" id="status">正在初始化引擎…</div>
</div>
<div class="version">v0.7.0</div>
<script>
(function(){var c=document.getElementById('bg'),ctx=c.getContext('2d');var W=c.width=window.innerWidth,H=c.height=window.innerHeight;var pts=[];for(var i=0;i<40;i++)pts.push({x:Math.random()*W,y:Math.random()*H,vx:(Math.random()-.5)*.4,vy:(Math.random()-.5)*.4,r:Math.random()*1+.4});function loop(){ctx.clearRect(0,0,W,H);for(var i=0;i<pts.length;i++){var p=pts[i];p.x+=p.vx;p.y+=p.vy;if(p.x<0)p.x=W;if(p.x>W)p.x=0;if(p.y<0)p.y=H;if(p.y>H)p.y=0;ctx.fillStyle='rgba(118,185,0,.45)';ctx.beginPath();ctx.arc(p.x,p.y,p.r,0,Math.PI*2);ctx.fill();for(var j=i+1;j<pts.length;j++){var p2=pts[j],dx=p.x-p2.x,dy=p.y-p2.y,d=Math.sqrt(dx*dx+dy*dy);if(d<90){ctx.strokeStyle='rgba(118,185,0,'+(.1*(1-d/90))+')';ctx.lineWidth=.5;ctx.beginPath();ctx.moveTo(p.x,p.y);ctx.lineTo(p2.x,p2.y);ctx.stroke()}}}requestAnimationFrame(loop)}loop()})();
var bar=document.getElementById('progress'),status=document.getElementById('status');
var steps=[{pct:20,msg:'正在加载检测引擎…'},{pct:45,msg:'同步威胁情报数据库…'},{pct:70,msg:'初始化 AI 安全助手…'},{pct:90,msg:'连接系统防护服务…'},{pct:100,msg:'准备就绪'}];
var step=0;function advance(){if(step>=steps.length){return}var s=steps[step];bar.style.width=s.pct+'%';status.textContent=s.msg;step++;if(step<steps.length){setTimeout(advance,550+Math.random()*300)}}setTimeout(advance,300);
// 所有进度步完成后再跳转（~4.5s）
var totalTime=(steps.length*850)+500;setTimeout(function(){window.location.replace('__TARGET_URL__');},totalTime);
</script></body></html>""".replace("__TARGET_URL__", target_url)


def _on_closing():
    """窗口关闭时最小化到托盘，不退出。"""
    global _window
    if _window:
        _window.hide()
    return False  # 阻止 webview 默认关闭行为


def main() -> None:
    global _window, _server_thread, _tray_icon

    # 依赖检查
    missing = []
    if not _WEBVIEW_OK:
        missing.append("pywebview")
    if not _PYSTRAY_OK:
        missing.append("pystray")
    if not _PIL_OK:
        missing.append("Pillow")
    # 检查 .NET Desktop Runtime（pywebview EdgeChromium 后端必需）
    _dotnet_ok = False
    # 方法 1: 检查标准安装目录（不依赖 PATH）
    _dotnet_dirs = [
        Path("C:/Program Files/dotnet/shared/Microsoft.WindowsDesktop.App"),
        Path("C:/Program Files (x86)/dotnet/shared/Microsoft.WindowsDesktop.App"),
    ]
    for _dd in _dotnet_dirs:
        if _dd.exists():
            _dotnet_ok = True
            break
    # 方法 2: 尝试 dotnet CLI
    if not _dotnet_ok:
        try:
            import subprocess as _sp
            _r = _sp.run(["dotnet", "--list-runtimes"], capture_output=True, text=True, timeout=5)
            if "Microsoft.NETCore.App" in _r.stdout or "Microsoft.WindowsDesktop.App" in _r.stdout:
                _dotnet_ok = True
        except Exception:
            pass
    if not _dotnet_ok:
        missing.append(".NET Desktop Runtime 8.0 (https://dotnet.microsoft.com/download)")
    if missing:
        print(f"桌面模式缺少依赖: {', '.join(missing)}")
        print(f"请运行: pip install {' '.join(missing)}")
        print("或者直接使用 Web 模式：cd backend && uvicorn app.main:app --port 8300")
        sys.exit(1)

    # 1. 启动后端服务
    _server_thread = threading.Thread(target=_start_server, daemon=True)
    _server_thread.start()

    # 2. 启动系统托盘图标
    tray_icon = _load_icon()
    if tray_icon and _PYSTRAY_OK:
        menu = pystray.Menu(
            pystray.MenuItem("显示 OpenGuardian", _show_window, default=True),
            pystray.MenuItem("退出", _exit_app),
        )
        _tray_icon = pystray.Icon("OpenGuardian", tray_icon, TITLE, menu)
        threading.Thread(target=_tray_icon.run, daemon=True).start()

    # 3. 等待后端就绪（先启动后端，再开窗口，避免空白页）
    target_url = URL
    for attempt in range(20):
        time.sleep(0.15 * (attempt + 1))
        try:
            import urllib.request
            with urllib.request.urlopen(f"{URL}/api/health", timeout=1.5) as r:
                if r.status == 200:
                    break
        except Exception:
            if attempt == 19:
                print("警告: 后端启动超时")

    # 4. 检查是否首次运行 → 选择目标页
    try:
        import urllib.request, json as _json
        with urllib.request.urlopen(f"{URL}/api/config") as r:
            cfg = _json.loads(r.read())
        if not cfg.get("configured"):
            target_url = f"{URL}/config"
    except Exception:
        pass

    # 5. 构建带进场动画的启动页 HTML（加载后自动跳转）
    launch_html = _build_launch_html(target_url)

    # 6. 打开窗口（先显示进场动画，500ms 后自动跳转到目标页）
    _window = webview.create_window(
        TITLE, html=launch_html,
        width=1280, height=900,
        min_size=(900, 600),
    )

    # 绑定关闭事件 → 最小化到托盘
    try:
        _window.events.closing += _on_closing
    except Exception:
        pass

    webview.start(private_mode=False)
    sys.exit(0)


if __name__ == "__main__":
    main()
