"""ETW 实时进程监控 —— 通过 WMI 订阅替代 psutil.process_iter() 轮询。

使用 Win32_ProcessStartTrace / Win32_ProcessStopTrace 实时捕获进程创建/终止，
避免 O(n) 全进程扫描的性能开销。
"""
from __future__ import annotations

import logging
import queue
import threading
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# 事件类型
ProcessEvent = dict  # {event: "start"|"stop", pid: int, name: str, time: str}


class ETWProcessMonitor:
    """通过 WMI 事件订阅实时监听进程创建与终止。

    使用方式：
        monitor = ETWProcessMonitor()
        monitor.on_process(lambda evt: print(f"{evt['event']}: {evt['name']}"))
        monitor.start()
        ...
        monitor.stop()
    """

    def __init__(self):
        self._callbacks: list[Callable] = []
        self._running = False
        self._thread: threading.Thread | None = None

    def on_process(self, callback: Callable[[ProcessEvent], None]) -> None:
        self._callbacks.append(callback)

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name="etw-monitor")
        self._thread.start()
        logger.info("ETW 进程监控已启动（WMI 事件订阅）")

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=3.0)
            self._thread = None
        logger.info("ETW 进程监控已停止")

    def _poll_loop(self) -> None:
        """通过 PowerShell + WMI 事件订阅实时监听进程。

        订阅 Win32_ProcessStartTrace 和 Win32_ProcessStopTrace。
        若 PowerShell 不可用则降级为 psutil 轮询。
        """
        import subprocess
        import time as _time
        import json as _json

        ps_script = """
$Action = {
    $event = $Event.SourceEventArgs.NewEvent
    $obj = @{
        event = if ($event.__CLASS -match 'Stop') { 'stop' } else { 'start' }
        pid = $event.ProcessID
        name = $event.ProcessName
        time = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
    } | ConvertTo-Json -Compress
    Write-Output $obj
}

$q1 = "SELECT * FROM Win32_ProcessStartTrace"
$q2 = "SELECT * FROM Win32_ProcessStopTrace"

$watcher1 = Register-CimIndicationEvent -Query $q1 -Action $Action -ErrorAction SilentlyContinue
$watcher2 = Register-CimIndicationEvent -Query $q2 -Action $Action -ErrorAction SilentlyContinue

try {
    while ($true) {
        Start-Sleep -Seconds 1
    }
} finally {
    Unregister-Event -SourceIdentifier $watcher1.Name -ErrorAction SilentlyContinue
    Unregister-Event -SourceIdentifier $watcher2.Name -ErrorAction SilentlyContinue
}
"""
        try:
            proc = subprocess.Popen(
                ["powershell", "-NoProfile", "-Command", ps_script],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            while self._running and proc.poll() is None:
                line = proc.stdout.readline()
                if line.strip():
                    try:
                        evt = _json.loads(line.strip())
                        for cb in self._callbacks:
                            try:
                                cb(evt)
                            except Exception:
                                pass
                    except _json.JSONDecodeError:
                        continue
            proc.terminate()
        except Exception as exc:
            logger.debug("ETW/WMI 监控启动失败，降级为 psutil 轮询: %s", exc)
            # 降级：psutil 轮询
            self._fallback_polling()

    def _fallback_polling(self) -> None:
        """psutil 轮询降级方案。"""
        import time as _time
        import psutil

        known_pids: set[int] = set()
        try:
            for proc in psutil.process_iter(["pid", "name"]):
                known_pids.add(proc.info["pid"])
        except Exception:
            pass

        while self._running:
            _time.sleep(2)
            try:
                current: set[int] = set()
                for proc in psutil.process_iter(["pid", "name"]):
                    pid = proc.info["pid"]
                    current.add(pid)
                    if pid not in known_pids:
                        name = proc.info["name"] or ""
                        import time as _t
                        for cb in self._callbacks:
                            try:
                                cb({"event": "start", "pid": pid, "name": name,
                                    "time": _t.strftime("%Y-%m-%dT%H:%M:%S")})
                            except Exception:
                                pass
                stopped = known_pids - current
                for pid in stopped:
                    for cb in self._callbacks:
                        try:
                            cb({"event": "stop", "pid": pid, "name": "",
                                "time": _t.strftime("%Y-%m-%dT%H:%M:%S")})
                        except Exception:
                            pass
                known_pids = current
            except Exception:
                pass


# 全局单例
_monitor: ETWProcessMonitor | None = None


def get_monitor() -> ETWProcessMonitor:
    global _monitor
    if _monitor is None:
        _monitor = ETWProcessMonitor()
    return _monitor
