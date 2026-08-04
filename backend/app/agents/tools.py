"""可扩展安全检测工具链。

每个工具：
- 接收结构化参数，返回结构化结果（JSON-serializable dict）
- 带超时保护，失败不中断整体检测
- 可被 Detector / Verifier / Reflector 调用

当前工具：
1. check_signature   — 数字签名验证（PowerShell Get-AuthenticodeSignature）
2. process_tree      — 进程父子关系分析
3. network_profile   — 进程网络行为画像（连接数、流量目标）
4. file_entropy      — 文件熵值检测（高熵 = 可能加壳/加密）
"""
from __future__ import annotations

import hashlib
import json
import logging
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import psutil

logger = logging.getLogger(__name__)


# ─── 工具注册表 ───


@dataclass
class ToolDef:
    """工具定义（类似 OpenAI function calling 的 schema）。"""
    name: str
    description: str
    parameters: dict  # JSON Schema for parameters
    fn: Callable[..., dict]


_tools: dict[str, ToolDef] = {}


def register(name: str, description: str, parameters: dict):
    """装饰器：注册工具到全局注册表。"""
    def decorator(fn):
        _tools[name] = ToolDef(
            name=name,
            description=description,
            parameters=parameters,
            fn=fn,
        )
        return fn
    return decorator


def get_tool(name: str) -> ToolDef | None:
    return _tools.get(name)


def list_tools() -> list[dict]:
    """列出所有可用工具（供 Agent 发现）。"""
    return [
        {"name": t.name, "description": t.description, "parameters": t.parameters}
        for t in _tools.values()
    ]


def call_tool(name: str, **params) -> dict:
    """调用一个工具，返回结果 dict（必定包含 success 字段）。"""
    tool = _tools.get(name)
    if not tool:
        return {"success": False, "error": f"未知工具: {name}"}
    start = time.time()
    try:
        result = tool.fn(**params)
        result["success"] = True
        result["_tool"] = name
        result["_elapsed_ms"] = round((time.time() - start) * 1000)
        return result
    except Exception as exc:
        logger.warning("Tool %s failed: %s", name, exc)
        return {
            "success": False,
            "error": str(exc),
            "_tool": name,
            "_elapsed_ms": round((time.time() - start) * 1000),
        }


# ─── 工具实现 ───


@register(
    "check_signature",
    "验证可执行文件的数字签名（Windows Authenticode）",
    {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "可执行文件的完整路径"},
        },
        "required": ["path"],
    },
)
def check_signature(path: str) -> dict:
    """验证 PE 文件数字签名。"""
    exe_path = Path(path)
    if not exe_path.exists():
        return {"signed": False, "status": "file_not_found", "signer": None}

    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"(Get-AuthenticodeSignature -FilePath '{path}' | "
             "Select-Object Status, SignerCertificate | ConvertTo-Json -Compress)"],
            capture_output=True, text=True, errors="replace", timeout=10,
        )
        data = json.loads(r.stdout)
        status = data.get("Status", 2)  # 0=Valid, 1=NotSigned, 2=UnknownError
        signer_info = data.get("SignerCertificate", {})
        signer = (signer_info.get("Subject") or "").strip() if signer_info else None

        return {
            "signed": status == 0,
            "status": {0: "valid", 1: "not_signed", 2: "error"}.get(status, "error"),
            "signer": signer,
            "trusted": any(
                vendor in (signer or "").lower()
                for vendor in ("microsoft", "google", "adobe", "apple", "intel",
                              "nvidia", "amd", "oracle", "vmware", "dell", "hp",
                              "lenovo", "samsung", "dropbox", "slack", "zoom",
                              "jetbrains", "github", "gitlab")
            ) if signer else False,
        }
    except Exception:
        return {"signed": False, "status": "check_failed", "signer": None}


@register(
    "process_tree",
    "分析进程的父子关系链，检测可疑启动模式",
    {
        "type": "object",
        "properties": {
            "pid": {"type": "integer", "description": "目标进程 PID"},
        },
        "required": ["pid"],
    },
)
def process_tree(pid: int) -> dict:
    """分析进程树：父进程 → 目标进程 → 子进程。

    可疑模式：
    - Word/Excel 启动了 cmd.exe/powershell.exe
    - 普通用户进程启动了隐藏窗口的进程
    - 短时大量子进程（爆破特征）
    """
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        exe = proc.exe() if hasattr(proc, "exe") else ""

        # 父进程链（向上 3 层）
        ancestors: list[dict] = []
        current = proc
        for _ in range(3):
            try:
                parent = current.parent()
                if parent is None:
                    break
                ancestors.append({
                    "pid": parent.pid,
                    "name": parent.name(),
                    "exe": (parent.exe() if hasattr(parent, "exe") else ""),
                })
                current = parent
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break

        # 子进程（向下 1 层）
        children: list[dict] = []
        try:
            for child in proc.children(recursive=False):
                try:
                    children.append({
                        "pid": child.pid,
                        "name": child.name(),
                        "status": child.status(),
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        # 可疑模式检测
        suspicious_patterns: list[str] = []
        office_parents = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
        shell_children = {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"}

        for a in ancestors:
            if a["name"].lower() in office_parents and name.lower() in shell_children:
                suspicious_patterns.append(
                    f"办公软件 {a['name']} 启动了命令行 {name}——疑似宏病毒/钓鱼文档执行"
                )
            if a["name"].lower() in ("svchost.exe", "services.exe") and len(children) > 10:
                suspicious_patterns.append(
                    f"{name} 作为服务子进程创建了大量子进程（{len(children)} 个）"
                )

        return {
            "pid": pid,
            "name": name,
            "exe": exe,
            "ancestors": ancestors,
            "children_count": len(children),
            "children_sample": children[:10],
            "suspicious": suspicious_patterns,
        }
    except psutil.NoSuchProcess:
        return {"pid": pid, "error": "进程已不存在"}
    except psutil.AccessDenied:
        return {"pid": pid, "error": "权限不足"}


@register(
    "network_profile",
    "分析进程的网络连接画像",
    {
        "type": "object",
        "properties": {
            "pid": {"type": "integer", "description": "目标进程 PID"},
        },
        "required": ["pid"],
    },
)
def network_profile(pid: int | None = None) -> dict:
    """分析进程的所有网络连接。

    pid=None 时分析系统级网络画像。
    """
    connections: list[dict] = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if pid is not None and conn.pid != pid:
                continue
            if conn.status != "ESTABLISHED":
                continue
            raddr = conn.raddr.ip if conn.raddr else ""
            rport = conn.raddr.port if conn.raddr else 0
            connections.append({
                "pid": conn.pid,
                "local_port": conn.lport,
                "remote": f"{raddr}:{rport}",
                "remote_ip": raddr,
                "remote_port": rport,
                "is_common": rport in (80, 443, 53, 853, 22, 993, 995, 8080, 8443),
            })
    except (psutil.AccessDenied, Exception):
        pass

    # 聚合统计
    unique_ips = len(set(c["remote_ip"] for c in connections if c["remote_ip"]))
    suspicious_count = sum(
        1 for c in connections
        if c["remote_port"] not in (80, 443, 53, 853) and c["remote_port"] not in (0,)
    )

    return {
        "pid": pid or "system",
        "connection_count": len(connections),
        "unique_ips": unique_ips,
        "suspicious_connections": suspicious_count,
        "connections": connections[:20],
        "risk_assessment": (
            "high" if suspicious_count > 10 or unique_ips > 20
            else "medium" if suspicious_count > 5
            else "low"
        ),
    }


@register(
    "file_hash",
    "计算文件 SHA256 哈希，用于威胁情报查询",
    {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "文件路径"},
        },
        "required": ["path"],
    },
)
def file_hash(path: str) -> dict:
    """计算文件 SHA256，可用于 VirusTotal / MalwareBazaar 查询。"""
    p = Path(path)
    if not p.exists():
        return {"sha256": None, "error": "文件不存在"}
    if not p.is_file():
        return {"sha256": None, "error": "不是文件"}

    try:
        sha = hashlib.sha256()
        # 只读前 10MB（大文件保护）
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha.update(chunk)
                if f.tell() > 10_000_000:
                    break
        return {
            "sha256": sha.hexdigest(),
            "path": str(p),
            "size": p.stat().st_size,
            "truncated": p.stat().st_size > 10_000_000,
        }
    except Exception as exc:
        return {"sha256": None, "error": str(exc)}


@register(
    "entropy_check",
    "检测文件的熵值（高熵 = 可能加壳/加密/压缩）",
    {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "PE 文件路径"},
        },
        "required": ["path"],
    },
)
def entropy_check(path: str) -> dict:
    """香农熵检测。熵值 > 7.0 可能表示加壳/加密载荷。"""
    import math
    p = Path(path)
    if not p.exists():
        return {"entropy": None, "suspicious": False, "error": "文件不存在"}

    try:
        byte_counts = [0] * 256
        total = 0
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                for b in chunk:
                    byte_counts[b] += 1
                    total += 1
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p_val = count / total
                entropy -= p_val * math.log2(p_val)
        return {
            "entropy": round(entropy, 3),
            "suspicious": entropy > 7.2,
            "interpretation": (
                "文件熵值高，可能经过加壳、加密或压缩——恶意软件常用此技术躲避检测"
                if entropy > 7.2
                else "熵值正常"
            ),
        }
    except Exception as exc:
        return {"entropy": None, "suspicious": False, "error": str(exc)}


# ─── 批量工具调用 ───


def deep_inspect(pid: int, exe_path: str | None = None) -> dict:
    """对可疑进程执行全套深度检测（组合调用多个工具）。

    返回聚合结果供 Verifier 和 Reflector 使用。
    """
    results: dict[str, Any] = {
        "pid": pid,
        "exe_path": exe_path,
        "inspected_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }

    # 并行调用所有相关工具（ThreadPoolExecutor 节省 2-3 秒）
    from concurrent.futures import ThreadPoolExecutor, as_completed

    tasks = []
    if exe_path:
        tasks.append(("check_signature", check_signature, exe_path))
        tasks.append(("file_hash", file_hash, exe_path))
        tasks.append(("entropy_check", entropy_check, exe_path))
    tasks.append(("process_tree", process_tree, pid))
    tasks.append(("network_profile", network_profile, pid))

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(fn, arg): name for name, fn, arg in tasks}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as exc:
                results[name] = {"success": False, "error": str(exc)}

    # 综合风险评估
    risk_flags: list[str] = []
    sig = results.get("check_signature", {})
    entropy = results.get("entropy_check", {})
    tree = results.get("process_tree", {})
    net = results.get("network_profile", {})

    if sig.get("signed") is False:
        risk_flags.append("无有效数字签名")
    if entropy.get("suspicious"):
        risk_flags.append(f"高熵值({entropy.get('entropy')})——可能加壳")
    if tree.get("suspicious"):
        risk_flags.extend(tree["suspicious"])
    if net.get("risk_assessment") in ("high", "medium"):
        risk_flags.append(f"网络行为异常({net.get('risk_assessment')})")

    results["risk_flags"] = risk_flags
    results["risk_score"] = min(100, len(risk_flags) * 20)

    return results
