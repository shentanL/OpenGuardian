"""Slash 命令路由 —— 在对话中检测 /scan /fix /report 等精确指令。

借鉴: Unclecheng-li/DeepSec 的 Slash Command System
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from .schemas import AgentResult, Intent

logger = logging.getLogger(__name__)

# 命令路由表
COMMANDS: dict[str, dict] = {
    "/scan": {
        "intent": Intent.DETECT,
        "action": "full_scan",
        "desc": "全量安全检测",
    },
    "/check": {
        "intent": Intent.CREDENTIAL,
        "action": "credential_check",
        "desc": "凭据泄露检测 (/check email@domain.com)",
        "has_args": True,
    },
    "/fix": {
        "intent": Intent.EXECUTE,
        "action": "fix_risk",
        "desc": "一键修复 (/fix vuln_smb1)",
        "has_args": True,
    },
    "/report": {
        "intent": None,
        "action": "export_report",
        "desc": "导出检测报告",
    },
    "/help": {
        "intent": None,
        "action": "show_help",
        "desc": "显示命令列表",
    },
}


def parse_command(text: str) -> tuple[Optional[str], Optional[str], str]:
    """解析 /command args 格式。

    Returns:
        (command, args, raw_text) — 命令名、参数、移除命令后的原始文本
    """
    text = text.strip()
    if not text.startswith("/"):
        return None, None, text

    parts = text.split(maxsplit=1)
    cmd = parts[0].lower()
    args = parts[1].strip() if len(parts) > 1 else ""
    return cmd, args, args


def handle_command(user_input: str, consultant) -> Optional[AgentResult]:
    """处理 slash 命令。已路由则返回 AgentResult，否则返回 None。"""
    cmd, args, rest = parse_command(user_input)
    if not cmd:
        return None

    if cmd not in COMMANDS:
        return AgentResult(
            agent="slash",
            success=True,
            message=f"未知命令 `{cmd}`。输入 `/help` 查看可用命令。",
            data={"intent": "consult"},
        )

    entry = COMMANDS[cmd]

    # /help
    if entry["action"] == "show_help":
        lines = ["📋 **可用命令**\n"]
        for c, info in COMMANDS.items():
            lines.append(f"  `{c}` — {info['desc']}")
        return AgentResult(
            agent="slash",
            success=True,
            message="\n".join(lines),
            data={"intent": "consult"},
        )

    # /scan → 全量检测
    if entry["action"] == "full_scan":
        return consultant._handle_detect("全量安全检测")

    # /check → 凭据检测
    if entry["action"] == "credential_check":
        cred_input = args or rest
        if not cred_input or "@" not in cred_input:
            return AgentResult(
                agent="slash",
                success=True,
                message="用法: `/check email@domain.com` 或 `/check 13800138000`",
                data={"intent": "credential"},
            )
        return consultant._handle_credential(f"检查账号 {cred_input}")

    # /fix → 一键修复
    if entry["action"] == "fix_risk":
        item_type = args.strip()
        if not item_type:
            return AgentResult(
                agent="slash",
                success=True,
                message="用法: `/fix <风险类型>`，如 `/fix vuln_smb1`。",
                data={"intent": "consult"},
            )
        from .agents.fixer import execute_fix
        result = execute_fix(item_type)
        if result["ok"]:
            return AgentResult(
                agent="slash",
                success=True,
                message=f"✅ {result['desc']}\n{result.get('output', '')[:200]}",
                data={"intent": "fix"},
            )
        else:
            return AgentResult(
                agent="slash",
                success=True,
                message=f"❌ 修复失败: {result.get('error', '未知错误')}\n{result.get('hint', '')}",
                data={"intent": "fix"},
            )

    # /report → 报告导出
    if entry["action"] == "export_report":
        fmt = args.strip() or "html"
        return AgentResult(
            agent="slash",
            success=True,
            message=f"📄 正在生成{fmt.upper()}格式报告… 请通过 API 端点 `/api/report?format={fmt}` 获取文件。",
            data={"intent": "report", "format": fmt},
        )

    return None
