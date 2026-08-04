"""SARIF v2.1.0 报告生成器 —— GitHub Code Scanning 兼容。

SARIF (Static Analysis Results Interchange Format) 是微软/OASIS 制定的
安全检测结果交换标准。生成的 .sarif 文件可直接导入 GitHub Code Scanning。

参考: Vercel DeepSec (6528⭐) 的 SARIF 导出
"""

from __future__ import annotations

import datetime
import json
from typing import Optional

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# 风险等级 → SARIF level 映射
LEVEL_MAP = {
    "critical": "error",
    "high": "warning",
    "medium": "note",
    "low": "none",
}


def generate_sarif(
    risks: list[dict],
    security_score: int = 0,
    version: str = "0.7.0",
    tool_name: str = "OpenGuardian",
) -> dict:
    """生成 SARIF v2.1.0 格式的检测报告。

    Args:
        risks: [{"name","level","item_type","detail","suggestion","attack_tech"}]
        security_score: 0-100
    """
    detect_time = datetime.datetime.utcnow().isoformat() + "Z"

    results = []
    for i, r in enumerate(risks):
        lv = r.get("level", "low")
        name = r.get("name", "")
        detail = r.get("detail", "")
        suggestion = r.get("suggestion", "")
        attack_tech = r.get("attack_tech", "")
        item_type = r.get("item_type", "")

        # 构建增强的 message（含 ATT&CK + 建议）
        message_parts = [f"**{name}**"]
        if detail:
            message_parts.append(detail)
        if attack_tech:
            message_parts.append(f"ATT&CK: `{attack_tech}`")
        if suggestion:
            message_parts.append(f"→ {suggestion}")

        # 虚拟位置（桌面安全扫描无文件位置，用检测类型代替）
        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": f"openguardian://detect/{item_type}"},
                "region": {"startLine": i + 1},
            }
        }

        results.append({
            "ruleId": f"OG-{item_type.upper()[:20]}",
            "ruleIndex": min(i, 99),
            "level": LEVEL_MAP.get(lv, "none"),
            "message": {
                "text": "\n".join(message_parts),
                "markdown": "\n\n".join(message_parts),
            },
            "locations": [location],
            "properties": {
                "risk_name": name,
                "risk_type": item_type,
                "attack_technique": attack_tech,
                "suggestion": suggestion,
                "security_score": security_score,
            },
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": version,
                    "informationUri": "https://github.com/openguardian",
                    "rules": [
                        {
                            "id": f"OG-{r.get('item_type','UNKNOWN').upper()[:20]}",
                            "shortDescription": {"text": r.get("name", "")},
                            "fullDescription": {"text": r.get("detail", "")},
                            "help": {"text": r.get("suggestion", "")},
                            "properties": {
                                "security-severity": _severity_to_score(r.get("level", "low")),
                            },
                        }
                        for r in risks
                    ],
                    "properties": {
                        "total_risks": len(risks),
                        "security_score": security_score,
                        "detect_time": detect_time,
                    },
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": detect_time,
            }],
        }],
    }


def _severity_to_score(level: str) -> float:
    """GitHub Code Scanning severity score (0-10)."""
    return {
        "critical": 9.5,
        "high": 7.5,
        "medium": 5.0,
        "low": 2.5,
    }.get(level, 1.0)


def export_sarif_string(
    risks: list[dict],
    security_score: int = 0,
    version: str = "0.7.0",
    indent: int = 2,
) -> str:
    """导出 SARIF JSON 字符串。"""
    return json.dumps(
        generate_sarif(risks, security_score, version),
        ensure_ascii=False,
        indent=indent,
    )
