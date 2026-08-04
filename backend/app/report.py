"""检测报告导出 —— 生成 HTML 格式的安全检测报告。

用途：
1. 竞赛评审现场打印/展示
2. 用户下载留存
3. 含 MITRE ATT&CK 编号 + 威胁情报来源 + 检测时间

报告包含：
- 检测概览（时间/风险数/安全评分）
- 风险明细表（等级/名称/ATT&CK/详情/建议）
- 验证统计（确认/证伪/不确定）
- 系统信息
"""

from __future__ import annotations

import datetime
import json
from typing import Optional

REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>OpenGuardian 安全检测报告</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif;
    background: #000; color: #e0e0e0; padding: 32px;
  }}
  .report {{ max-width: 900px; margin: 0 auto; }}
  h1 {{
    font-family: "Courier New", monospace; font-size: 28px; color: #76b900;
    border-bottom: 2px solid #76b900; padding-bottom: 12px; margin-bottom: 8px;
  }}
  .meta {{ color: #757575; font-size: 12px; margin-bottom: 28px; }}
  .summary {{
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px;
    margin-bottom: 28px;
  }}
  .sum-card {{
    background: #0d0d0d; border: 1px solid #2a2a2a;
    padding: 16px; text-align: center;
  }}
  .sum-val {{ font-family: "Courier New", monospace; font-size: 32px; font-weight: 800; color: #76b900; }}
  .sum-lbl {{ font-size: 10px; color: #757575; letter-spacing: 1px; margin-top: 6px; }}
  .score-val {{ color: {score_color}; }}
  table {{
    width: 100%; border-collapse: collapse; font-size: 12px;
    margin-bottom: 20px;
  }}
  th {{
    text-align: left; padding: 10px 12px;
    font-family: "Courier New", monospace; font-size: 10px;
    color: #757575; letter-spacing: 1px; text-transform: uppercase;
    border-bottom: 1px solid #2a2a2a;
    background: #0a0a0a;
  }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #1a1a1a; }}
  tr:hover td {{ background: rgba(118,185,0,0.04); }}
  .badge {{
    display: inline-block; padding: 2px 8px;
    border-radius: 2px; font-family: "Courier New", monospace;
    font-size: 10px; font-weight: 700;
  }}
  .badge-crit {{ color: #e52020; border: 1px solid #e52020; background: rgba(229,32,32,0.1); }}
  .badge-high {{ color: #df6500; border: 1px solid #df6500; background: rgba(223,101,0,0.1); }}
  .badge-med  {{ color: #ef9100; border: 1px solid #ef9100; background: rgba(239,145,0,0.1); }}
  .badge-low  {{ color: #76b900; border: 1px solid #3f8500; background: rgba(63,133,0,0.1); }}
  .attk {{
    font-family: "Courier New", monospace; font-size: 10px; color: #76b900;
    background: rgba(118,185,0,0.08); border: 1px solid rgba(118,185,0,0.3);
    padding: 1px 6px; border-radius: 2px; white-space: nowrap;
  }}
  .section-title {{
    font-family: "Courier New", monospace; font-size: 14px; font-weight: 800;
    color: #a7a7a7; letter-spacing: 1px;
    margin: 24px 0 12px; padding-bottom: 6px; border-bottom: 1px solid #1f1f1f;
  }}
  .footer {{
    margin-top: 40px; padding-top: 16px; border-top: 1px solid #2a2a2a;
    color: #555; font-size: 10px; text-align: center;
  }}
</style>
</head>
<body>
<div class="report">
  <h1>OpenGuardian</h1>
  <div class="meta">
    检测时间：{detect_time}<br>
    版本：{version} &nbsp;|&nbsp; {risk_count} 项风险 &nbsp;|&nbsp; 安全评分 {security_score}/100
  </div>

  <div class="summary">
    <div class="sum-card">
      <div class="sum-val">{risk_count}</div>
      <div class="sum-lbl">风险项</div>
    </div>
    <div class="sum-card">
      <div class="sum-val" style="color:#e52020">{critical_count}</div>
      <div class="sum-lbl">高危</div>
    </div>
    <div class="sum-card">
      <div class="sum-val">{confirmed_count}</div>
      <div class="sum-lbl">已确认</div>
    </div>
    <div class="sum-card">
      <div class="sum-val score-val">{security_score}</div>
      <div class="sum-lbl">安全评分</div>
    </div>
  </div>

  <div class="section-title">风险明细</div>
  <table>
    <thead><tr>
      <th>等级</th><th>名称</th><th>ATT&CK</th><th>详情</th><th>处置建议</th>
    </tr></thead>
    <tbody>
      {risk_rows}
    </tbody>
  </table>

  <div class="section-title">验证统计</div>
  <table>
    <thead><tr><th>项目</th><th>数值</th></tr></thead>
    <tbody>
      <tr><td>总风险（原始）</td><td>{total_raw}</td></tr>
      <tr><td>已确认</td><td>{confirmed_count}</td></tr>
      <tr><td>已证伪（误报）</td><td>{refuted_count}</td></tr>
      <tr><td>不确定</td><td>{uncertain_count}</td></tr>
      <tr><td>AI 提供商</td><td>{llm_provider}</td></tr>
      <tr><td>检测引擎</td><td>8 模块并行 + Verifier + Reflector + Triage</td></tr>
    </tbody>
  </table>

  <div class="footer">
    OpenGuardian — AI 驱动的个人数字安全防护平台<br>
    温州科技职业学院 · 数智技术学院
  </div>
</div>
</body>
</html>
"""


def generate_html_report(
    risks: list[dict],
    security_score: int = 0,
    verified: Optional[dict] = None,
    total_raw: int = 0,
    version: str = "0.7.0",
    llm_provider: str = "DeepSeek",
) -> str:
    """生成 HTML 检测报告。

    Args:
        risks: [{"name","level","item_type","detail","suggestion","attack_tech"}]
        security_score: 0-100
        verified: {"confirmed": N, "refuted": N, "uncertain": N}
        total_raw: 原始风险数
    """
    verified = verified or {}
    detect_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk_count = len(risks)
    critical_count = sum(1 for r in risks if r.get("level") in ("critical", "高危"))
    confirmed_count = verified.get("confirmed", risk_count)
    refuted_count = verified.get("refuted", 0)
    uncertain_count = verified.get("uncertain", 0)

    # 评分颜色
    if security_score >= 80:
        score_color = "#76b900"
    elif security_score >= 50:
        score_color = "#df6500"
    else:
        score_color = "#e52020"

    # 风险行
    level_map = {
        "critical": ("crit", "CRITICAL"),
        "high": ("high", "HIGH"),
        "medium": ("med", "MEDIUM"),
        "low": ("low", "LOW"),
    }
    risk_rows: list[str] = []
    for r in risks:
        lv = r.get("level", "low")
        badge_cls, badge_txt = level_map.get(lv, ("low", lv.upper()))
        attack_tech = r.get("attack_tech", "")
        atk_html = f'<span class="attk">{attack_tech}</span>' if attack_tech else ""
        risk_rows.append(
            f'<tr>'
            f'<td><span class="badge badge-{badge_cls}">{badge_txt}</span></td>'
            f'<td>{r.get("name", "")}</td>'
            f'<td>{atk_html}</td>'
            f'<td>{r.get("detail", "")}</td>'
            f'<td>{r.get("suggestion", "")}</td>'
            f'</tr>'
        )

    return REPORT_TEMPLATE.format(
        detect_time=detect_time,
        version=version,
        risk_count=risk_count,
        critical_count=critical_count,
        security_score=security_score,
        score_color=score_color,
        total_raw=total_raw or risk_count,
        confirmed_count=confirmed_count,
        refuted_count=refuted_count,
        uncertain_count=uncertain_count,
        llm_provider=llm_provider,
        risk_rows="\n".join(risk_rows),
    )
