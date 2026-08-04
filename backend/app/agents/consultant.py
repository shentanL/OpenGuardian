"""交互 Agent（Consultant）：意图识别 + 多 Agent 编排 + 通俗化回复。

这是 OpenGuardian 的"大脑"：
1. 接收用户消息 → LLM 意图识别（结构化 JSON）
2. 按意图调度对应 Agent（通过消息总线）
3. 把检测/分析结果用 LLM 通俗化，或直接生成咨询回复
4. LLM 不可用时降级为关键词规则
"""
from __future__ import annotations

import logging
from typing import Optional

from ..agents.verifier import Verdict
from ..async_util import run_async
from ..bus import MessageBus
from ..llm.client import get_llm_client
from ..prompts import (
    CONSULT_SYSTEM,
    CONSULT_STREAM,
    FALLBACK_AI_RETRY,
    FALLBACK_AI_TIMEOUT,
    FALLBACK_AI_UNAVAILABLE,
    FALLBACK_WELCOME,
    INTENT_CLASSIFY,
)
from ..schemas import (
    AgentResult,
    AgentTask,
    ChatResponse,
    Intent,
    RiskItem,
    RiskLevel,
)
from .base import BaseAgent

logger = logging.getLogger(__name__)

# 关键词降级规则（LLM 不可用时）。顺序敏感：高特异性意图在前。
KEYWORD_RULES: list[tuple[Intent, list[str]]] = [
    # 疑问句式优先：咨询类问题不能被检测词（木马/病毒/进程）抢走
    (Intent.CONSULT, ["什么是", "啥是", "什么叫", "解释一下", "介绍一下", "介绍下", "是什么", "有哪些", "怎么办", "如何防范", "怎么防范"]),
    (Intent.EXECUTE, ["结束", "关闭进程", "杀掉", "终止", "干掉", "退出进程"]),
    (Intent.DETECT, ["检测", "扫描", "查一下", "查杀", "体检", "风险", "木马", "病毒", "进程", "安全吗"]),
    (Intent.ASSET, ["密码", "账号安全", "隐私", "泄露", "弱密码", "强密码"]),
    (Intent.EDUCATE, ["科普", "讲解", "讲讲", "钓鱼", "诈骗", "勒索", "科普一下", "教教我"]),
]

# 可科普的教育话题（供 educator 使用）
EDU_TOPICS = [
    "钓鱼邮件", "假冒网站", "勒索病毒", "账号泄露", "免费WiFi",
    "刷单", "杀猪盘", "校园贷", "游戏账号交易", "AI换脸", "演唱会门票",
    "冒充公检法", "冒充客服", "退款", "短信钓鱼", "验证码",
    "共享屏幕", "兼职打字", "培训贷", "二手交易", "U盘", "充电桩",
    "APP权限", "免密支付", "代考", "路由器", "隐私照片", "代购",
    "陌生领导", "WiFi探针",
]


class ConsultantAgent(BaseAgent):
    name = "consult"
    description = "交互中枢：意图识别、任务编排、通俗化回复"

    def __init__(self, bus: MessageBus) -> None:
        self.bus = bus
        self.llm = get_llm_client()

    # ---- 主入口 ----
    def handle(self, task: AgentTask) -> AgentResult:
        # Consultant 不走总线分发，直接编排
        user_input = task.user_input
        intent, params = self._classify(user_input)
        logger.info("Intent classified: %s (input=%r)", intent.value, user_input[:50])

        if intent == Intent.CONSULT:
            reply = self._handle_consult(user_input, context=task.params.get("context", ""))
            return AgentResult(agent=self.name, success=True, message=reply, data={"intent": intent.value})

        if intent == Intent.DETECT:
            return self._handle_detect(user_input)

        if intent == Intent.EXECUTE:
            return self._handle_execute(user_input)

        if intent == Intent.ASSET:
            return self._handle_asset(user_input)

        # educate
        return self._handle_educate(user_input)

    # ---- 意图识别 ----
    def _classify(self, text: str) -> tuple[Intent, dict]:
        # 1) 关键词规则（快路径，确定性，毫秒级）
        rule_intent = self._keyword_classify(text)
        if rule_intent is not None:
            return rule_intent, {}

        # 2) LLM（慢路径，只兜底模糊表达）
        if self.llm.available:
            try:
                data = run_async(
                    self.llm.chat_json(
                        [{"role": "user", "content": text}],
                        system=INTENT_CLASSIFY,
                        fallback={},
                    ),
                    timeout=15.0,
                )
                intent_str = data.get("intent", "")
                try:
                    intent = Intent(intent_str)
                    params = data.get("params") or {}
                    # 规则叠加：LLM 判为 educate 但无具体话题且是"什么是X"句式 → 转 consult
                    if (
                        intent == Intent.EDUCATE
                        and not any(t in text for t in EDU_TOPICS)
                        and any(k in text for k in ("什么是", "是什么", "啥是", "啥叫"))
                    ):
                        return Intent.CONSULT, {}
                    return intent, params
                except ValueError:
                    logger.warning("Unknown intent from LLM: %r", intent_str)
            except Exception as exc:  # noqa: BLE001
                logger.warning("LLM classify failed: %s", exc)

        return Intent.CONSULT, {}

    @staticmethod
    def _keyword_classify(text: str) -> Intent | None:
        """关键词规则分类；未命中返回 None（交给 LLM 或默认 consult）。"""
        # 0) 疑问句式最优先：咨询类问题不能被教育话题/检测词抢走
        if any(k in text for k in ("什么是", "是什么", "啥是", "啥叫", "什么叫")):
            return Intent.CONSULT
        # 1) 具体教育话题精确匹配
        for topic in EDU_TOPICS:
            if topic in text:
                return Intent.EDUCATE
        # 2) 通用关键词（顺序敏感：高特异性意图在前）
        for intent, keywords in KEYWORD_RULES:
            if any(k in text for k in keywords):
                return intent
        return None

    # ---- 各意图处理 ----
    def _handle_consult(self, user_input: str, context: str = "") -> str:
        # 咨询类：直接 LLM 对话（降级给固定引导）
        reply = self._llm_chat(user_input, context=context)
        if reply:
            return reply
        return FALLBACK_WELCOME

    def _handle_detect(self, user_input: str) -> AgentResult:
        """检测流程（增强版）：Detector → Verifier → Reflector → Triage。

        1. Detector 扫描 → 原始风险列表
        2. Verifier 对抗性验证 → 确认/误报/不确定
        3. 对确认的可疑项执行工具调用链（签名/进程树/网络/熵值）
        4. Reflector 反思 → 补充边界信号 + 历史对比
        5. Triage 分级 → 自动处置 / 建议 / 证据展示 / 仅报告
        """
        from ..agents.tools import deep_inspect
        from ..agents.verifier import get_verifier
        from ..agents.reflector import get_reflector
        from ..memory import get_memory
        from ..triage import get_triage, ActionTier
        from ..db import get_db

        memory = get_memory()
        verifier = get_verifier()
        db = get_db()

        # ── 1. Detector 扫描 ──
        result = self.bus.dispatch(
            AgentTask(intent=Intent.DETECT, params={"scope": "all"}, user_input=user_input)
        )
        # 同时采集资产数据
        asset_result = self.bus.dispatch(
            AgentTask(intent=Intent.ASSET, params={"action": "scan"}, user_input=user_input)
        )
        if asset_result.risks:
            result.risks = (result.risks or []) + asset_result.risks
            if asset_result.message and "未发现" not in asset_result.message:
                result.message += "\n\n" + asset_result.message

        # ── 1.5 CVE 漏洞扫描（检测已安装软件的已知漏洞）──
        try:
            from .cve_check import check_installed_software, generate_cve_report
            cve_hits = check_installed_software()
            if cve_hits:
                cve_report = generate_cve_report()
                result.message += cve_report
                for h in cve_hits:
                    from ..schemas import RiskItem, RiskLevel
                    level = {"critical": RiskLevel.CRITICAL, "high": RiskLevel.HIGH,
                             "medium": RiskLevel.MEDIUM}.get(h.severity, RiskLevel.LOW)
                    result.risks = (result.risks or []) + [RiskItem(
                        item_type="vuln_cve", name=h.product_name,
                        detail=f"{h.cve} — {h.description}",
                        level=level, suggestion=h.fix,
                    )]
        except Exception:
            pass

        raw_risks = result.risks
        if not raw_risks:
            # 无风险，但仍做反思确认
            reflector = get_reflector(db)
            refl = reflector.reflect(
                scanned_modules=["process", "network", "resource", "vuln",
                                 "defender", "updates", "services"],
                risks=[],
            )
            return AgentResult(
                agent=self.name,
                success=True,
                message=f"🛡️ 检测完成，未发现明显风险。{refl.quality_note}",
                risks=[],
                data={"intent": Intent.DETECT.value, "reflect": {
                    "coverage": refl.coverage_score,
                    "borderline": refl.borderline_signals,
                }},
            )

        # ── 2. Verifier 对抗性验证 ──
        whitelist = memory.db.get_whitelist() if memory.db else set()
        verified_risks = verifier.verify(raw_risks, whitelist)

        # ── 2.5 行为异常检测 ──
        try:
            from .behavioral import get_behavioral_engine
            import psutil as _ps, time as _t
            bengine = get_behavioral_engine()
            ts = __import__('time').strftime('%Y-%m-%dT%H:%M:%S')
            for proc in _ps.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent',
                                          'connections']):
                try:
                    pname = proc.info['name'] or ''
                    pcpu = proc.info['cpu_percent'] or 0.0
                    pmem = proc.info['memory_percent'] or 0.0
                    pchildren = len(proc.children())
                    pports = set()
                    try:
                        for c in proc.connections():
                            if c.lport:
                                pports.add(c.lport)
                    except Exception:
                        pass
                    pparent = proc.parent().name() if proc.parent() else ''
                    bengine.update_baseline(pname, pcpu, pmem, pchildren, pports, pparent, ts)
                    anomaly = bengine.check(pname, pcpu, pmem, pchildren, pports, pparent)
                    if anomaly and anomaly['severity'] in ('critical', 'high'):
                        from ..schemas import RiskItem, RiskLevel
                        lv = RiskLevel.CRITICAL if anomaly['severity'] == 'critical' else RiskLevel.HIGH
                        result.risks.append(RiskItem(
                            item_type='process', name=f"{pname} (行为异常)",
                            detail="行为基线偏离：" + '; '.join(anomaly['flags']),
                            level=lv,
                            suggestion=f"该进程行为模式偏离正常基线（得分 {anomaly['anomaly_score']}），建议立即调查。",
                            pid=proc.info['pid'],
                        ))
                except (_ps.NoSuchProcess, _ps.AccessDenied):
                    continue
        except Exception:
            pass

        # ── 3. 工具调用链（仅对 CONFIRMED + UNCERTAIN 项深度检测）──
        triage_engine = get_triage()
        triaged: list = []
        confirmed_risks: list = []
        refuted_risks: list = []
        uncertain_risks: list = []

        for vr in verified_risks:
            inspect = {}
            if vr.verdict in (Verdict.CONFIRMED, Verdict.UNCERTAIN) and vr.risk.pid:
                try:
                    inspect = deep_inspect(vr.risk.pid)
                except Exception:
                    pass

            # 跳过被 Verifier 明确证伪的误报项
            if vr.verdict == Verdict.REFUTED:
                refuted_risks.append(vr.risk)
                continue

            triage_result = triage_engine.evaluate(vr, inspect)
            triaged.append((vr, triage_result, inspect))

            # 按处置等级分组
            if triage_result.tier in (ActionTier.AUTO, ActionTier.SUGGEST):
                confirmed_risks.append(vr.risk)
            elif triage_result.tier == ActionTier.EVIDENCE:
                uncertain_risks.append(vr.risk)
            else:
                refuted_risks.append(vr.risk)

            # 记录进程指纹
            if vr.risk.pid:
                try:
                    import psutil
                    proc = psutil.Process(vr.risk.pid)
                    exe = proc.exe() if hasattr(proc, "exe") else ""
                    sig = inspect.get("check_signature", {})
                    verdict = "safe" if triage_result.tier == ActionTier.REPORT else "suspicious"
                    memory.record_fingerprint(
                        proc.name(), exe,
                        verdict=verdict,
                        signed_by=sig.get("signer", ""),
                    )
                except Exception:
                    pass

        # ── 4. Reflector 反思 ──
        reflector = get_reflector(db)
        scanned = ["process", "network", "resource", "vuln",
                    "defender", "updates", "services"]
        refl = reflector.reflect(scanned, confirmed_risks + uncertain_risks)
        all_risks = confirmed_risks + uncertain_risks + refl.missed_risks

        # ── 5. 保存情节记忆 ──
        try:
            memory.save_episode({
                "detected_at": __import__('time').strftime("%Y-%m-%dT%H:%M:%S"),
                "raw_count": len(raw_risks),
                "confirmed": len(confirmed_risks),
                "refuted": len(refuted_risks),
                "uncertain": len(uncertain_risks),
                "borderline": len(refl.borderline_signals),
                "risks": [r.model_dump() for r in all_risks],
            })
        except Exception:
            pass

        # ── 6. 生成通俗报告 ──
        # 附加 CVE 扫描报告
        try:
            from .cve_check import generate_cve_report
            cve = generate_cve_report()
            if cve:
                result.message += cve
        except Exception:
            pass
        # 附加攻击链分析
        try:
            from .attack_chain import generate_attack_narrative
            chain = generate_attack_narrative(
                [r.model_dump() for r in (confirmed_risks + uncertain_risks)]
            )
            if chain:
                result.message += chain
        except Exception:
            pass

        reply = self._humanize_verified_risks(
            triaged,
            refuted_risks,
            refl,
            total_raw=len(raw_risks),
        )
        return AgentResult(
            agent=self.name,
            success=True,
            message=reply,
            risks=all_risks,
            data={
                "intent": Intent.DETECT.value,
                "verified": {
                    "confirmed": len(confirmed_risks),
                    "refuted": len(refuted_risks),
                    "uncertain": len(uncertain_risks),
                },
                "reflect": {
                    "coverage": refl.coverage_score,
                    "quality": refl.quality_note,
                },
            },
        )

    def _handle_execute(self, user_input: str) -> AgentResult:
        # 从自然语言提取 PID：支持 "结束 1234" / "PID 1234" 等
        import re

        pid = self._extract_pid(user_input)
        if pid is None:
            return AgentResult(
                agent=self.name,
                success=True,
                message="你想结束哪个进程？如果不确定的话，先让我「检测一下电脑」——我会把可疑进程列出来，每个都有编号，然后告诉我要结束哪个就行。",
                data={"intent": Intent.EXECUTE.value, "needs_scan": True},
            )
        # 需要用户确认：返回 execute_hint，由前端二次确认后调 /api/execute
        return AgentResult(
            agent=self.name,
            success=True,
            message=f"确认要结束进程（PID {pid}）吗？该操作会立即终止此程序。",
            data={
                "intent": Intent.EXECUTE.value,
                "needs_confirmation": True,
                "execute_hint": {"pid": pid, "action": "terminate"},
            },
        )

    def _handle_asset(self, user_input: str) -> AgentResult:
        import re

        # 提取密码：形如 "检查密码 xxx" / "密码是 xxx" / "密码 xxx"
        m = re.search(r"密码\s*[是为：:]?\s*(\S+)", user_input)
        params = {"action": "password"}
        if m:
            params["password"] = m.group(1).strip()
        elif "习惯" in user_input or "做法" in user_input:
            params = {"action": "habit", "text": user_input}
        else:
            return AgentResult(
                agent=self.name,
                success=True,
                message="试试这样跟我说：\n"
                        "「检查密码 123456」—— 我帮你看看这个密码够不够强\n"
                        "或者描述一下你的密码习惯，我帮你分析有没有风险～",
                data={"intent": Intent.ASSET.value},
            )

        result = self.bus.dispatch(AgentTask(intent=Intent.ASSET, params=params, user_input=user_input))
        risks = result.risks
        lines = [result.message or ""]
        for r in risks:
            lines.append(f"· {r.name}（{r.level.value}）：{r.detail}")
            if r.suggestion:
                lines.append(f"  💡 {r.suggestion}")
        return AgentResult(
            agent=self.name,
            success=True,
            message="\n".join(lines),
            risks=risks,
            data={"intent": Intent.ASSET.value},
        )

    def _handle_educate(self, user_input: str) -> AgentResult:
        topic = next((t for t in EDU_TOPICS if t in user_input), "")
        result = self.bus.dispatch(
            AgentTask(intent=Intent.EDUCATE, params={"topic": topic}, user_input=user_input)
        )
        return AgentResult(
            agent=self.name,
            success=True,
            message=result.message,
            data={"intent": Intent.EDUCATE.value},
        )

    # ---- 工具方法 ----
    def _llm_chat(self, user_input: str, context: str = "") -> Optional[str]:
        msg = user_input
        if context:
            msg = f"{context}\n\n{msg}"

        try:
            return run_async(
                self.llm.chat(
                    [{"role": "user", "content": msg}],
                    system=CONSULT_SYSTEM,
                    temperature=0.7,
                ),
                timeout=30.0,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("consult LLM chat failed: %s", exc)
            return None

    def _humanize_risks(self, risks: list[RiskItem], summary: str) -> str:
        """把风险清单转成通俗报告。"""
        if not risks:
            return f"检测完毕～ {summary}，电脑状态不错 👍\n\n（说明一下：这是轻量级检测，代替不了专业的杀毒软件哈）"

        lines = [f"检测结果出来了——{summary}：\n"]
        for r in risks:
            icon = {
                RiskLevel.CRITICAL: "🔴",
                RiskLevel.HIGH: "🟠",
                RiskLevel.MEDIUM: "🟡",
                RiskLevel.LOW: "🟢",
            }.get(r.level, "⚪")
            lines.append(f"{icon} {r.name}")
            lines.append(f"   {r.detail}")
            if r.suggestion:
                lines.append(f"   → {r.suggestion}")
            if r.pid:
                lines.append(f"   回复「结束进程 {r.pid}」我来处理")
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _humanize_verified_risks(
        triaged: list,
        refuted_risks: list,
        refl,  # ReflectReport
        total_raw: int,
    ) -> str:
        """生成自然对话式的检测报告（不用模板腔）。"""
        from ..triage import ActionTier

        if not triaged:
            # 干净的结果 —— 轻松、鼓励的语气
            msg = f"检测完毕～ 看了 {total_raw} 项指标，没发现什么值得担心的。"
            if refuted_risks:
                names = [r.name for r in refuted_risks[:3]]
                msg += f" 有几个看起来像风险的程序（{', '.join(names)}），但我们验证过了，是安全的，帮你放过了。"
            if hasattr(refl, 'coverage_score') and refl.coverage_score < 1.0:
                msg += f" 不过有 {len(getattr(refl, 'modules_skipped', []))} 个检测模块没跑到，可能跟权限有关。"
            return msg

        # 按等级分组
        auto_items, suggest_items, evidence_items, report_items = [], [], [], []
        for vr, triage_result, inspect in triaged:
            entry = (vr, triage_result, inspect)
            if triage_result.tier == ActionTier.AUTO:
                auto_items.append(entry)
            elif triage_result.tier == ActionTier.SUGGEST:
                suggest_items.append(entry)
            elif triage_result.tier == ActionTier.EVIDENCE:
                evidence_items.append(entry)
            else:
                report_items.append(entry)

        total_confirmed = len(auto_items) + len(suggest_items)
        parts = []

        # 开场 —— 用对话语气概括
        parts.append(
            f"检测完了。总共扫描了 {total_raw} 个指标，"
            f"确认有 {total_confirmed} 个问题值得处理"
            + (f"，另外 {len(refuted_risks)} 个看起来像风险但实际安全的已经帮你排除了" if refuted_risks else "")
            + "。"
        )

        # 高风险优先说
        if auto_items:
            names = [vr.risk.name for vr, _, _ in auto_items]
            parts.append(f"\n我直接帮你处理掉了 {', '.join(names)}——这几个基本可以确定是恶意程序，留着会有风险。")

        if suggest_items:
            parts.append("\n下面这几个建议你处理一下：")
            for vr, tr, _ in suggest_items:
                parts.append(f"\n🔸 {vr.risk.name}")
                parts.append(f"   {tr.suggested_action}")
                if vr.risk.pid:
                    parts.append(f"   回复「结束进程 {vr.risk.pid}」我来处理")

        if evidence_items:
            parts.append("\n还有几个我不太确定的，把证据列出来，你来判断：")
            for vr, tr, _ in evidence_items:
                parts.append(f"\n🔹 {vr.risk.name}")
                for ev in tr.evidence_chain[:2]:
                    parts.append(f"   {ev[:120]}")

        if report_items and not suggest_items and not evidence_items:
            names = [vr.risk.name for vr, _, _ in report_items[:3]]
            parts.append(f"\n剩下像 {', '.join(names)} 这些，风险很低，平时留意就好，不用特别处理。")

        # 边界信号 —— 预防性提醒
        if hasattr(refl, 'borderline_signals') and refl.borderline_signals:
            borderline = refl.borderline_signals
            if len(borderline) > 0:
                parts.append(f"\n对了，还有 {len(borderline)} 个指标虽然没到报警线，但也比较接近了。")
                for b in borderline[:2]:
                    parts.append(f"· {b.get('detail', '')[:100]}")

        # 历史对比
        if hasattr(refl, 'new_vs_last_scan') and refl.new_vs_last_scan:
            new_items = refl.new_vs_last_scan
            if new_items:
                parts.append(f"\n跟上次检测比，多了 {len(new_items)} 个新东西。最值得注意的是 {new_items[0]['name']}——上次没出现。")

        return "\n".join(parts)

    @staticmethod
    def _extract_pid(text: str) -> Optional[int]:
        import re

        # 匹配：PID 1234 / pid:1234 / 结束进程 1234 / 结束 1234
        patterns = [
            r"(?:pid|PID)[\s:：]*(\d+)",
            r"结束(?:进程)?[\s:：]*(\d+)",
            r"关闭(?:进程)?[\s:：]*(\d+)",
            r"终止[\s:：]*(\d+)",
        ]
        for pattern in patterns:
            m = re.search(pattern, text)
            if m:
                return int(m.group(1))
        return None
