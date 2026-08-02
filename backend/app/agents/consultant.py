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

from ..bus import MessageBus
from ..llm.client import get_llm_client
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

INTENT_SYSTEM_PROMPT = """你是 OpenGuardian 的意图识别器。根据用户消息，判断其意图，输出 JSON：
{"intent": "consult|detect|execute|asset|educate", "params": {}, "reason": "简短理由"}

意图规则：
- consult：询问安全知识、某个东西是否安全、怎么办（不涉及本机操作）
- detect：要求扫描/检测/查看电脑风险、进程、网络、杀毒
- execute：要求结束/关闭/杀掉某个进程
- asset：要求检查密码强度、账号安全、隐私
- educate：要求科普、讲解某个安全话题（钓鱼、病毒、诈骗等）
只输出 JSON。"""

# 关键词降级规则（LLM 不可用时）。顺序敏感：高特异性意图在前。
KEYWORD_RULES: list[tuple[Intent, list[str]]] = [
    (Intent.EXECUTE, ["结束", "关闭进程", "杀掉", "终止", "干掉", "退出进程"]),
    (Intent.DETECT, ["检测", "扫描", "查一下", "查杀", "体检", "风险", "木马", "病毒", "进程", "安全吗"]),
    (Intent.ASSET, ["密码", "账号安全", "隐私", "泄露", "弱密码", "强密码"]),
    (Intent.EDUCATE, ["科普", "讲解", "讲讲", "钓鱼", "诈骗", "勒索", "科普一下", "教教我"]),
]

# 可科普的教育话题（供 educator 使用）
EDU_TOPICS = [
    "钓鱼邮件", "假冒网站", "勒索病毒", "账号泄露", "免费WiFi",
    "刷单", "杀猪盘", "校园贷", "游戏账号交易", "AI换脸", "演唱会门票",
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
            reply = self._handle_consult(user_input)
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
            import asyncio

            async def _run() -> dict:
                return await self.llm.chat_json(
                    [{"role": "user", "content": text}],
                    system=INTENT_SYSTEM_PROMPT,
                    fallback={},
                )

            try:
                data = asyncio.run(_run())
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
        # 1) 具体教育话题精确匹配
        for topic in EDU_TOPICS:
            if topic in text:
                return Intent.EDUCATE
        # 2) 通用关键词（顺序敏感：高特异性意图在前）
        for intent, keywords in KEYWORD_RULES:
            if any(k in text for k in keywords):
                return intent
        # 3) "什么是X"类提问 → 咨询
        if any(k in text for k in ("什么是", "是什么", "啥是", "啥叫")):
            return Intent.CONSULT
        return None

    # ---- 各意图处理 ----
    def _handle_consult(self, user_input: str) -> str:
        # 咨询类：直接 LLM 对话（降级给固定引导）
        reply = self._llm_chat(user_input)
        if reply:
            return reply
        return (
            "👋 我是 OpenGuardian 安全助手。你可以：\n"
            "1. 问我安全知识，比如「什么是钓鱼邮件？」\n"
            "2. 让我检测电脑，比如「帮我检测一下电脑」\n"
            "3. 检查密码强度，比如「检查密码 123456 的强度」\n"
            "4. 学习安全案例，比如「讲讲勒索病毒」"
        )

    def _handle_detect(self, user_input: str) -> AgentResult:
        result = self.bus.dispatch(AgentTask(intent=Intent.DETECT, params={"scope": "all"}, user_input=user_input))
        risks = result.risks
        reply = self._humanize_risks(risks, result.message)
        return AgentResult(
            agent=self.name,
            success=True,
            message=reply,
            risks=risks,
            data={"intent": Intent.DETECT.value},
        )

    def _handle_execute(self, user_input: str) -> AgentResult:
        # 从自然语言提取 PID：支持 "结束 1234" / "PID 1234" 等
        import re

        pid = self._extract_pid(user_input)
        if pid is None:
            return AgentResult(
                agent=self.name,
                success=True,
                message="请告诉我要结束哪个进程。可以先让我检测电脑，我会列出可疑进程和它们的编号（PID），然后你说「结束进程 1234」即可。",
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
                message="📊 资产安全小助手\n\n"
                        "你可以这样用：\n"
                        "· 「检查密码 123456」→ 评估密码强度\n"
                        "· 描述你的密码使用习惯 → 我帮你分析风险",
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
    def _llm_chat(self, user_input: str) -> Optional[str]:
        import asyncio

        async def _run() -> Optional[str]:
            return await self.llm.chat(
                [{"role": "user", "content": user_input}],
                system=(
                    "你是 OpenGuardian——面向普通用户的个人数字安全助手。"
                    "回答要求：通俗易懂、不超过 200 字、给出可操作建议。"
                ),
                temperature=0.7,
            )

        try:
            return asyncio.run(_run())
        except Exception as exc:  # noqa: BLE001
            logger.warning("consult LLM chat failed: %s", exc)
            return None

    def _humanize_risks(self, risks: list[RiskItem], summary: str) -> str:
        """把风险清单转成通俗报告，末尾自动附术语解释。"""
        from ..kb.glossary import glossary_footer

        if not risks:
            return f"🛡️ {summary}，未发现明显风险，继续保持！\n\n（提示：本检测为轻量级，无法替代专业杀毒软件）"

        lines = [f"🛡️ {summary}：\n"]
        for r in risks:
            icon = {
                RiskLevel.CRITICAL: "🔴",
                RiskLevel.HIGH: "🟠",
                RiskLevel.MEDIUM: "🟡",
                RiskLevel.LOW: "🟢",
            }.get(r.level, "⚪")
            lines.append(f"{icon} {r.name}")
            lines.append(f"   详情：{r.detail}")
            if r.suggestion:
                lines.append(f"   💡 {r.suggestion}")
            if r.pid:
                lines.append(f"   🆔 PID：{r.pid}（回复「结束进程 {r.pid}」可处置）")
            lines.append("")
        report = "\n".join(lines)
        # 术语小课堂：把报告中的专业词自动翻译成大白话
        report += glossary_footer(report)
        return report

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
