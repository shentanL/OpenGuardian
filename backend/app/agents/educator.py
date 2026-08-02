"""教育 Agent：数字安全教育（案例库 + 对话式科普）。"""
from __future__ import annotations

from ..llm.client import get_llm_client
from ..schemas import AgentResult, AgentTask
from .base import BaseAgent

# 典型安全案例库（MVP 版）
CASES: dict[str, dict] = {
    "钓鱼邮件": {
        "scenario": "收到一封“您的账号存在异常，请点击链接立即验证”的邮件，落款是“客服中心”。",
        "explain": "这是典型的钓鱼邮件。骗子冒充官方客服，诱导你点击伪造链接，"
                   "在仿冒的登录页面输入账号密码，从而窃取你的信息。",
        "tips": [
            "看发件人：官方邮箱域名要仔细核对，如 @edu.cn 而非 @edu.cn.xyz",
            "不点链接：把鼠标悬停在链接上看真实地址，或用官网入口进入",
            "有疑问：直接打电话给官方客服核实，不要回复邮件",
        ],
    },
    "假冒网站": {
        "scenario": "搜索引擎搜到的“官网”实际上是长得一模一样的仿冒站点。",
        "explain": "假冒网站会复制真实网站的界面，域名只差一两个字母（如 1ogin 而非 login），"
                   "诱导你在上面输入账号密码或支付信息。",
        "tips": [
            "核对域名：认准地址栏的完整域名，注意拼写",
            "看 HTTPS：有锁形图标不代表安全，还要看证书归属",
            "收藏官网：把常用网站加入书签，从书签进入",
        ],
    },
    "勒索病毒": {
        "scenario": "电脑突然弹窗：所有文件已被加密，48 小时内支付比特币才能解锁。",
        "explain": "勒索病毒会加密你的文件并索要赎金。即使支付赎金，也不保证能恢复文件。",
        "tips": [
            "不要支付赎金：支付只会助长犯罪，且不一定解锁",
            "断网隔离：立即断开网络，防止病毒扩散到其他设备",
            "定期备份：重要文件用 3-2-1 备份（3 份副本、2 种介质、1 份离线）",
        ],
    },
    "账号泄露": {
        "scenario": "收到短信说你“在陌生设备登录”，但你并没有登录过。",
        "explain": "账号可能已泄露（数据泄露或撞库）。骗子拿到密码后会在各处尝试登录。",
        "tips": [
            "立即改密：修改密码并开启两步验证（2FA）",
            "检查登录记录：在官网查看最近的登录设备",
            "重要账号分级：邮箱、支付、社交等核心账号用不同强密码",
        ],
    },
    "免费WiFi": {
        "scenario": "在咖啡馆连了“Free-WiFi”，之后发现账号在别处被登录。",
        "explain": "公共 WiFi 可能被设置成钓鱼热点，流量经过骗子设备，"
                   "明文传输的账号密码会被截获。",
        "tips": [
            "不连陌生 WiFi：优先使用手机热点",
            "敏感操作用加密：登录网银/邮箱时确保地址是 HTTPS",
            "关闭自动连接：避免设备自动连上伪造热点",
        ],
    },
}


class EducatorAgent(BaseAgent):
    name = "educate"
    description = "数字安全教育：典型案例讲解与安全知识科普"

    def handle(self, task: AgentTask) -> AgentResult:
        topic = task.params.get("topic", "")
        case = CASES.get(topic)

        if case:
            tips_text = "\n".join(f"{i+1}. {t}" for i, t in enumerate(case["tips"]))
            reply = (
                f"📖 【{topic}】安全课堂\n\n"
                f"场景：{case['scenario']}\n\n"
                f"原理：{case['explain']}\n\n"
                f"防护建议：\n{tips_text}"
            )
        else:
            # 未命中案例库 → 尝试 LLM 讲解（失败则给通用指引）
            llm = get_llm_client()
            reply = llm and self._ask_llm(llm, topic) or self._generic(topic)

        return AgentResult(agent=self.name, success=True, message=reply, data={"topic": topic})

    def _ask_llm(self, llm, topic: str) -> str:
        import asyncio

        async def _run() -> str | None:
            return await llm.chat(
                [
                    {
                        "role": "user",
                        "content": (
                            f"请用通俗易懂的方式科普「{topic}」相关的数字安全知识，"
                            "包括：是什么、常见套路、如何防护。控制在 200 字以内。"
                        ),
                    }
                ],
                system="你是 OpenGuardian 的安全教育老师，面向普通用户，语言要通俗、有场景感。",
            )

        try:
            result = asyncio.run(_run())
            return result or self._generic(topic)
        except Exception:  # noqa: BLE001
            return self._generic(topic)

    @staticmethod
    def _generic(topic: str) -> str:
        return (
            f"📖 关于「{topic}」的安全课堂\n\n"
            "安全三原则：\n"
            "1. 不轻信：任何索要密码、验证码、转账的消息都要先核实\n"
            "2. 不乱点：陌生链接、附件、二维码先确认来源\n"
            "3. 不裸奔：重要账号开启两步验证，定期备份数据\n\n"
            "想深入了解某个话题（如钓鱼邮件、假冒网站、勒索病毒），直接告诉我即可。"
        )
