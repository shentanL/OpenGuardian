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
    "刷单返利诈骗": {
        "scenario": "你在宿舍刷手机，看到“点赞日赚300”广告，对方发来链接说刷单返现，前两单真的收到钱，第三单却要你垫付5000。",
        "explain": "骗子用小利引诱，先让你尝到甜头，最后骗走大额本金后拉黑。",
        "tips": ["拒绝任何需垫付资金的兼职", "不点击陌生链接或下载不明APP", "记住：轻松赚钱往往是陷阱"],
    },
    "杀猪盘（网恋诈骗）": {
        "scenario": "你在交友软件认识温柔体贴的TA，每天嘘寒问暖，感情升温后对方说在投资平台有漏洞，带你赚钱。",
        "explain": "骗子伪造完美人设，长期培养感情（养猪），最后诱导投资或借钱（杀猪）卷款消失。",
        "tips": ["网恋不提钱，提及立即警惕", "绝不向未见过面的网友转账", "核实对方身份，不轻信完美人设"],
    },
    "校园贷陷阱": {
        "scenario": "你想买新款手机却没钱，看到“零门槛、秒到账”贷款广告，签了合同，结果利息如滚雪球，还被威胁催收。",
        "explain": "非法借贷利用高利率、违约金和暴力催收，让借款金额短时间内翻倍，难以还清。",
        "tips": ["树立理性消费观，不超前消费", "缺钱可向学校申请正规助贷", "遭遇非法借贷立即报警或求助老师"],
    },
    "游戏账号交易诈骗": {
        "scenario": "你为高价出售游戏账号，网友要求在“安全平台”交易，注册后账号却被冻结，客服让你交解冻费。",
        "explain": "骗子搭建虚假交易平台，以交保证金、解冻费为由连环诈骗，钱到手即消失。",
        "tips": ["只在官方平台交易，拒绝私下转账", "不点击对方发来的平台链接", "任何要求先交钱的交易都别信"],
    },
    "AI换脸冒充亲友借钱": {
        "scenario": "深夜，你收到“室友”视频电话，画面里他焦急地说住院急需用钱，让你转账到指定账户。",
        "explain": "骗子用AI换脸技术伪造熟人视频，制造紧急情况利用你的信任和同情骗取钱财。",
        "tips": ["遇到熟人借钱，务必通过其他方式确认", "视频里可以让对方做特定动作验证", "不轻易转账，警惕深夜紧急求助"],
    },
    "演唱会门票代购诈骗": {
        "scenario": "你抢不到偶像演唱会门票，在粉丝群看到有人称内部渠道代购，付了全款后，对方失联。",
        "explain": "骗子利用追星热情，冒充票务人员或粉丝，收款后不发货或发假票。",
        "tips": ["购票只选官方渠道，勿信内部票", "不向个人账号直接转账", "发现被骗保存证据，及时报警"],
    },
}


class EducatorAgent(BaseAgent):
    name = "educate"
    description = "数字安全教育：典型案例讲解与安全知识科普"

    def handle(self, task: AgentTask) -> AgentResult:
        topic = task.params.get("topic", "")
        case = self._find_case(topic)

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

    @staticmethod
    def _find_case(topic: str) -> dict | None:
        """按关键词模糊匹配案例库（如 '刷单' 命中 '刷单返利诈骗'）。"""
        if not topic:
            return None
        for key in CASES:
            if topic in key or key in topic:
                return CASES[key]
        return None

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
