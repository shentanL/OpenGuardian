"""OpenGuardian 单元测试（确定性，不依赖 LLM/网络）。

运行：cd backend && python -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.agents.analyst import AnalystAgent  # noqa: E402
from app.agents.consultant import ConsultantAgent, EDU_TOPICS  # noqa: E402
from app.agents.detector import (  # noqa: E402
    MALWARE_PATTERNS,
    SYSTEM_PROCESSES,
    _match_pattern,
    DetectorAgent,
)
from app.agents.educator import CASES, EducatorAgent  # noqa: E402
from app.agents.executor import ExecutorAgent  # noqa: E402
from app.kb.glossary import GLOSSARY, explain_terms, lookup  # noqa: E402
from app.schemas import AgentTask, Intent  # noqa: E402


def _task(intent: Intent, **params) -> AgentTask:
    return AgentTask(intent=intent, params=params)


class TestDetector(unittest.TestCase):
    def test_malware_pattern_hit(self):
        hit = _match_pattern("xmrig.exe", r"C:\Users\x\miner\xmrig.exe")
        self.assertIsNotNone(hit)
        label, desc, level = hit
        self.assertIn("挖矿", label)
        self.assertEqual(level.value, "critical")

    def test_benign_process_no_hit(self):
        self.assertIsNone(_match_pattern("chrome.exe", r"C:\Program Files\Google\Chrome\chrome.exe"))

    def test_whitelist_contains_system(self):
        self.assertIn("svchost.exe", SYSTEM_PROCESSES)

    def test_signature_library_size(self):
        self.assertGreaterEqual(len(MALWARE_PATTERNS), 50, "特征库应 ≥50 条以支撑识别率指标")

    def test_signature_categories(self):
        names = [p[1] for p in MALWARE_PATTERNS]
        self.assertTrue(any("挖矿" in n for n in names))
        self.assertTrue(any("勒索" in n for n in names))
        self.assertTrue(any("远控" in n or "RAT" in n for n in names))

    def test_scans_run_without_error(self):
        agent = DetectorAgent()
        self.assertIsInstance(agent._scan_processes(), list)
        self.assertIsInstance(agent._scan_resources(), list)


class TestAnalyst(unittest.TestCase):
    def test_weak_password_critical(self):
        risks = AnalystAgent()._check_password("123456")
        self.assertTrue(risks)
        self.assertEqual(risks[0].level.value, "critical")

    def test_strong_password_ok(self):
        risks = AnalystAgent()._check_password("Kj8#mQ2$vLp9xT4w")
        self.assertFalse(any(r.level.value in ("critical", "high") for r in risks))


class TestExecutor(unittest.TestCase):
    def test_system_process_protected(self):
        from app.db import get_db

        before = len(get_db().get_audit())
        result = ExecutorAgent().handle(_task(Intent.EXECUTE, pid=4, action="terminate"))
        self.assertFalse(result.success)
        self.assertIn("保护名单", result.message)
        self.assertEqual(len(get_db().get_audit()), before)  # 白名单拒绝不记审计

    def test_missing_pid_friendly_error(self):
        result = ExecutorAgent().handle(_task(Intent.EXECUTE))
        self.assertFalse(result.success)


class TestEducator(unittest.TestCase):
    def test_case_library_size(self):
        self.assertGreaterEqual(len(CASES), 10, "案例库应 ≥10 个（含反诈新案例）")

    def test_phishing_case_returns(self):
        result = EducatorAgent().handle(_task(Intent.EDUCATE, topic="钓鱼邮件"))
        self.assertTrue(result.success)
        self.assertIn("钓鱼邮件", result.message)


class TestConsultant(unittest.TestCase):
    def setUp(self):
        self.consultant = ConsultantAgent(bus=None)
        # 强制 LLM 离线 → 走确定性关键词降级路径
        self.consultant.llm.api_key = ""

    def test_keyword_classification(self):
        cases = {
            "帮我检测一下电脑": Intent.DETECT,
            "讲讲钓鱼邮件": Intent.EDUCATE,
            "检查密码 123456": Intent.ASSET,
            "结束进程 1234": Intent.EXECUTE,
            "什么是防火墙？": Intent.CONSULT,
        }
        for text, expected in cases.items():
            got, _ = self.consultant._classify(text)
            self.assertEqual(got, expected, f"input={text}")

    def test_extract_pid(self):
        self.assertEqual(self.consultant._extract_pid("结束进程 1234"), 1234)
        self.assertIsNone(self.consultant._extract_pid("帮我检测电脑"))


class TestBlacklists(unittest.TestCase):
    def test_domain_hit(self):
        from app.kb.blacklists import is_malicious_domain

        # URLhaus 真实恶意域名
        self.assertTrue(is_malicious_domain("0022a601.pphost.net"))
        self.assertFalse(is_malicious_domain("google.com"))

    def test_domain_subdomain_match(self):
        from app.kb.blacklists import is_malicious_domain

        self.assertTrue(is_malicious_domain("evil.sub.0022a601.pphost.net"))

    def test_ip_query_runs(self):
        from app.kb.blacklists import is_malicious_ip

        # 正常 IP 不应命中（黑名单主要是威胁情报段）
        self.assertFalse(is_malicious_ip("8.8.8.8"))
        self.assertFalse(is_malicious_ip("1.1.1.1"))


class TestGlossary(unittest.TestCase):
    def test_library_size(self):
        self.assertGreaterEqual(len(GLOSSARY), 40, "术语库应 ≥40 主条目")

    def test_lookup(self):
        entry = lookup("木马")
        self.assertIsNotNone(entry)
        self.assertIn("plain", entry)
        # 变体也能查
        self.assertIsNotNone(lookup("xmrig"))
        self.assertIsNotNone(lookup("2FA"))

    def test_explain_terms(self):
        items = explain_terms("检测到 keylogger 和反弹shell，CPU 占用 95%")
        terms = [i["term"] for i in items]
        self.assertIn("键盘记录器", terms)
        self.assertIn("反弹shell", terms)

    def test_lookup_unknown_returns_none(self):
        self.assertIsNone(lookup("不存在的术语xyz"))


if __name__ == "__main__":
    unittest.main()
