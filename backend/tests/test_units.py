"""OpenGuardian 单元测试（确定性，不依赖 LLM/网络）。

运行：cd backend && python -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.agents.analyst import AnalystAgent  # noqa: E402
from app.agents.consultant import ConsultantAgent, EDU_TOPICS  # noqa: E402
from app.agents.detector import SYSTEM_PROCESSES, _match_pattern, DetectorAgent  # noqa: E402
from app.agents.educator import CASES, EducatorAgent  # noqa: E402
from app.agents.executor import AUDIT_LOG, ExecutorAgent  # noqa: E402
from app.schemas import AgentTask, Intent  # noqa: E402


def _task(intent: Intent, **params) -> AgentTask:
    return AgentTask(intent=intent, params=params)


class TestDetector(unittest.TestCase):
    def test_malware_pattern_hit(self):
        hit = _match_pattern("xmrig.exe", r"C:\Users\x\miner\xmrig.exe")
        self.assertIsNotNone(hit)
        self.assertIn("挖矿", hit[0])

    def test_benign_process_no_hit(self):
        self.assertIsNone(_match_pattern("chrome.exe", r"C:\Program Files\Google\Chrome\chrome.exe"))

    def test_whitelist_contains_system(self):
        self.assertIn("svchost.exe", SYSTEM_PROCESSES)

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
        before = len(AUDIT_LOG)
        result = ExecutorAgent().handle(_task(Intent.EXECUTE, pid=4, action="terminate"))
        self.assertFalse(result.success)
        self.assertIn("保护名单", result.message)
        self.assertEqual(len(AUDIT_LOG), before)  # 白名单拒绝不记审计

    def test_missing_pid_friendly_error(self):
        result = ExecutorAgent().handle(_task(Intent.EXECUTE))
        self.assertFalse(result.success)


class TestEducator(unittest.TestCase):
    def test_case_library_has_5_topics(self):
        self.assertEqual(len(CASES), 5)

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


if __name__ == "__main__":
    unittest.main()
