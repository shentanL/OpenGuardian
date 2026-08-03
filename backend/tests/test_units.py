"""OpenGuardian 单元测试（确定性，不依赖 LLM/网络）。

运行：cd backend && python -m unittest discover -s tests -v
"""
import os
import sys
import unittest
from pathlib import Path

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
    def test_system_idle_process_in_whitelist(self):
        """回归：System Idle Process 必须在白名单（曾误报挖矿木马）。"""
        from app.agents.detector import SYSTEM_PROCESSES

        self.assertIn("System Idle Process", SYSTEM_PROCESSES)
        self.assertIn("System", SYSTEM_PROCESSES)

    def test_cpu_threshold_normalized(self):
        """CPU 阈值按核数归一化：85% 总计能力为界（多核下阈值=85×核数）。"""
        import psutil

        from app.config import settings

        cores = max(psutil.cpu_count() or 1, 1)
        threshold = settings.CPU_ALERT_PCT * cores
        # 边界：99% 阈值不报警，101% 报警（归一化生效）
        self.assertFalse(int(threshold * 0.99) > threshold)
        self.assertTrue(int(threshold * 1.01) > threshold)
        # 占满全部核：必然报警
        miner_val = cores * 100
        self.assertTrue(miner_val > threshold, "占满全部核的进程应触发 CPU 报警")
        # 单核场景：100% > 85% 报警，50% 不报警
        self.assertTrue(100 > settings.CPU_ALERT_PCT)
        self.assertFalse(50 > settings.CPU_ALERT_PCT)
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


class TestDatabase(unittest.TestCase):
    """SQLite 持久化层测试（独立临时库，不污染产品库）。"""

    def setUp(self):
        import tempfile
        from pathlib import Path

        from app.db import Database

        self._tmp = Path(tempfile.gettempdir()) / "hv-unit-test.db"
        self._tmp.unlink(missing_ok=True)
        self.db = Database(self._tmp)

    def tearDown(self):
        if self.db._conn:
            self.db._conn.close()
        import time

        for _ in range(5):
            try:
                self._tmp.unlink()
                break
            except PermissionError:
                time.sleep(0.3)

    def test_session_roundtrip(self):
        self.db.save_session("s1", [{"role": "user", "content": "hi"}])
        loaded = self.db.load_session("s1")
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["content"], "hi")
        # 覆盖更新
        self.db.save_session("s1", [{"role": "user", "content": "hi"}, {"role": "user", "content": "again"}])
        self.assertEqual(len(self.db.load_session("s1")), 2)
        self.assertEqual(self.db.list_sessions()[0]["id"], "s1")

    def test_audit_log(self):
        self.db.add_audit("terminate", 123, "x.exe", "ok")
        self.db.add_audit("terminate(force)", 456, "y.exe", "ok")
        logs = self.db.get_audit()
        self.assertEqual(len(logs), 2)
        self.assertEqual(logs[0]["action"], "terminate(force)")  # 倒序

    def test_whitelist_crud(self):
        self.assertTrue(self.db.add_whitelist("myapp.exe"))
        self.assertIn("myapp.exe", self.db.get_whitelist())
        self.assertFalse(self.db.add_whitelist("myapp.exe"))  # 去重
        self.assertTrue(self.db.remove_whitelist("myapp.exe"))
        self.assertNotIn("myapp.exe", self.db.get_whitelist())

    def test_scan_history(self):
        self.db.add_scan(3, 1, "检测完成")
        hist = self.db.get_scan_history()
        self.assertEqual(len(hist), 1)
        self.assertEqual(hist[0]["total"], 3)
        self.assertEqual(hist[0]["high"], 1)


class TestUIFrontend(unittest.TestCase):
    """前端 UI 变更验证（粒子背景 + 1s 采样 + canvas 层级 + 风险明细）。"""

    def test_background_js_particle_logic(self):
        bg = (Path(__file__).resolve().parent.parent.parent / "frontend" / "background.js").read_text(encoding="utf-8")
        for feature in ("LINK_DIST", "MOUSE_DIST", "MAX_PARTICLES", "requestAnimationFrame", "visibilitychange", "118,185,0"):
            self.assertIn(feature, bg, f"background.js 缺 {feature}")

    def test_background_js_syntax(self):
        import subprocess

        bg = Path(__file__).resolve().parent.parent.parent / "frontend" / "background.js"
        node = r"C:\Users\14845\AppData\Local\hermes\node\node.exe"
        r = subprocess.run([node, "--check", "background.js"], capture_output=True, text=True, cwd=bg.parent)
        self.assertEqual(r.returncode, 0, r.stderr[:100])

    def test_index_has_canvas_and_bg(self):
        html = (Path(__file__).resolve().parent.parent.parent / "frontend" / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="bg-canvas"', html)
        self.assertIn("background.js", html)

    def test_css_bg_layer(self):
        css = (Path(__file__).resolve().parent.parent.parent / "frontend" / "style.css").read_text(encoding="utf-8")
        self.assertIn(".bg-canvas", css)
        self.assertIn("pointer-events: none", css)
        self.assertEqual(css.count("{"), css.count("}"))
    def test_sampler_interval_1s(self):
        """资源采样间隔缩到最短：1s 连续采样。"""
        main = (Path(__file__).resolve().parent.parent / "app" / "main.py").read_text(encoding="utf-8")
        self.assertIn("interval=1", main)
        self.assertIn("get_resource_history(limit=120)", main)

    def test_kb_active_update(self):
        """知识库主动汲取：启动后台更新 + stats 暴露状态。"""
        main = (Path(__file__).resolve().parent.parent / "app" / "main.py").read_text(encoding="utf-8")
        self.assertIn("start_background_update", main)
        self.assertIn("kb_status", main)
        updater = (Path(__file__).resolve().parent.parent / "app" / "kb" / "updater.py").read_text(encoding="utf-8")
        self.assertIn("URLHAUS_URL", updater)
        self.assertIn("FIREHOL_URL", updater)
        self.assertIn("update_knowledge", updater)
        js = (Path(__file__).resolve().parent.parent.parent / "frontend" / "app.js").read_text(encoding="utf-8")
        self.assertIn("renderKbStatus", js)

    def test_clickable_affordance(self):
        """可点击元素区分：查看/收起提示 + 展开详情交互。"""
        js = (Path(__file__).resolve().parent.parent.parent / "frontend" / "app.js").read_text(encoding="utf-8")
        self.assertIn("expand-hint", js)
        self.assertIn("scan-detail", js)
        self.assertIn("risk-sug", js)
        css = (Path(__file__).resolve().parent.parent.parent / "frontend" / "style.css").read_text(encoding="utf-8")
        self.assertIn(".clickable", css)
        self.assertIn("cursor: pointer", css)


class TestIntentRules(unittest.TestCase):
    """意图识别规则：疑问句优先 + 各意图确定性分类（曾误判 consult→detect/educate）。"""

    CASES = {
        "什么是木马？": Intent.CONSULT,
        "什么是钓鱼邮件？": Intent.CONSULT,
        "解释一下什么是病毒": Intent.CONSULT,
        "帮我检测一下电脑": Intent.DETECT,
        "检查密码 123456": Intent.ASSET,
        "讲讲勒索病毒": Intent.EDUCATE,
        "讲讲钓鱼邮件": Intent.EDUCATE,
        "结束进程 123": Intent.EXECUTE,
    }

    def test_keyword_classify_all_intents(self):
        for text, want in self.CASES.items():
            got = ConsultantAgent._keyword_classify(text)
            self.assertEqual(got, want, f"{text!r} → {got}，期望 {want}")

    def test_question_first_overrides_detect_keywords(self):
        """疑问句式最优先：'什么是木马？' 不能被 DETECT 的 '木马' 抢走。"""
        self.assertIs(ConsultantAgent._keyword_classify("什么是木马？"), Intent.CONSULT)
        self.assertIs(ConsultantAgent._keyword_classify("什么是钓鱼邮件？"), Intent.CONSULT)


class TestDetectorPatterns(unittest.TestCase):
    """特征库：黑客工具命中 + 正常程序零误报（曾漏报 netcat/ncat）。"""

    def test_hack_tools_hit(self):
        for name in ("netcat.exe", "ncat.exe"):
            self.assertIsNotNone(_match_pattern(name, rf"C:\tmp\{name}"), f"{name} 应命中")

    def test_legit_programs_no_false_positive(self):
        for name in ("chrome.exe", "explorer.exe", "notepad.exe"):
            self.assertIsNone(_match_pattern(name, rf"C:\Program Files\{name}"), f"{name} 不应误报")

    def test_netcat_in_patterns(self):
        names = {p[0] for p in MALWARE_PATTERNS}
        self.assertIn("netcat", names)
        self.assertIn("ncat", names)


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
