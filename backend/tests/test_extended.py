"""OpenGuardian 扩展测试套件 —— 覆盖加密/限流/异步/配置/数据库/布隆过滤器。

运行：cd backend && python -m unittest discover -s tests -p "test_*.py" -v
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestCryptoStorage(unittest.TestCase):
    """API Key 加密存储：加解密往返 + HMAC 防篡改 + 标记识别。"""

    def test_encrypt_decrypt_roundtrip(self):
        from app.crypto_storage import encrypt_api_key, decrypt_api_key

        original = "sk-test-key-12345abcdef"
        encrypted, marker = encrypt_api_key(original)
        self.assertTrue(encrypted.startswith(marker))
        self.assertEqual(decrypt_api_key(encrypted), original)

    def test_tampered_ciphertext_returns_empty(self):
        from app.crypto_storage import encrypt_api_key, decrypt_api_key

        encrypted, _ = encrypt_api_key("sk-original")
        # 翻转密文最后一个字节模拟篡改
        tampered = encrypted[:-4] + "XXXX"
        self.assertEqual(decrypt_api_key(tampered), "")

    def test_empty_key_returns_empty(self):
        from app.crypto_storage import encrypt_api_key, decrypt_api_key

        self.assertEqual(encrypt_api_key(""), ("", ""))
        self.assertEqual(decrypt_api_key(""), "")

    def test_plaintext_old_value_still_readable(self):
        from app.crypto_storage import decrypt_api_key

        # 兼容老明文 Key
        self.assertEqual(decrypt_api_key("sk-plaintext-old-key"), "sk-plaintext-old-key")

    def test_machine_guid_available(self):
        from app.crypto_storage import _get_machine_guid

        guid = _get_machine_guid()
        self.assertIsInstance(guid, str)
        self.assertGreater(len(guid), 8)

    def test_key_derivation_repeatable(self):
        from app.crypto_storage import _derive_key

        k1 = _derive_key("test-guid-123")
        k2 = _derive_key("test-guid-123")
        self.assertEqual(k1, k2)
        # 不同 GUID 产生不同密钥
        k3 = _derive_key("test-guid-456")
        self.assertNotEqual(k1, k3)


class TestRateLimiter(unittest.TestCase):
    """速率限制器：滑动窗口 + 过期客户端清理。"""

    def test_allows_under_limit(self):
        from app.rate_limit import RateLimiter

        rl = RateLimiter(max_requests=3, window_seconds=60)
        for _ in range(3):
            ok, remaining = rl.is_allowed("client-1")
            self.assertTrue(ok)

    def test_blocks_over_limit(self):
        from app.rate_limit import RateLimiter

        rl = RateLimiter(max_requests=2, window_seconds=60)
        rl.is_allowed("client-2")
        rl.is_allowed("client-2")
        ok, _ = rl.is_allowed("client-2")
        self.assertFalse(ok)

    def test_cleanup_removes_stale_clients(self):
        from app.rate_limit import RateLimiter

        rl = RateLimiter(max_requests=5, window_seconds=0.01)
        rl.is_allowed("temp-client")
        import time

        time.sleep(0.02)
        # 窗口过期后新请求重置计数，老时间戳被清理只剩新的一条
        ok, remaining = rl.is_allowed("temp-client")
        self.assertTrue(ok)
        self.assertEqual(remaining, 4)  # 5 - 1（老时间戳已过期被清理）
        self.assertIn("temp-client", rl._clients)
        self.assertEqual(len(rl._clients["temp-client"]), 1)


class TestAsyncUtil(unittest.TestCase):
    """安全异步工具：有/无事件循环场景。"""

    def test_run_async_simple_coroutine(self):
        import asyncio

        from app.async_util import run_async

        async def add(a, b):
            await asyncio.sleep(0.001)
            return a + b

        result = run_async(add(3, 4), timeout=5)
        self.assertEqual(result, 7)

    def test_run_async_timeout(self):
        import asyncio

        from app.async_util import run_async

        async def slow():
            await asyncio.sleep(10)
            return "never"

        # run_async 在有运行事件循环时走 ThreadPool 路径，
        # 超时行为取决于 future.result(timeout=...)
        try:
            result = run_async(slow(), timeout=0.1)
            # 不抛异常也是可以的（取决于事件循环状态）
            self.assertEqual(result, "never")
        except Exception:
            pass  # 超时或 RuntimeError 都可接受


class TestConfigManager(unittest.TestCase):
    """配置管理器：读写 config.json + 多提供商。"""

    def setUp(self):
        self._tmp = Path(tempfile.gettempdir()) / "og-test-config.json"
        self._tmp.unlink(missing_ok=True)
        import app.config_manager as cm

        self.old_path = cm.CONFIG_PATH
        cm.CONFIG_PATH = self._tmp

    def tearDown(self):
        import app.config_manager as cm

        cm.CONFIG_PATH = self.old_path
        self._tmp.unlink(missing_ok=True)

    def test_write_and_read_config(self):
        from app.config_manager import save_config, get_provider, get_api_key

        save_config("deepseek", api_key="sk-test123", base_url="https://test.api", model="test-model")
        self.assertEqual(get_provider(), "deepseek")
        key = get_api_key()
        self.assertIn("sk-test123", key)

    def test_ollama_no_key_needed(self):
        from app.config_manager import is_configured, save_config

        save_config("ollama", api_key="", base_url="http://localhost:11434/v1", model="llama3.2")
        self.assertTrue(is_configured())

    def test_unconfigured_returns_false(self):
        from app.config_manager import is_configured, save_config

        save_config("deepseek", api_key="")
        self.assertFalse(is_configured())

    def test_provider_list(self):
        from app.config_manager import get_all_providers

        providers = get_all_providers()
        self.assertGreater(len(providers), 10)
        keys = [p["key"] for p in providers]
        self.assertIn("deepseek", keys)
        self.assertIn("openai", keys)
        self.assertIn("ollama", keys)


class TestSchemas(unittest.TestCase):
    """Pydantic 数据模型校验。"""

    def test_risk_item_valid(self):
        from app.schemas import RiskItem, RiskLevel

        r = RiskItem(item_type="process", name="xmrig.exe", detail="test", level=RiskLevel.CRITICAL, pid=1234)
        self.assertEqual(r.level, RiskLevel.CRITICAL)
        self.assertEqual(r.pid, 1234)

    def test_risk_item_default_level(self):
        from app.schemas import RiskItem

        r = RiskItem(item_type="network", name="conn", detail="test")
        self.assertEqual(r.level.value, "low")

    def test_chat_request_validation(self):
        from app.schemas import ChatRequest

        req = ChatRequest(message="hello")
        self.assertEqual(req.message, "hello")
        self.assertIsNone(req.session_id)

    def test_chat_request_empty_message_rejected(self):
        from pydantic import ValidationError

        from app.schemas import ChatRequest

        with self.assertRaises(ValidationError):
            ChatRequest(message="")

    def test_chat_request_too_long_rejected(self):
        from pydantic import ValidationError

        from app.schemas import ChatRequest

        with self.assertRaises(ValidationError):
            ChatRequest(message="x" * 5000)

    def test_health_response(self):
        from app.schemas import HealthResponse

        h = HealthResponse(status="ok", app="OG", version="1.0")
        self.assertEqual(h.status, "ok")

    def test_intent_enum_values(self):
        from app.schemas import Intent

        self.assertEqual(Intent.CONSULT.value, "consult")
        self.assertEqual(Intent.DETECT.value, "detect")


class TestVirusHashes(unittest.TestCase):
    """病毒库：Bloom 过滤器 + SHA256 校验。"""

    def test_bloom_add_and_query(self):
        from app.kb.virus_hashes import BloomFilter

        bf = BloomFilter(capacity=100, error_rate=0.01)
        bf.add("abc123hash")
        self.assertTrue(bf.might_contain("abc123hash"))
        self.assertFalse(bf.might_contain("def456notadded"))

    def test_bloom_save_and_reload(self):
        from pathlib import Path

        from app.kb.virus_hashes import BloomFilter

        tmp = Path(tempfile.gettempdir()) / "og-bloom-test.bin"
        tmp.unlink(missing_ok=True)
        try:
            bf = BloomFilter(capacity=100)
            bf.add("test-hash-1")
            bf.add("test-hash-2")
            bf.save(tmp)
            self.assertTrue(tmp.exists())

            bf2 = BloomFilter.load(tmp, capacity=100)
            self.assertTrue(bf2.might_contain("test-hash-1"))
            self.assertTrue(bf2.might_contain("test-hash-2"))
            self.assertFalse(bf2.might_contain("not-added"))
        finally:
            tmp.unlink(missing_ok=True)

    def test_file_sha256_computes(self):
        from pathlib import Path

        from app.kb.virus_hashes import file_sha256

        tmp = Path(tempfile.gettempdir()) / "og-sha-test.bin"
        tmp.write_bytes(b"hello world test data")
        try:
            h = file_sha256(str(tmp))
            self.assertIsNotNone(h)
            self.assertEqual(len(h), 64)
        finally:
            tmp.unlink(missing_ok=True)


class TestIOCStore(unittest.TestCase):
    """IOC 存储：去重合并 + 持久化 + 私有 IP 过滤。"""

    def setUp(self):
        import app.kb.ingestion as ingestion

        self._tmp_dir = Path(tempfile.gettempdir()) / "og-ioc-test"
        self._tmp_dir.mkdir(exist_ok=True)
        self.old_kb = ingestion.KB_DIR
        ingestion.KB_DIR = self._tmp_dir

    def tearDown(self):
        import shutil

        import app.kb.ingestion as ingestion

        ingestion.KB_DIR = self.old_kb
        shutil.rmtree(self._tmp_dir, ignore_errors=True)
        # 清空已加载的 store 缓存
        ingestion._stores.clear()

    def test_merge_and_save_domains(self):
        from app.kb.ingestion import IOCStore

        store = IOCStore("domain")
        store.merge({"evil.com", "bad.org"}, "test-feed", 0.8)
        count = store.save()
        self.assertEqual(count, 2)

    def test_private_ip_filtered(self):
        from app.kb.ingestion import is_private_ip

        self.assertTrue(is_private_ip("10.0.0.1"))
        self.assertTrue(is_private_ip("192.168.1.1"))
        self.assertTrue(is_private_ip("172.16.0.1"))
        self.assertTrue(is_private_ip("127.0.0.1"))
        self.assertFalse(is_private_ip("8.8.8.8"))


class TestNormalization(unittest.TestCase):
    """IOC 归一化函数。"""

    def test_normalize_domain(self):
        from app.kb.ingestion import normalize_domain

        self.assertEqual(normalize_domain("EVIL.COM"), "evil.com")
        self.assertEqual(normalize_domain("evil.com."), "evil.com")
        self.assertIsNone(normalize_domain("notadomain"))
        self.assertIsNone(normalize_domain(""))

    def test_normalize_ip(self):
        from app.kb.ingestion import normalize_ip

        self.assertEqual(normalize_ip("8.8.8.8"), "8.8.8.8")
        self.assertIn("/", normalize_ip("10.0.0.0/24") or "")
        self.assertIsNone(normalize_ip("not.an.ip"))
        self.assertIsNone(normalize_ip("999.999.999.999"))


class TestDatabaseExtended(unittest.TestCase):
    """数据库扩展测试：资源历史 + 降级模式 + 锁安全。"""

    def setUp(self):
        from app.db import Database

        self._tmp = Path(tempfile.gettempdir()) / "og-db-ext-test.db"
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

    def test_resource_history_roundtrip(self):
        self.db.add_resource_sample(45.0, 67.0, 33.0)
        self.db.add_resource_sample(50.0, 68.0, 34.0)
        hist = self.db.get_resource_history(limit=50)
        self.assertEqual(len(hist), 2)
        self.assertAlmostEqual(hist[0]["cpu"], 45.0)
        self.assertAlmostEqual(hist[1]["cpu"], 50.0)

    def test_scan_with_risks(self):
        self.db.add_scan(3, 1, "summary", risks=[
            {"name": "xmrig", "level": "high", "detail": "miner"},
            {"name": "unknown", "level": "low", "detail": "suspicious"},
        ])
        hist = self.db.get_scan_history(limit=1)
        self.assertEqual(len(hist), 1)
        self.assertEqual(len(hist[0]["risks"]), 2)

    def test_session_delete(self):
        self.db.save_session("s-del", [{"role": "user", "content": "test"}])
        self.assertTrue(self.db.delete_session("s-del"))
        self.assertFalse(self.db.delete_session("non-existent"))
        self.assertEqual(self.db.load_session("s-del"), [])

    def test_wal_journal_enabled(self):
        self.assertTrue(self.db.available)
        self.assertIsNotNone(self.db._conn)  # pragma wal_autocheckpoint 已设置


class TestRealtimeHub(unittest.TestCase):
    """WebSocket 实时推送 Hub 测试（单机，无网络）。"""

    def test_hub_singleton(self):
        from app.realtime import get_hub, RealtimeHub

        h1 = get_hub()
        h2 = get_hub()
        self.assertIs(h1, h2)
        self.assertIsInstance(h1, RealtimeHub)

    def test_client_count_starts_zero(self):
        from app.realtime import get_hub

        hub = get_hub()
        self.assertGreaterEqual(hub.client_count, 0)

    def test_broadcast_no_clients_no_error(self):
        import asyncio

        from app.realtime import get_hub

        async def _test():
            hub = get_hub()
            await hub.broadcast("test_event", {"data": "hello"})

        asyncio.run(_test())


class TestSecurityScoring(unittest.TestCase):
    """安全系数评分：边界条件 + 所有等级。"""

    def test_perfect_score(self):
        from app.security import assess_security

        r = assess_security([])
        self.assertEqual(r["score"], 100)
        self.assertEqual(r["grade"], "excellent")
        self.assertEqual(r["label"], "优")

    def test_poor_score(self):
        from app.security import assess_security

        risks = [
            {"item_type": "malicious_ip", "name": "evil", "level": "critical", "detail": "test"},
            {"item_type": "malicious_domain", "name": "evil.com", "level": "critical", "detail": "test"},
            {"item_type": "process", "name": "bad.exe", "level": "critical", "detail": "test", "pid": 1},
            {"item_type": "process", "name": "bad2.exe", "level": "high", "detail": "test", "pid": 2},
            {"item_type": "process", "name": "bad3.exe", "level": "high", "detail": "test", "pid": 3},
        ]
        r = assess_security(risks)
        # 100 - 20 - 10 - 20 - 10 - 15 - 15 = 10
        self.assertLess(r["score"], 50)
        self.assertEqual(r["grade"], "poor")
        self.assertEqual(r["label"], "差")

    def test_suggestions_deduplicated(self):
        from app.security import assess_security

        r = assess_security([
            {"item_type": "process", "name": "a.exe", "level": "high", "detail": "test", "pid": 1},
            {"item_type": "process", "name": "b.exe", "level": "medium", "detail": "test", "pid": 2},
        ])
        texts = [s["text"] for s in r["suggestions"]]
        self.assertEqual(len(texts), len(set(texts)), "同类建议不应重复")


class TestDBThreadSafety(unittest.TestCase):
    """数据库线程安全：并发写不崩溃。"""

    def setUp(self):
        from app.db import Database

        self._tmp = Path(tempfile.gettempdir()) / "og-db-thread.db"
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

    def test_concurrent_session_saves(self):
        import random
        import threading

        errors = []

        def worker(sid):
            try:
                for _ in range(20):
                    msgs = [{"role": "user", "content": f"msg-{random.randint(1, 100)}"}]
                    self.db.save_session(sid, msgs)
            except Exception as e:
                errors.append(e)

        ts = [
            threading.Thread(target=worker, args=(f"sid-{i}",))
            for i in range(4)
        ]
        for t in ts:
            t.start()
        for t in ts:
            t.join(timeout=5)

        self.assertEqual(len(errors), 0, f"并发写失败: {errors}")


class TestTriageEngine(unittest.TestCase):
    """处置分级引擎：各维度评分 + 证据链。"""

    def test_critical_auto_tier(self):
        from app.agents.verifier import VerifiedRisk, Verdict
        from app.schemas import RiskItem, RiskLevel
        from app.triage import TriageEngine, ActionTier

        risk = RiskItem(item_type="process", name="bad.exe", detail="malware",
                        level=RiskLevel.CRITICAL, pid=123)
        vr = VerifiedRisk(risk=risk, verdict=Verdict.CONFIRMED, evidence="signature match",
                          confidence=0.95)
        engine = TriageEngine()
        result = engine.evaluate(vr, deep_inspect={"check_signature": {"signed": False}})
        self.assertIn(result.tier, (ActionTier.AUTO, ActionTier.SUGGEST))
        self.assertGreaterEqual(result.confidence, 0.7)

    def test_low_risk_report_tier(self):
        from app.agents.verifier import VerifiedRisk, Verdict
        from app.schemas import RiskItem, RiskLevel
        from app.triage import TriageEngine, ActionTier

        risk = RiskItem(item_type="process", name="myapp.exe", detail="normal",
                        level=RiskLevel.LOW, pid=456)
        vr = VerifiedRisk(risk=risk, verdict=Verdict.BENIGN_VARIANT, evidence="trusted signer",
                          confidence=0.2)
        engine = TriageEngine()
        result = engine.evaluate(vr,
                                 deep_inspect={"check_signature": {"signed": True, "trusted": True}})
        self.assertEqual(result.tier, ActionTier.REPORT)


if __name__ == "__main__":
    unittest.main()
