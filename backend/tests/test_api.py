"""OpenGuardian API 集成测试（需服务运行在 :8300，未运行则自动跳过）。"""
import os
import sys
import unittest

import httpx

BASE = os.getenv("OG_BASE_URL", "http://127.0.0.1:8300")


def _ping() -> bool:
    try:
        return httpx.get(f"{BASE}/api/health", timeout=3).status_code == 200
    except Exception:  # noqa: BLE001
        return False


@unittest.skipUnless(
    os.getenv("OG_TEST_API") or _ping(),
    "服务未运行（设置 OG_TEST_API=1 或先启动 uvicorn）",
)
class TestAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = httpx.Client(base_url=BASE, timeout=60)

    def test_health(self):
        r = self.client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "ok")

    def test_chat_detect_intent(self):
        r = self.client.post("/api/chat", json={"message": "帮我检测一下电脑"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["intent"], "detect")

    def test_chat_educate_intent(self):
        r = self.client.post("/api/chat", json={"message": "讲讲钓鱼邮件"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["intent"], "educate")

    def test_chat_asset_intent(self):
        r = self.client.post("/api/chat", json={"message": "检查密码 123456"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["intent"], "asset")

    def test_execute_missing_process(self):
        r = self.client.post("/api/execute", json={"pid": 999999, "action": "terminate"})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()["success"])

    def test_audit_endpoint(self):
        r = self.client.get("/api/audit")
        self.assertEqual(r.status_code, 200)

    def test_static_assets(self):
        for path in ("/", "/static/style.css", "/static/app.js"):
            r = self.client.get(path)
            self.assertEqual(r.status_code, 200, path)


def _ping() -> bool:
    try:
        return httpx.get(f"{BASE}/api/health", timeout=3).status_code == 200
    except Exception:  # noqa: BLE001
        return False


if __name__ == "__main__":
    unittest.main()
