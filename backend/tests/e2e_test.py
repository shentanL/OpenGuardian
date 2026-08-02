"""OpenGuardian API 端到端测试脚本。"""
import json
import sys
import httpx

BASE = "http://127.0.0.1:8300"


def test(message: str) -> None:
    print(f"\n{'='*60}\n🧪 输入: {message}")
    try:
        resp = httpx.post(f"{BASE}/api/chat", json={"message": message}, timeout=60)
        resp.raise_for_status()
        d = resp.json()
        print(f"意图: {d.get('intent')}")
        print(f"回复: {d.get('reply', '')[:600]}")
        risks = d.get("risks") or []
        if risks:
            print(f"风险项 ({len(risks)}):")
            for r in risks[:5]:
                print(f"  [{r['level']}] {r['name']} — {r['detail'][:60]}")
        if d.get("needs_confirmation"):
            print(f"需要确认: {d.get('execute_hint')}")
    except Exception as e:  # noqa: BLE001
        print(f"❌ 错误: {e}")
        if isinstance(e, httpx.HTTPStatusError):
            print(e.response.text[:300])


if __name__ == "__main__":
    tests = sys.argv[1:] or [
        "帮我检测一下电脑",
        "讲讲钓鱼邮件",
        "检查密码 123456",
        "什么是安全？",
    ]
    for t in tests:
        test(t)
