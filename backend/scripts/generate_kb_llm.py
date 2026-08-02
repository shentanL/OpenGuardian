"""用 DeepSeek LLM 批量生成新术语条目与教育案例，合并进知识库。

生成内容：
- 术语：移动安全、社交工程、反诈、法律法规类（~20 条）
- 案例：刷单诈骗、杀猪盘、校园贷、游戏交易诈骗等（~6 个）
"""
import json
import sys
import urllib.request

sys.path.insert(0, r"C:\Users\14845\Desktop\OpenGuardian\backend")
from app.config import settings  # noqa: E402

API_URL = "https://api.deepseek.com/chat/completions"


def llm_json(system: str, user: str) -> dict:
    payload = {
        "model": settings.LLM_MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.3,
        "max_tokens": 4000,
        "response_format": {"type": "json_object"},
    }
    req = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {settings.DEEPSEEK_API_KEY}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read())
    return json.loads(data["choices"][0]["message"]["content"])


# ---- 1. 生成新术语 ----
TERM_SYSTEM = """你是网络安全科普专家。生成符合以下 JSON 结构的术语条目列表：
{"terms": [{"key": "主术语|变体1|变体2", "plain": "大白话解释（30-50字，避免专业术语）",
"analogy": "生活化类比（一句话）", "advice": "防护建议（一句话）"}]}
要求：面向普通用户，通俗易懂。"""

TERM_USER = """生成以下主题的安全术语条目（共 20 条，每条 key 用主术语|常见变体格式）：
1. 移动安全：恶意App、权限滥用、伪基站、短信验证码劫持、公共充电桩攻击
2. 社交工程：杀猪盘、刷单诈骗、冒充公检法、AI换脸诈骗、冒充领导、快递诈骗、游戏交易诈骗
3. 反诈与法律：帮信罪、断卡行动、反诈中心APP、止付冻结
4. 网络风险：深度伪造、人肉搜索、社工库、暗网
5. 基础概念：浏览器指纹、Cookie、会话劫持、DNS劫持、ARP欺骗"""

# ---- 2. 生成新案例 ----
CASE_SYSTEM = """你是网络安全教育专家。生成符合以下 JSON 结构的案例列表：
{"cases": [{"key": "案例名", "scenario": "场景描述（60字内，有代入感）",
"explain": "原理讲解（80字内，通俗）", "tips": ["防护建议1", "防护建议2", "防护建议3"]}]}
要求：面向大学生用户，真实感强，通俗易懂。"""

CASE_USER = """生成 6 个针对大学生的安全案例：
刷单返利诈骗、杀猪盘（网恋诈骗）、校园贷陷阱、游戏账号交易诈骗、
AI换脸冒充亲友借钱、演唱会门票代购诈骗"""


def main() -> None:
    print("== 生成新术语 ==")
    try:
        term_data = llm_json(TERM_SYSTEM, TERM_USER)
        terms = term_data.get("terms", [])
        print(f"  ✓ 生成 {len(terms)} 条术语")
        with open(r"C:\Users\14845\Desktop\OpenGuardian\backend\kb_data\new_terms.json", "w", encoding="utf-8") as f:
            json.dump(terms, f, ensure_ascii=False, indent=1)
    except Exception as e:  # noqa: BLE001
        print(f"  ✗ 术语生成失败: {e}")

    print("== 生成新案例 ==")
    try:
        case_data = llm_json(CASE_SYSTEM, CASE_USER)
        cases = case_data.get("cases", [])
        print(f"  ✓ 生成 {len(cases)} 个案例")
        with open(r"C:\Users\14845\Desktop\OpenGuardian\backend\kb_data\new_cases.json", "w", encoding="utf-8") as f:
            json.dump(cases, f, ensure_ascii=False, indent=1)
    except Exception as e:  # noqa: BLE001
        print(f"  ✗ 案例生成失败: {e}")


if __name__ == "__main__":
    main()
