"""从 SecLists 抓取弱密码数据，生成 OpenGuardian 弱密码库。

数据源（GitHub SecLists）：
- Chinese-common-password-list-top-1000.txt   中文弱密码
- Mandarin_Pwdb_common-password-list-top-150.txt 普通话
- 2025-199_most_used_passwords.txt           2025 全球最新
- 10k-most-common.txt                        经典 Top（取前 200）
"""
import urllib.request

BASE = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials"
SOURCES = [
    f"{BASE}/Language-Specific/Chinese-common-password-list-top-1000.txt",
    f"{BASE}/Language-Specific/Mandarin_Pwdb_common-password-list-top-150.txt",
    f"{BASE}/2025-199_most_used_passwords.txt",
    f"{BASE}/10k-most-common.txt",
]

OUT = r"C:\Users\14845\Desktop\OpenGuardian\backend\kb_data\passwords.txt"
CAP_PER_SOURCE = 400  # 每个源最多取多少条

all_pw: set[str] = set()
for url in SOURCES:
    try:
        with urllib.request.urlopen(url, timeout=20) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        src_name = url.rsplit("/", 1)[-1]
        before = len(all_pw)
        for pw in lines[:CAP_PER_SOURCE]:
            # 清洗：去空格、去超长、去纯符号
            cleaned = pw.strip()
            if len(cleaned) < 4 or len(cleaned) > 20:
                continue
            if all(c in "!@#$%^&*()_+-=[]{};:,.<>?/" for c in cleaned):
                continue
            all_pw.add(cleaned)
        print(f"  ✓ {src_name}: {len(lines)} 行 → 新增 {len(all_pw)-before} 条")
    except Exception as e:  # noqa: BLE001
        print(f"  ✗ {url}: {e}")

print(f"合计去重后: {len(all_pw)} 条")

# 按长度排序写出（短密码风险最高，排前面）
sorted_pw = sorted(all_pw, key=lambda p: (len(p), p))
with open(OUT, "w", encoding="utf-8") as f:
    f.write("# OpenGuardian 弱密码库（来源：SecLists 公开字典）\n")
    f.write(f"# 共 {len(sorted_pw)} 条 · 生成时间 2026-08-02\n")
    for pw in sorted_pw:
        f.write(pw + "\n")
print(f"已写入 {OUT}")
