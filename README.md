# OpenGuardian — AI 驱动的个人数字安全服务平台

> 温州科技职业学院 数智技术学院 · "导师+项目+团队"创新项目（2026-2027学年）
> 负责人：郑琪涛 · 团队成员：包斌 / 周奕含 / 徐宇豪 / 付思思 / 龚瑜洁 / 沈鑫强

## 🎯 项目定位

打破传统安全工具"功能堆砌"的局限，以 **大语言模型 + 多智能体协同** 为核心，
构建覆盖"**风险识别 → 通俗理解 → 一键处置 → 安全教育**"全流程的个人数字安全服务平台。

**核心痛点**：安全产品"看不懂、不会用、不会处理"。

## 🏗️ 系统架构

```
用户提问
   │
   ▼
┌─────────────────────────────────────────────┐
│              交互 Agent (Consultant)          │
│        自然语言理解 · 意图识别 · 应答生成      │
└─────────────────────────────────────────────┘
   │                    │                    │
   ▼                    ▼                    ▼
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│ 检测Agent │  │ 分析Agent │  │ 执行Agent │  │ 教育Agent │
│ 风险识别  │  │ 资产防护  │  │ 一键处置  │  │ 安全科普  │
└──────────┘  └──────────┘  └──────────┘  └──────────┘
   └──────────── 消息总线 (Message Bus) ────────────┘
```

**处理链路**：`用户提问 → 自动任务分解 → 多模块并行处理 → 统一结果反馈`

## 🧩 五大服务

| Agent | 服务 | 说明 |
|---|---|---|
| 交互 | 数字安全咨询 | 对话式提问，通俗解答 |
| 检测 | 数字风险识别 | 异常进程/网络连接/恶意程序检测与风险分级 |
| 分析 | 数字资产防护 | 账号密码强度、隐私泄露监测 |
| 执行 | 终端健康管理 | 资源监控 + 一键处置（白名单+授权） |
| 教育 | 数字安全教育 | 钓鱼邮件/假冒网站案例科普，个性化推送 |

## 🛠️ 技术栈

- **后端**：Python 3.11 + FastAPI + WebSocket + SQLite
- **LLM**：DeepSeek API（Anthropic 兼容端点或原生端点）
- **检测**：psutil
- **前端**：单页聊天 UI（HTML + JS，无构建步骤）
- **客户端**：PyWebview（Windows 可执行文件）

## 📁 目录结构

```
OpenGuardian/
├── backend/
│   ├── app/
│   │   ├── main.py          # FastAPI 入口
│   │   ├── config.py        # 配置（API Key 等）
│   │   ├── bus.py           # 消息总线
│   │   ├── schemas.py       # 数据模型
│   │   ├── agents/          # 5 个 Agent
│   │   ├── llm/             # LLM 客户端
│   │   └── kb/              # 术语映射知识库
│   └── tests/
├── frontend/                # 聊天 UI
├── docs/                    # 需求/架构/用户手册/运维报告
└── README.md
```

## 🚀 快速开始

```bash
cd backend
python -m venv .venv
.venv/Scripts/activate
pip install -r requirements.txt
# 配置 .env（DEEPSEEK_API_KEY=sk-xxx）
uvicorn app.main:app --reload --port 8300
# 浏览器打开 http://localhost:8300
```

> 注意：Windows 上 8000/8100 等端口可能落在 Hyper-V 保留范围内（`netsh interface ipv4 show excludedportrange protocol=tcp` 可查），推荐用 8300。

## ✅ 测试

```bash
cd backend
python -m unittest discover -s tests -p "test_*.py"   # 单元 + API 集成测试
```

- `test_units.py` — 确定性单元测试（LLM 离线降级路径），无需网络
- `test_api.py` — API 集成测试，服务未运行时自动跳过

## 📌 量化目标

- 自然语言咨询平均响应 ≤ 3 秒
- 用户满意度 ≥ 80%
- 常见恶意软件识别准确率 ≥ 85%
- 用户安全术语理解率提升 80% 以上
