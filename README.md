# OpenGuardian 🔐

> AI 驱动的个人数字安全服务平台 —— 多 Agent 架构，为普通用户提供企业级终端安全防护

[![Python 3.11](https://img.shields.io/badge/Python-3.11-76b900)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-76b900)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-76b900)](LICENSE)

---

## 🚀 项目简介

OpenGuardian 是一个面向个人用户的安全防护平台，将**多智能体（Multi-Agent）架构**、**威胁情报**与 **LLM 大模型**结合，提供从检测、验证、教育到修复的完整安全闭环。

不是杀毒软件，而是你的 **AI 安全管家**——用大白话告诉你电脑有什么问题、为什么是问题、怎么解决。

## ✨ 核心能力

### 🔍 八模块并行检测引擎
| 模块 | 检测内容 |
|---|---|
| 进程检测 | 恶意进程 / 挖矿木马 / 高危行为 |
| 网络检测 | 恶意 IP / 恶意域名 / C2 通信 |
| 资源检测 | CPU / 内存 / 磁盘异常 |
| 漏洞审计 | SMBv1 / 防火墙 / 计划任务 / 启动项 |
| Defender 状态 | 实时保护 / 签名版本 |
| 系统更新 | 补丁缺失审计 |
| 风险服务 | 高危服务 / 共享 / 账户策略 |
| 凭据安全 | zxcvbn 密码强度 + 弱密码检测 |

### 🧠 多 Agent 验证流水线
```
Detector → Verifier → Reflector → Triage → Educator
```
每个风险项经过 **LLM 对抗性验证**（确认/证伪/不确定），杜绝误报。

### 📊 MITRE ATT&CK 映射
每个检测结果自动映射到 ATT&CK 战术/技术编号，构建攻击链可视化。

### 🤖 27 家 AI 提供商
DeepSeek / GPT / Claude / Gemini / 文心一言 / Kimi / GLM……一键切换，离线自动降级。

### 📄 多格式报告
HTML / **SARIF**（兼容 GitHub Code Scanning）双格式导出。

## 🏗️ 架构

```
┌─────────────────────────────────────────┐
│            PyWebView 桌面端              │
│   (Windows 原生窗口 + EdgeChromium)      │
└──────────────┬──────────────────────────┘
               │ HTTP/WS (127.0.0.1:8300)
┌──────────────▼──────────────────────────┐
│              FastAPI 后端                │
│  ┌──────────────────────────────────┐   │
│  │  Consultant (意图路由 + 编排)     │   │
│  ├──────────────────────────────────┤   │
│  │  Agent 总线                      │   │
│  │  Detect │ Asset │ Execute │      │   │
│  │  Educate │ Credential            │   │
│  ├──────────────────────────────────┤   │
│  │  Verifier │ Reflector │ Triage   │   │
│  │  AttackChain │ ETW │ CVE │ WMI   │   │
│  └──────────────────────────────────┘   │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│   威胁情报知识库 (SQLite + Bloom)        │
│  5797 病毒哈希 · 39440 恶意IP ·          │
│  2296 恶意域名 · 100万弱密码 · 30案例     │
└─────────────────────────────────────────┘
```

## 📦 快速开始

### 开发模式
```bash
# 1. 配置 API Key（DeepSeek 等）
cp backend/.env.example backend/.env
# 编辑 backend/.env 填入 DEEPSEEK_API_KEY

# 2. 安装依赖
cd backend
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt

# 3. 启动
.venv/Scripts/python -m uvicorn app.main:app --host 127.0.0.1 --port 8300
# 打开 http://127.0.0.1:8300
```

### 桌面版
双击 `OpenGuardian.exe`（PyWebView 原生窗口，自动启动后端）。

## 📁 目录结构
```
OpenGuardian/
├── backend/
│   ├── app/
│   │   ├── agents/          # 多 Agent 实现
│   │   │   ├── detector.py      # 八模块检测引擎
│   │   │   ├── verifier.py      # LLM 对抗验证
│   │   │   ├── consultant.py    # 意图路由编排
│   │   │   ├── educator.py      # 安全教育 RAG
│   │   │   ├── credential.py    # 凭据泄露检测
│   │   │   └── ...
│   │   ├── kb/              # 威胁情报知识库
│   │   ├── llm/             # 27 家 LLM 适配
│   │   └── main.py          # FastAPI 入口
│   ├── tests/               # 92 个单元测试
│   └── kb_data/             # 情报数据
├── frontend/                # 前端 (原生 JS + SVG)
├── desktop_app.py           # PyWebView 桌面壳
└── OpenGuardian.spec        # PyInstaller 打包配置
```

## 🛡️ 安全设计
- ✅ 无云依赖：所有检测**本地执行**，隐私零上传
- ✅ API Key 加密存储（本机 DPAPI 绑定）
- ✅ 检测结果本地 SQLite，卸载即清
- ✅ 威胁情报本地化，离线可用

## 📚 文档
- [研究报告](docs/RESEARCH-REPORT.md)
- [用户手册](docs/USER-MANUAL.md)
- [运维报告](docs/OPS-REPORT.md)

## 🏆 项目背景
温州科技职业学院 · 数智技术学院 · 创新项目

## 📄 License
MIT
