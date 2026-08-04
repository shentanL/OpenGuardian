# OpenGuardian 运维报告

**版本**：v0.7.0  
**运维对象**：OpenGuardian 桌面端（PyWebView + FastAPI）  
**目标读者**：部署/维护人员、评审专家

---

## 一、部署架构

### 1.1 运行时拓扑

```
┌─────────────────────────────────────────────┐
│           OpenGuardian.exe (PyInstaller)     │
│                                             │
│  ┌─────────────┐   ┌─────────────────────┐  │
│  │ PyWebView   │   │ FastAPI (127.0.0.1) │  │
│  │ 原生窗口     │◄─►│ 端口 8300           │  │
│  │ EdgeChromium│   │  SSE / REST / WS    │  │
│  └─────────────┘   └─────────┬───────────┘  │
│                              │               │
│  ┌───────────────────────────▼─────────────┐ │
│  │ 数据层: SQLite (AppData) + KB (只读)     │ │
│  └─────────────────────────────────────────┘ │
└─────────────────────────────────────────────┘
```

### 1.2 数据目录（Windows）

| 路径 | 内容 | 可写 |
|---|---|---|
| `%LOCALAPPDATA%\OpenGuardian\openguardian.db` | 主数据库（WAL 模式） | ✅ |
| `%LOCALAPPDATA%\OpenGuardian\config.json` | 配置（API Key 加密） | ✅ |
| `%LOCALAPPDATA%\OpenGuardian\crashes\` | 崩溃日志 | ✅ |
| `%LOCALAPPDATA%\OpenGuardian\.update_cache.json` | 更新缓存 | ✅ |
| `<安装目录>\_internal\kb_data\` | 威胁情报（只读） | ❌ |
| `<安装目录>\_internal\frontend\` | 前端静态资源（只读） | ❌ |

> ⚠️ **关键设计**：可写数据全部在 AppData，安装目录只读。这是 PyInstaller frozen 环境的正确姿势——避免 `_MEI` 临时目录导致数据丢失。

---

## 二、部署清单

### 2.1 打包流水线

```
Python 源码
  │  PyInstaller (OpenGuardian.spec)
  ▼
dist/OpenGuardian/  (文件夹 + OpenGuardian.exe)
  │  Inno Setup (setup.iss → ISCC.exe)
  ▼
OpenGuardian-0.7.0-Setup.exe  (安装包)
```

### 2.2 打包要点（spec 配置）

| 项目 | 配置 |
|---|---|
| 前端资源 | `datas: frontend → frontend` |
| 知识库 | `datas: kb_data → backend/kb_data` |
| .env | `datas: backend/.env → backend` |
| 隐藏导入 | 全部 30+ 模块（agents/kb/llm/新模块） |
| pywebview | hookspath 指定（EdgeChromium 后端） |
| runtime hook | `runtime_hook.py`（frozen 环境初始化） |
| 图标 | `OpenGuardian.ico`（7 尺寸） |

### 2.3 安装包（Inno Setup）特性

- 中文/英文双语向导
- 默认安装 `C:\Program Files\OpenGuardian`
- 桌面 + 开始菜单快捷方式
- 管理员权限请求（UAC）
- **卸载彻底清空**：AppData + `_internal` + config.json + .env + *.db + *.log

---

## 三、监控与运维

### 3.1 健康检查

```bash
# 服务健康
curl http://127.0.0.1:8300/api/health
# 返回: {"status":"ok","version":"0.7.0","llm":"configured","db":"connected","ws_clients":0}

# 配置状态
curl http://127.0.0.1:8300/api/config

# 仪表盘数据
curl http://127.0.0.1:8300/api/stats

# 崩溃记录
curl http://127.0.0.1:8300/api/crashes
```

### 3.2 日志体系

| 日志 | 位置 | 说明 |
|---|---|---|
| 访问日志 | 控制台/stdout | 结构化 JSON（request_id/latency_ms） |
| 崩溃报告 | `%LOCALAPPDATA%\OpenGuardian\crashes\crash-*.json` | 自动收集（错误处理器） |
| 数据库 WAL | `openguardian.db-wal` | SQLite 预写日志 |

### 3.3 进程管理

```bash
# 查看进程
tasklist | findstr OpenGuardian

# 端口占用检查
netstat -ano | findstr :8300

# 强制清理残留进程（异常情况）
taskkill /F /IM OpenGuardian.exe
```

> ✅ 正常退出：托盘 → 退出 → `os._exit(0)` 强制终止全部线程（含后台服务线程），无残留。
> ✅ 异常防护：每次启动自动杀死占用 8300 端口的旧进程。

### 3.4 数据库维护

- 存储模式：SQLite WAL（读写并发安全）
- 数据表：sessions / scan_history / resource_history / audit_log / whitelist / memory
- **打包前清理**（发布铁律）：
  ```sql
  DELETE FROM sessions;
  DELETE FROM scan_history;
  DELETE FROM resource_history;
  DELETE FROM audit_log;
  ```

---

## 四、故障排查手册

### 4.1 服务无法启动

| 症状 | 排查步骤 |
|---|---|
| 双击无反应 | 1. 检查端口 8300 是否被占用（`netstat -ano \| findstr :8300`）<br>2. 检查 `%LOCALAPPDATA%\OpenGuardian\crashes\` 最新崩溃日志 |
| 启动后白屏 | 前端资源缺失 → 检查安装完整性，重新安装 |
| 数据库损坏 | 删除 `openguardian.db*` 后重启（自动重建） |

### 4.2 AI 对话失败

| 症状 | 排查步骤 |
|---|---|
| "服务暂时无法连接AI" | 1. `设置页` 检查 API Key<br>2. `curl http://127.0.0.1:8300/api/health` 看 llm 字段<br>3. 测试直连：`curl https://api.deepseek.com/chat/completions -H "Authorization: Bearer <key>"` |
| 响应慢 | 默认模型 `deepseek-v4-flash`（1.2s 首响应）；可换更快提供商 |
| 返回固定文案 | 案例库命中（educate 意图）→ 属正常设计；未命中才走 LLM |

### 4.3 检测异常

| 症状 | 排查步骤 |
|---|---|
| 检测超时 | 并行引擎受最慢模块限制（网络/补丁查询）；SCAN_TIMEOUT=15s 兜底 |
| 误报 | Verifier 已实现确定性验证；仍误报可加入白名单（`/api/whitelist`） |
| 无风险结果 | 可能 Defender/补丁查询权限不足 → 以管理员身份运行 |

### 4.4 升级与回滚

- 覆盖安装即可升级（保留 AppData 数据）
- 回滚：卸载 → 安装旧版本（卸载会清空数据，注意备份）

---

## 五、安全运维

### 5.1 权限最小化

- 检测模块：只读系统状态（psutil/注册表/命令查询）
- 处置模块：需用户弹窗确认 + 白名单保护
- 后台服务：仅监听 127.0.0.1（不暴露外网）

### 5.2 数据安全

- API Key 加密存储（机器绑定，`og_enc_v1` 格式）
- 威胁情报来自权威源（ESET/URLhaus/FireHOL）
- 卸载彻底清除（无残留隐私）

### 5.3 更新机制

- 威胁情报自动更新：每 6 小时（URLhaus/FireHOL/ESET/AlienVault）
- 应用更新检查：启动时后台异步
- WSC 注册：向 Windows 安全中心注册（需管理员，失败不阻塞）

---

## 六、性能基线（实测）

| 指标 | 基线 |
|---|---|
| 启动时间 | ~5s |
| 全量检测 | 11.7s |
| 资源采样 | 每 5s，占用 <1% CPU |
| 内存占用 | ~53MB |
| SSE 首 token | 1.2s |
| 知识库更新 | 6h 周期，~10s/次 |

---

## 七、版本记录

| 版本 | 要点 |
|---|---|
| 0.5.8 | 基础版：5 类检测 + 3 智能体 + 打包 |
| 0.7.0 | 增强版：7 类并行检测 + 验证流水线 + 25 家 LLM + RAG 教育 + 加密存储 |

---

*运维就绪，可部署至竞赛演示环境。*
