# OpenGuardian 架构设计文档

> 版本：v0.1（2026-08-02）· 状态：MVP 基线

## 1. 总体设计

### 1.1 设计原则

1. **单一闭环优先**：先跑通"提问→检测→解释→处置"最小闭环，再横向扩展功能。
2. **Agent 可插拔**：5 个 Agent 实现统一基类接口，通过消息总线路由，互不耦合。
3. **LLM 可降级**：所有 LLM 调用带本地规则兜底（关键词匹配），API 不可用时系统仍可回答基础问题。
4. **安全合规**：所有处置操作必须用户二次确认，白名单进程永不处置。

### 1.2 核心处理链路

```
用户输入
  → Consultant Agent（意图识别）
      ├─ 咨询意图 → LLM 生成通俗解答 → 回复
      ├─ 检测意图 → 调度 Detector Agent → 风险清单 → LLM 通俗化 → 回复
      ├─ 处置意图 → 调度 Executor Agent（白名单校验 + 用户确认）→ 执行 → 回复
      ├─ 资产意图 → 调度 Analyst Agent → 资产报告 → 回复
      └─ 教育意图 → 调度 Educator Agent → 案例讲解 → 回复
```

## 2. 模块设计

### 2.1 消息总线（bus.py）

- 职责：注册 Agent、按意图分发任务、收集结果
- 接口：
  ```python
  bus = MessageBus()
  bus.register("detect", DetectorAgent())
  result = bus.dispatch("detect", task)
  ```

### 2.2 Agent 基类（agents/base.py）

```python
class BaseAgent(abc.ABC):
    name: str                    # "consultant" / "detector" / ...
    description: str
    @abc.abstractmethod
    def handle(self, task: AgentTask) -> AgentResult: ...
```

### 2.3 五个 Agent

| Agent | 输入 | 输出 | 依赖 |
|---|---|---|---|
| Consultant | 用户消息 | 意图 + 参数 + 回复 | LLM |
| Detector | 扫描指令 | RiskItem[]（进程/网络/资源） | psutil + 特征库 |
| Analyst | 账号/文件 | 资产风险报告 | 规则库 |
| Executor | 处置指令 | 执行结果 | psutil + 白名单 |
| Educator | 话题 | 案例讲解 | LLM + 案例库 |

### 2.4 数据模型（schemas.py）

```python
class Intent(str, Enum):
    CONSULT = "consult"
    DETECT = "detect"
    EXECUTE = "execute"
    ASSET = "asset"
    EDUCATE = "educate"

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class RiskItem(BaseModel):
    item_type: str        # process / network / resource
    name: str
    detail: str
    level: RiskLevel
    suggestion: str       # 通俗建议

class AgentTask(BaseModel):
    intent: Intent
    params: dict = {}
    user_input: str = ""

class AgentResult(BaseModel):
    agent: str
    success: bool
    data: Any = None
    message: str = ""
```

## 3. LLM 集成（llm/client.py）

- 端点：`https://api.deepseek.com/anthropic`（Anthropic 兼容）或原生 `https://api.deepseek.com`
- 模型：`deepseek-v4-pro`
- 用途：
  1. **意图识别**：结构化 JSON 输出（intent + params）
  2. **通俗化解释**：风险清单 → 大白话报告
  3. **咨询/教育对话**：流式回复
- 降级策略：意图识别失败 → 关键词规则兜底（"检测/扫描/查"→detect，"杀/结束/关闭"→execute）

## 4. 检测模块（Detector Agent）

- **进程检测**：psutil.process_iter() 遍历，与特征库（恶意软件特征：已知名称/路径/签名）比对；CPU/内存占用异常告警
- **网络检测**：psutil.net_connections() 检查可疑端口（如 4444/5555 反弹shell）、未知外联
- **资源检测**：CPU/内存/磁盘使用率超过阈值 → 健康建议
- **风险分级**：特征库命中=critical/high；资源异常=medium；轻微=low
- **白名单**：系统进程（svchost 等）、用户配置名单永不标记

## 5. 前端设计（frontend/）

- 单页应用：`index.html` + `app.js` + `style.css`（零构建，FastAPI 静态托管）
- 核心：聊天窗口（流式显示）+ 风险报告卡片（分级颜色）+ 一键处置按钮
- API：
  - `POST /api/chat` — 发送消息（返回结构化结果）
  - `GET /api/health` — 健康检查
  - `POST /api/execute` — 处置确认执行

## 6. 安全与合规

1. 处置操作（结束进程等）必须：**白名单校验 → 用户二次确认 → 执行 → 记录日志**
2. 所有操作写入操作日志（audit log），便于追溯
3. API Key 只存于服务端 .env，前端不接触

## 7. 里程碑（一个月 MVP）

| 周 | 内容 | 验收标准 |
|---|---|---|
| W1 | 需求冻结 + 骨架 | 仓库可运行，Hello World |
| W2 | 咨询+检测闭环 | 问→扫→通俗报告 |
| W3 | 执行+教育+资产简化 | 全流程闭环 |
| W4 | 打包 + 文档 + 演示 | 可安装 + 三份文档 |
