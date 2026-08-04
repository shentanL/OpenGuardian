"""MITRE ATT&CK 映射 —— 风险类型 → 战术 + 技术编号。

参考: MITRE ATT&CK Matrix for Enterprise v16 (2025-2026)
战术阶段: Recon → ResourceDev → InitialAccess → Execution → Persistence →
  PrivEsc → DefenseEvasion → CredAccess → Discovery → LateralMovement →
  Collection → C2 → Exfiltration → Impact

映射原则:
- 每种风险类型对应 1 个主要战术(TA) + 1 个主要技术(T)
- 技术编号优先精确子技术（如 T1053.005 计划任务）
- 未覆盖的类型返回 "Ungrouped"
"""

ATTACK_MAP: dict[str, dict] = {
    # ═══ 进程检测 ═══
    "process": {
        "tactic": {"id": "TA0002", "name": "Execution"},
        "technique": {"id": "T1204", "name": "User Execution"},
        "summary": "可疑进程执行——可能是用户无意中运行了恶意软件",
        "mitigation": "使用应用白名单（AppLocker/WDAC），不运行来源不明的程序",
    },
    "malware_hash": {
        "tactic": {"id": "TA0002", "name": "Execution"},
        "technique": {"id": "T1204", "name": "User Execution"},
        "summary": "进程哈希命中已知恶意软件签名库",
        "mitigation": "立即终止进程，全盘扫描，检查启动项和计划任务",
    },

    # ═══ 网络检测 ═══
    "malicious_ip": {
        "tactic": {"id": "TA0011", "name": "Command and Control"},
        "technique": {"id": "T1071", "name": "Application Layer Protocol"},
        "summary": "连接到已知恶意 IP——可能是 C2 通信或数据渗出",
        "mitigation": "防火墙封禁该 IP 出站流量，检查发起连接的进程",
    },
    "malicious_domain": {
        "tactic": {"id": "TA0011", "name": "Command and Control"},
        "technique": {"id": "T1071", "name": "Application Layer Protocol"},
        "summary": "DNS 请求已知恶意域名——C2 信标/钓鱼下载",
        "mitigation": "DNS 层面封禁域名，检查浏览器下载记录",
    },
    "network": {
        "tactic": {"id": "TA0011", "name": "Command and Control"},
        "technique": {"id": "T1071", "name": "Application Layer Protocol"},
        "summary": "异常外联连接——可能是 C2 通信或数据渗出",
        "mitigation": "检查防火墙规则，审计外连进程",
    },

    # ═══ 漏洞检测 ═══
    "vuln_patch": {
        "tactic": {"id": "TA0001", "name": "Initial Access"},
        "technique": {"id": "T1190", "name": "Exploit Public-Facing Application"},
        "summary": "系统补丁不足——未修复的已知漏洞可被直接利用入侵",
        "mitigation": "打开 Windows Update 安装所有重要/可选更新",
    },
    "vuln_smb1": {
        "tactic": {"id": "TA0008", "name": "Lateral Movement"},
        "technique": {"id": "T1021", "name": "Remote Services", "sub": "T1021.002 SMB/Windows Admin Shares"},
        "summary": "SMBv1 协议启用——永恒之蓝(MS17-010)/WannaCry 的攻击入口",
        "mitigation": "以管理员运行: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
    },
    "vuln_firewall": {
        "tactic": {"id": "TA0005", "name": "Defense Evasion"},
        "technique": {"id": "T1562", "name": "Impair Defenses", "sub": "T1562.004 Disable System Firewall"},
        "summary": "防火墙处于禁用或非活动状态——攻击者可自由进出网络",
        "mitigation": "打开 Windows 防火墙/第三方防火墙，开启入站+出站规则",
    },
    "vuln_guest": {
        "tactic": {"id": "TA0003", "name": "Persistence"},
        "technique": {"id": "T1136", "name": "Create Account", "sub": "T1136.001 Local Account"},
        "summary": "Guest 账户已启用——攻击者可匿名访问系统",
        "mitigation": "以管理员运行: net user guest /active:no",
    },
    "vuln_uac": {
        "tactic": {"id": "TA0005", "name": "Defense Evasion"},
        "technique": {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "sub": "T1548.002 Bypass UAC"},
        "summary": "UAC 已禁用——恶意软件无需弹窗即可提权",
        "mitigation": "控制面板→用户账户→更改UAC设置→拉到最高",
    },
    "vuln_share": {
        "tactic": {"id": "TA0008", "name": "Lateral Movement"},
        "technique": {"id": "T1021", "name": "Remote Services", "sub": "T1021.002 SMB/Windows Admin Shares"},
        "summary": "发现可疑网络共享权限——可能被用于横向移动",
        "mitigation": "检查共享文件夹权限，关闭不必要共享",
    },
    "vuln_autorun": {
        "tactic": {"id": "TA0003", "name": "Persistence"},
        "technique": {"id": "T1547", "name": "Boot or Logon Autostart Execution", "sub": "T1547.001 Registry Run Keys / Startup Folder"},
        "summary": "发现可疑自启动项——恶意软件常用于开机自启持久化",
        "mitigation": "运行 msconfig → 启动 → 禁用可疑项；检查注册表 Run 键",
    },
    "vuln_hosts": {
        "tactic": {"id": "TA0005", "name": "Defense Evasion"},
        "technique": {"id": "T1562", "name": "Impair Defenses"},
        "summary": "HOSTS 文件被劫持——DNS 流量可被重定向到钓鱼站点",
        "mitigation": "以管理员编辑 C:\\Windows\\System32\\drivers\\etc\\hosts 恢复默认",
    },
    "vuln_task": {
        "tactic": {"id": "TA0003", "name": "Persistence"},
        "technique": {"id": "T1053", "name": "Scheduled Task/Job", "sub": "T1053.005 Scheduled Task"},
        "summary": "发现可疑计划任务——APT 和勒索软件常通过计划任务维持持久化",
        "mitigation": "运行 taskschd.msc 禁用可疑任务；或 schtasks /Delete 删除",
    },
    "vuln_wmi": {
        "tactic": {"id": "TA0003", "name": "Persistence"},
        "technique": {"id": "T1546", "name": "Event Triggered Execution", "sub": "T1546.003 WMI Event Subscription"},
        "summary": "发现 WMI 事件订阅——高级 APT 常用无文件持久化技术",
        "mitigation": "以管理员 PowerShell 清理 WMI 订阅",
    },
    "vuln_cve": {
        "tactic": {"id": "TA0001", "name": "Initial Access"},
        "technique": {"id": "T1190", "name": "Exploit Public-Facing Application"},
        "summary": "检测到已知 CVE 漏洞的可利用版本——需紧急更新",
        "mitigation": "立即更新受影响的软件到最新版本",
    },

    # ═══ Defender ═══
    "defender": {
        "tactic": {"id": "TA0005", "name": "Defense Evasion"},
        "technique": {"id": "T1562", "name": "Impair Defenses", "sub": "T1562.001 Disable or Modify Tools"},
        "summary": "Windows Defender 未启用——系统失去第一道防线",
        "mitigation": "设置→更新和安全→Windows安全中心→打开实时保护",
    },

    # ═══ 系统更新 ═══
    "updates": {
        "tactic": {"id": "TA0001", "name": "Initial Access"},
        "technique": {"id": "T1190", "name": "Exploit Public-Facing Application"},
        "summary": "系统补丁极少——大量已知漏洞等待攻击者利用",
        "mitigation": "Windows Update 安装所有补丁，开启自动更新",
    },

    # ═══ 风险服务 ═══
    "services": {
        "tactic": {"id": "TA0005", "name": "Defense Evasion"},
        "technique": {"id": "T1562", "name": "Impair Defenses"},
        "summary": "高危系统服务已启用——攻击者常用作跳板",
        "mitigation": "禁用不必要的服务: sc config <服务名> start=disabled",
    },

    # ═══ 资源 ═══
    "resource": {
        "tactic": {"id": "TA0040", "name": "Impact"},
        "technique": {"id": "T1498", "name": "Network Denial of Service"},
        "summary": "系统资源异常消耗——可能是加密货币挖矿或DDoS代理",
        "mitigation": "定位高占用进程，检查是否为合法软件",
    },

    # ═══ 资产/账户 ═══
    "asset": {
        "tactic": {"id": "TA0006", "name": "Credential Access"},
        "technique": {"id": "T1110", "name": "Brute Force"},
        "summary": "账户安全配置不足——密码策略弱，存在暴力破解/凭据窃取风险",
        "mitigation": "启用强密码策略(≥8位)，限制登录尝试次数，开启账户锁定",
    },
}

# 通用默认值（无匹配类型时回退）
FALLBACK_ATTACK = {
    "tactic": {"id": "TA9999", "name": "Ungrouped"},
    "technique": {"id": "T9999", "name": "Ungrouped"},
    "summary": "未归类的安全风险",
    "mitigation": "按修复建议操作",
}


def get_attack(item_type: str) -> dict:
    """根据风险类型返回 MITRE ATT&CK 映射。"""
    return ATTACK_MAP.get(item_type, FALLBACK_ATTACK)


def get_tactic_display(item_type: str) -> str:
    """返回战术的简短展示字符串（如 TA0002 Execution）。"""
    a = ATTACK_MAP.get(item_type, FALLBACK_ATTACK)
    t = a["tactic"]
    return f"{t['id']} {t['name']}"


def get_technique_display(item_type: str) -> str:
    """返回技术的简短展示字符串（如 T1204 User Execution）。"""
    a = ATTACK_MAP.get(item_type, FALLBACK_ATTACK)
    t = a["technique"]
    sub = t.get("sub", "")
    return f"{sub or t['id']} {t['name']}"
