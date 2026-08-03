"""OpenGuardian 配置模块。

所有配置优先从环境变量读取，其次 .env 文件，最后内置默认值。
"""
import os
from pathlib import Path

from dotenv import load_dotenv

# 加载 backend/.env（若存在）
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


class Settings:
    # ---- LLM ----
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "deepseek")
    DEEPSEEK_API_KEY: str = os.getenv("DEEPSEEK_API_KEY", "")
    DEEPSEEK_BASE_URL: str = os.getenv(
        "DEEPSEEK_BASE_URL", "https://api.deepseek.com/anthropic"
    )
    LLM_MODEL: str = os.getenv("LLM_MODEL", "deepseek-v4-pro")
    LLM_TIMEOUT: float = float(os.getenv("LLM_TIMEOUT", "30"))
    LLM_MAX_TOKENS: int = int(os.getenv("LLM_MAX_TOKENS", "2048"))

    # ---- 服务 ----
    APP_NAME: str = "OpenGuardian"
    APP_VERSION: str = "0.5.8"
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8000"))

    # ---- 检测 ----
    CPU_ALERT_PCT: float = float(os.getenv("CPU_ALERT_PCT", "85"))
    MEM_ALERT_PCT: float = float(os.getenv("MEM_ALERT_PCT", "85"))
    DISK_ALERT_PCT: float = float(os.getenv("DISK_ALERT_PCT", "90"))
    SCAN_TIMEOUT: float = float(os.getenv("SCAN_TIMEOUT", "15"))

    # ---- 数据库 ----
    DB_PATH: Path = BASE_DIR / "openguardian.db"


settings = Settings()
