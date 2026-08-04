"""OpenGuardian 配置模块。

所有配置优先从环境变量读取，其次 .env 文件，最后内置默认值。
"""
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

# 加载 backend/.env（若存在）
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

# PyInstaller frozen：资源在 _MEIPASS，但可写数据必须在 AppData
if getattr(sys, "frozen", False):
    APP_DATA_DIR = Path.home() / "AppData" / "Local" / "OpenGuardian"
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
else:
    APP_DATA_DIR = BASE_DIR


class Settings:
    # ---- LLM ----
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "deepseek")
    DEEPSEEK_API_KEY: str = os.getenv("DEEPSEEK_API_KEY", "")
    DEEPSEEK_BASE_URL: str = os.getenv(
        "DEEPSEEK_BASE_URL", "https://api.deepseek.com"
    )
    LLM_MODEL: str = os.getenv("LLM_MODEL", "deepseek-v4-flash")
    LLM_TIMEOUT: float = float(os.getenv("LLM_TIMEOUT", "30"))
    LLM_MAX_TOKENS: int = int(os.getenv("LLM_MAX_TOKENS", "2048"))

    # ---- 服务 ----
    APP_NAME: str = "OpenGuardian"
    APP_VERSION: str = "0.7.0"
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8300"))

    # ---- 检测 ----
    CPU_ALERT_PCT: float = float(os.getenv("CPU_ALERT_PCT", "85"))
    MEM_ALERT_PCT: float = float(os.getenv("MEM_ALERT_PCT", "85"))
    DISK_ALERT_PCT: float = float(os.getenv("DISK_ALERT_PCT", "90"))
    SCAN_TIMEOUT: float = float(os.getenv("SCAN_TIMEOUT", "15"))

    # ---- 数据库（frozen → AppData，源码 → backend/）----
    DB_PATH: Path = APP_DATA_DIR / "openguardian.db"


settings = Settings()
