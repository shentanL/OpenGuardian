# OpenGuardian 开发命令（canonical 入口）
# 用法: make test / make run / make db / make clean
PY ?= cd backend && .venv/Scripts/python.exe

.PHONY: test run db clean

## 运行完整测试套件（单元 + API 集成）
test:
	$(PY) -m unittest discover -s tests -p "test_*.py"

## 启动服务（端口 8300）
run:
	cd backend && .venv/Scripts/python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8300

## 查看 SQLite 数据库
db:
	cd backend && .venv/Scripts/python.exe -c "import sqlite3; c=sqlite3.connect('openguardian.db'); [print(r) for r in c.execute('SELECT name FROM sqlite_master WHERE type=\'table\'')]"

## 清理缓存与临时文件
clean:
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null; rm -rf backend/kb_data/firehol_extract
