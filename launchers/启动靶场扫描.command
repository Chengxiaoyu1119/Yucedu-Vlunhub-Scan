#!/bin/bash
# 靶场扫描助手 · 双击启动器
# 双击本文件即可启动图形界面（无需打开终端敲命令）
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3 || true)}"
if [ -z "$PYTHON_BIN" ]; then
  printf '%s\n' '未找到 python3，请先安装 Python 3。' >&2
  exit 1
fi
nohup "$PYTHON_BIN" -m scanner_app.desktop.gui >/dev/null 2>&1 &
disown
exit 0
