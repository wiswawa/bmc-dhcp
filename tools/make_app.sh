#!/bin/bash
# 构建随包运行时 + 原生 WKWebView 窗口，不启动 DHCP、不改网口。
set -euo pipefail
TASK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TASK_PYTHON="${BMCD_BUILD_PYTHON:-$TASK_ROOT/.mac-build-venv/bin/python}"
if [ ! -x "$TASK_PYTHON" ]; then
  printf '%s\n' '请先创建构建环境：' \
    'python3 -m venv .mac-build-venv' \
    '.mac-build-venv/bin/python -m pip install -r requirements-macos-build.txt' >&2
  exit 1
fi
exec "$TASK_PYTHON" "$TASK_ROOT/tools/build_macos.py" "$@"
