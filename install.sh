#!/usr/bin/env bash
# 可选：把 bmcd 装成全局命令，并预装 scapy。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$HERE/.venv"

pick_python() {
  local c
  for c in /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
    [ -x "$c" ] && { printf '%s' "$c"; return 0; }
  done
  command -v python3
}

PY="$(pick_python)"
echo "==> python: $PY ($("$PY" -V 2>&1))"

if [ ! -x "$VENV/bin/python" ]; then
  echo "==> 创建 venv: $VENV"
  "$PY" -m venv "$VENV"
fi

echo "==> 安装依赖（scapy 用于 raw 引擎，pillow 只用来画图标）"
"$VENV/bin/pip" -q install --disable-pip-version-check "scapy>=2.5" "pillow>=10" \
  && echo "    scapy $(  "$VENV/bin/python" -c 'import scapy;print(scapy.__version__)')"

echo "==> 生成图形界面 App"
if "$VENV/bin/python" -m pip -q install --disable-pip-version-check -r "$HERE/requirements-macos-build.txt"; then
  BMCD_BUILD_PYTHON="$VENV/bin/python" "$HERE/tools/make_app.sh" || echo "    .app 生成失败（不影响命令行使用）"
else
  echo "    构建依赖安装失败，跳过 App（不影响命令行使用）"
fi

if [ -w /usr/local/bin ]; then
  ln -sf "$HERE/bmcd" /usr/local/bin/bmcd
  echo "==> 已链接 /usr/local/bin/bmcd"
else
  echo "==> /usr/local/bin 不可写，跳过全局命令"
  echo "    想全局使用可以执行：sudo ln -sf '$HERE/bmcd' /usr/local/bin/bmcd"
fi

chmod +x "$HERE/bmcd"
echo
echo "==> 自检"
"$HERE/bmcd" selftest
echo
echo "完成。用法：./bmcd   （或 bmcd）"
