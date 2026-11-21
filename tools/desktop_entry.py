"""打包后的唯一 Python 入口；桌面启动器和 DHCP 后台使用相同运行时。"""

import sys

import app
from bmcdhcp import cli


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--backend":
        del sys.argv[1]
        return cli.main()
    return app.main()


if __name__ == "__main__":
    raise SystemExit(main())
