"""Windowed executable entry point; requests UAC only for the backend."""

import sys
import traceback

import app_win


def main() -> int:
    if "--verify-package" in sys.argv:
        return 3 if app_win.missing_package_files() else 0
    try:
        return app_win.main()
    except BaseException:
        detail = traceback.format_exc()
        app_win.launcher_log(detail)
        app_win._box("BMC DHCP 启动失败，请查看 launcher.log。\n\n" + detail[-1500:])
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
