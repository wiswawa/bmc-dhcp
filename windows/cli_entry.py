"""Console/backend executable entry point for a self-contained Windows build."""

import sys


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
    if len(sys.argv) == 3 and sys.argv[1] == "--desktop-backend":
        from bmcdhcp.win_desktop import run_backend
        return run_backend(sys.argv[2])
    from bmcdhcp.cli import main as cli_main
    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
