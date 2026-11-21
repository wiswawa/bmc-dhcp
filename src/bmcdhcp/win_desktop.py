"""Runtime bridge for the frozen Windows desktop and console executables."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile

from .stateio import atomic_write_json


def write_config(directory: str, *, token: str, home: str, session: str,
                 fallback: str, log: str) -> str:
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix="backend-", suffix=".json", dir=root)
    os.close(descriptor)
    try:
        atomic_write_json(name, {"token": token, "home": home, "session": session,
                                "fallback": fallback, "log": log})
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise
    return name


def run_backend(config_path: str) -> int:
    path = Path(config_path)
    try:
        if path.stat().st_size > 64 * 1024:
            raise ValueError("Desktop startup configuration is too large")
        config = json.loads(path.read_text(encoding="utf-8"))
        for field in ("token", "home", "session", "fallback", "log"):
            if not isinstance(config.get(field), str) or not config[field]:
                raise ValueError(f"Missing desktop startup field: {field}")
    finally:
        path.unlink(missing_ok=True)
    for field, name in (("token", "BMCD_TOKEN"), ("home", "BMCD_HOME"),
                        ("session", "BMCD_SESSION_FILE"), ("fallback", "BMCD_SESSION_FALLBACK")):
        os.environ[name] = config[field]
    os.environ["BMCD_DESKTOP"] = "1"
    logfile = Path(config["log"])
    logfile.parent.mkdir(parents=True, exist_ok=True)
    with logfile.open("a", encoding="utf-8", buffering=1) as log:
        old_stdout, old_stderr = sys.stdout, sys.stderr
        sys.stdout = sys.stderr = log
        try:
            # Import only after the user's home/session overrides are installed.
            from . import webapp
            return webapp.main(host="127.0.0.1", port=0, token=config["token"])
        except BaseException:
            import traceback
            traceback.print_exc()
            return 1
        finally:
            sys.stdout, sys.stderr = old_stdout, old_stderr
