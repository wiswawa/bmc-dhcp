#!/usr/bin/env python3
"""Run the packaged Windows executables outside the checkout, without UAC/NIC changes."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import time
from urllib.error import URLError
from urllib.request import ProxyHandler, Request, build_opener
import zipfile

from source_manifest import ROOT


def main() -> int:
    if sys.platform != "win32":
        raise SystemExit("The executable smoke check must run on Windows.")
    version = runpy.run_path(str(ROOT / "src/bmcdhcp/__init__.py"))["__version__"]
    archive = ROOT / "dist" / f"BMC-DHCP-{version}-Windows-x64.zip"
    http = build_opener(ProxyHandler({}))
    with tempfile.TemporaryDirectory(prefix="bmcd-win-package-") as temporary:
        root = Path(temporary)
        relocated = root / "relocated application with spaces"
        with zipfile.ZipFile(archive) as source:
            assert source.testzip() is None
            source.extractall(relocated)
        app = relocated / "BMC DHCP"
        runtime = app / "bmcd.exe"
        gui = app / "BMC DHCP.exe"
        for executable in (runtime, gui):
            assert executable.read_bytes()[:2] == b"MZ"
        inventory = json.loads((app / "Resources/DEPENDENCIES.json").read_text())
        assert inventory["application"]["version"] == version
        for item in (inventory["scapySource"], inventory["projectSource"]):
            assert hashlib.sha256((app / "Resources/Sources" / item["filename"]).read_bytes()).hexdigest() == item["sha256"]
        home = root / "home"
        home.mkdir()
        env = dict(os.environ, BMCD_HOME=str(home), BMCD_SESSION_FILE=str(home / "session.json"),
                   PATH=os.environ["SystemRoot"] + "\\System32", PYTHONUTF8="1")
        for name in ("PYTHONHOME", "PYTHONPATH"):
            env.pop(name, None)
        flags = subprocess.CREATE_NO_WINDOW
        for arguments in ([str(gui), "--verify-package"], [str(runtime), "--version"], [str(runtime), "selftest"]):
            result = subprocess.run(arguments, cwd=root, env=env, creationflags=flags,
                                    capture_output=True, text=True, encoding="utf-8", timeout=60, check=True)
            print(result.stdout)
        config = root / "backend.json"
        token = "windows-package-smoke-test"
        session_path = home / "session.json"
        config.write_text(json.dumps({"token": token, "home": str(home), "session": str(session_path),
                                      "fallback": str(home / "fallback.json"), "log": str(home / "backend.log")}), encoding="utf-8")
        process = subprocess.Popen([str(runtime), "--desktop-backend", str(config)], cwd=root, env=env,
                                   creationflags=flags, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        base = ""
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError((home / "backend.log").read_text(encoding="utf-8"))
                if session_path.exists():
                    try:
                        state = json.loads(session_path.read_text(encoding="utf-8"))
                        base = f"http://127.0.0.1:{state['port']}"
                        break
                    except (OSError, ValueError, KeyError):
                        pass
                time.sleep(0.1)
            assert base and not config.exists()
            def request(path, post=False):
                req = Request(base + path, data=b"{}" if post else None,
                              headers={"Content-Type": "application/json", "X-BMCD-Token": token},
                              method="POST" if post else "GET")
                with http.open(req, timeout=10) as response:
                    return response.read()
            assert json.loads(request("/api/ping"))["version"] == version
            assert json.loads(request("/api/state"))["state"] == "idle"
            assert b"bmcdDesktop" in request("/")
            assert json.loads(request("/api/diag"))["capabilities"]["scapy"]
            request("/api/quit", True)
            assert process.wait(timeout=20) == 0
            print("Windows EXE, relocated runtime, DORA, resources, backend API and shutdown: PASS")
        finally:
            if process.poll() is None:
                try:
                    if base:
                        with http.open(Request(base + "/api/quit", data=b"{}", headers={"X-BMCD-Token": token}, method="POST"), timeout=3):
                            pass
                    process.wait(timeout=10)
                except (URLError, OSError, subprocess.TimeoutExpired):
                    process.kill()
                    process.wait()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
