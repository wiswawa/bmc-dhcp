#!/usr/bin/env python3
"""Verify the shipped ZIP without Python dependencies or privileged NIC changes."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import plistlib
import platform
import runpy
import subprocess
import sys
import tempfile
import tarfile
import time
from urllib.error import URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
HTTP = build_opener(ProxyHandler({}))


def main() -> int:
    version = runpy.run_path(str(ROOT / "src/bmcdhcp/__init__.py"))["__version__"]
    archive = (Path(sys.argv[1]) if len(sys.argv) > 1 else
               ROOT / "dist" / f"BMC-DHCP-{version}-macOS-{platform.machine()}.zip")
    if not archive.is_file():
        raise SystemExit(f"Build the requested release archive first: {archive.name}")
    with tempfile.TemporaryDirectory(prefix="bmcd-package-") as temp:
        root = Path(temp)
        relocated = root / "移动后的应用 with spaces"
        relocated.mkdir()
        subprocess.run(["/usr/bin/ditto", "-x", "-k", str(archive), str(relocated)], check=True)
        app = relocated / "BMC DHCP.app"
        subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)], check=True)
        print("[PASS] ZIP 解压、移动路径及完整签名", flush=True)
        info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
        assert info["CFBundleShortVersionString"] == version
        resources = app / "Contents/Resources"
        inventory = json.loads((resources / "DEPENDENCIES.json").read_text())
        assert inventory["application"]["version"] == version
        for source in (inventory["scapySource"], inventory["projectSource"]):
            path = resources / "Sources" / source["filename"]
            assert hashlib.sha256(path.read_bytes()).hexdigest() == source["sha256"]
        assert "GNU GENERAL PUBLIC LICENSE" in (resources / "Licenses/LICENSE").read_text()
        for component in inventory["buildDependencies"] + inventory["nativeLibraries"]:
            for path in component["licenseFiles"]:
                assert (resources / path).is_file(), path
        with tarfile.open(resources / "Sources" / inventory["projectSource"]["filename"]) as source:
            names = source.getnames()
            assert any(name.endswith("/macos/Desktop.swift") for name in names)
            assert not any(part in ("eval", "validation", "build", ".venv")
                           for name in names for part in Path(name).parts)
        print("[PASS] GPL 文本、对应项目/Scapy 源码摘要和依赖许可证完整", flush=True)
        runtime = app / "Contents/Resources/backend/bmcd-runtime"
        home = root / "test-home"
        home.mkdir()
        env = dict(os.environ, BMCD_HOME=str(home), BMCD_SESSION_FILE=str(home / ".bmcd/web.json"),
                   PATH="/usr/bin:/bin:/usr/sbin:/sbin", http_proxy="http://127.0.0.1:1",
                   HTTP_PROXY="http://127.0.0.1:1", no_proxy="", NO_PROXY="")
        for key in ("PYTHONPATH", "PYTHONHOME", "BMCD_TOKEN"):
            env.pop(key, None)
        result = subprocess.run([str(runtime), "--backend", "selftest"], env=env,
                                cwd=root, capture_output=True, text=True, timeout=60, check=True)
        print(result.stdout, flush=True)
        print("[PASS] 随包 Python/协议/真实环回 DORA/Session 自检", flush=True)
        result = subprocess.run([str(runtime), "--backend", "--version"], env=env,
                                cwd=root, capture_output=True, text=True, timeout=10, check=True)
        assert result.stdout.strip() == f"bmcd {version}", result.stdout

        result = subprocess.run([str(runtime), "--gui", "none", "--no-elevate", "--keep"], env=env,
                                cwd=root, capture_output=True, text=True, timeout=45, check=True)
        urls = [line for line in result.stdout.splitlines() if line.startswith("http://127.0.0.1:")]
        assert urls, "Launcher did not return a session URL"
        url = urls[-1]
        parsed = urlsplit(url)
        token = parse_qs(parsed.query)["t"][0]
        base = f"http://127.0.0.1:{parsed.port}"

        def request(path: str, method: str = "GET"):
            req = Request(base + path, data=b"{}" if method == "POST" else None,
                          headers={"X-BMCD-Token": token, "Content-Type": "application/json"},
                          method=method)
            with HTTP.open(req, timeout=15) as resp:
                return resp.read()

        try:
            ping = json.loads(request("/api/ping"))
            assert ping["version"] == info["CFBundleShortVersionString"]
            state = json.loads(request("/api/state"))
            assert state["state"] == "idle", state
            html = request("/").decode()
            assert "bmcdDesktop" in html and "启动服务" in html
            diag = json.loads(request("/api/diag"))
            assert diag["capabilities"]["scapy"], diag
            print("[PASS] 无 Homebrew/Python PATH、错误代理下启动；界面资源、令牌 API、scapy 正常", flush=True)
            request("/api/quit", "POST")
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                try:
                    request("/api/ping")
                except (URLError, OSError):
                    break
                time.sleep(0.1)
            else:
                raise AssertionError("Backend stayed alive after quit")
            print("[PASS] 退出请求关闭随包后台", flush=True)
        finally:
            try:
                request("/api/quit", "POST")
            except (URLError, OSError):
                pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
