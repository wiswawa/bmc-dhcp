#!/usr/bin/env python3
"""Build the self-contained Windows x64 GUI/CLI ZIP on Windows."""

from __future__ import annotations

import hashlib
from pathlib import Path
import platform
import runpy
import shutil
import subprocess
import sys
import zipfile

from bundle_licenses import collect_licenses
from check_release import check
from source_manifest import ROOT


def main() -> int:
    if sys.platform != "win32" or platform.machine().lower() not in ("amd64", "x86_64"):
        raise SystemExit("Build this package on Windows x64 (or the Windows GitHub Actions runner).")
    errors = check()
    if errors:
        raise SystemExit("\n".join(errors))
    version = runpy.run_path(str(ROOT / "src/bmcdhcp/__init__.py"))["__version__"]
    build = ROOT / "build/windows"
    build.mkdir(parents=True, exist_ok=True)
    subprocess.run([sys.executable, str(ROOT / "tools/make_icon.py"), str(build / "AppIcon.iconset")], check=True)
    from PIL import Image
    with Image.open(build / "AppIcon.iconset/icon_256x256.png") as icon:
        icon.save(build / "AppIcon.ico", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
                    "--distpath", str(build / "frozen"), "--workpath", str(build / "pyinstaller"),
                    str(ROOT / "windows/runtime.spec")], cwd=ROOT, check=True)
    package = build / "frozen/BMC DHCP"
    for name in ("BMC DHCP.exe", "bmcd.exe", "_internal/bmcdhcp/ui/index.html"):
        if not (package / name).is_file():
            raise RuntimeError(f"Missing Windows package component: {name}")
    resources = package / "Resources"
    resources.mkdir()
    collect_licenses(resources, build / "native-binaries.toc", version)
    for name in ("WIN-README.md", "LICENSE", "THIRD_PARTY_NOTICES.md"):
        shutil.copy2(ROOT / name, package / name)
    archive = ROOT / "dist" / f"BMC-DHCP-{version}-Windows-x64.zip"
    archive.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
        for path in sorted(package.rglob("*")):
            if path.is_file():
                output.write(path, "BMC DHCP/" + path.relative_to(package).as_posix())
    Path(str(archive) + ".sha256").write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + archive.name + "\n")
    print(f"Windows x64 application: {archive.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
