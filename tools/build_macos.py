#!/usr/bin/env python3
"""Build a relocatable native Mac app; never modifies network configuration."""

from __future__ import annotations

import argparse
import hashlib
from importlib.metadata import version as dependency_version
from pathlib import Path
import platform
import plistlib
import runpy
import shutil
import subprocess
import sys

from bundle_licenses import collect_licenses
from check_release import check

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build" / "macos"


def run(*args: object) -> None:
    subprocess.run([str(arg) for arg in args], cwd=ROOT, check=True)


def backend_source_id() -> str:
    digest = hashlib.sha256(sys.version.encode())
    paths = [ROOT / "app.py", ROOT / "tools/desktop_entry.py", ROOT / "requirements-macos-build.txt"]
    paths.extend(path for path in (ROOT / "src/bmcdhcp").rglob("*")
                 if path.is_file() and path.suffix in (".py", ".html"))
    for path in sorted(paths):
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(path.read_bytes())
    for name in ("pyinstaller", "scapy", "pillow"):
        digest.update(f"{name}={dependency_version(name)}".encode())
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-freeze", action="store_true",
                        help="Reuse the last frozen backend when only changing Swift or docs")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("This build requires macOS and Xcode Command Line Tools")
    errors = check()
    if errors:
        parser.error("Release preparation checks failed:\n" + "\n".join(errors))
    for dependency in ("PyInstaller", "scapy", "PIL"):
        __import__(dependency)
    version = runpy.run_path(str(ROOT / "src/bmcdhcp/__init__.py"))["__version__"]
    arch = platform.machine()
    BUILD.mkdir(parents=True, exist_ok=True)
    backend = BUILD / "frozen" / "bmcd-runtime"
    source_id = backend_source_id()
    source_id_path = backend / "source-id.txt"
    if args.skip_freeze and (not source_id_path.exists() or source_id_path.read_text().strip() != source_id):
        parser.error("Backend inputs changed or have no fingerprint; rebuild without --skip-freeze")
    if not args.skip_freeze:
        run(sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir",
            "--name", "bmcd-runtime", "--distpath", BUILD / "frozen",
            "--workpath", BUILD / "pyinstaller", "--specpath", BUILD,
            "--paths", ROOT, "--paths", ROOT / "src",
            "--collect-all", "scapy", "--add-data", f"{ROOT / 'src/bmcdhcp/ui'}:bmcdhcp/ui",
            ROOT / "tools/desktop_entry.py")
        source_id_path.write_text(source_id + "\n")
    if not (backend / "bmcd-runtime").is_file():
        parser.error("No frozen backend; rebuild without --skip-freeze")
    identity = hashlib.sha256()
    for path in sorted(backend.rglob("*")):
        if path.name == "build-id.txt":
            continue
        if path.is_file() or path.is_symlink():
            identity.update(str(path.relative_to(backend)).encode())
            identity.update(str(path.readlink()).encode() if path.is_symlink() else path.read_bytes())
    (backend / "build-id.txt").write_text(identity.hexdigest() + "\n")

    staging = BUILD / "BMC DHCP.app"
    if staging.exists():
        shutil.rmtree(staging)
    contents = staging / "Contents"
    resources = contents / "Resources"
    (contents / "MacOS").mkdir(parents=True)
    resources.mkdir()
    shutil.copytree(backend, resources / "backend", symlinks=True)
    icon = ROOT / "build/AppIcon.icns"
    if not icon.exists():
        run(sys.executable, ROOT / "tools/make_icon.py", ROOT / "build/AppIcon.iconset")
        run("/usr/bin/iconutil", "-c", "icns", ROOT / "build/AppIcon.iconset", "-o", icon)
    shutil.copy2(icon, resources / "AppIcon.icns")
    docs = resources / "Docs"
    docs.mkdir()
    for name in ("PROJECT.md", "QUICKSTART.md", "VALIDATION.md"):
        source = ROOT / "docs" / name
        if source.exists():
            shutil.copy2(source, docs / name)
    for name in ("screenshot-macos.png",):
        source = ROOT / "docs" / name
        if source.is_dir():
            shutil.copytree(source, docs / name)
        elif source.is_file():
            shutil.copy2(source, docs / name)
    collect_licenses(resources, BUILD / "pyinstaller/bmcd-runtime/Analysis-00.toc", version)

    info = {
        "CFBundleName": "BMC DHCP", "CFBundleDisplayName": "BMC DHCP",
        "CFBundleIdentifier": "local.bmcdhcp.app", "CFBundleExecutable": "BMCDHCP",
        "CFBundleIconFile": "AppIcon", "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": version, "CFBundleVersion": version,
        "CFBundleInfoDictionaryVersion": "6.0", "LSMinimumSystemVersion": "13.0",
        "NSHighResolutionCapable": True,
        "LSApplicationCategoryType": "public.app-category.utilities",
        "NSLocalNetworkUsageDescription": "在所选以太网口为直连 BMC 提供临时 DHCP 并识别管理页面。",
        "NSAppTransportSecurity": {"NSAllowsLocalNetworking": True},
        "NSHumanReadableCopyright": "本地工具 · 给 BMC 分配临时 DHCP 地址",
    }
    with (contents / "Info.plist").open("wb") as fh:
        plistlib.dump(info, fh, sort_keys=False)
    (contents / "PkgInfo").write_bytes(b"APPL????")
    run("/usr/bin/swiftc", "-O", "-parse-as-library", "-swift-version", "5", "-target", f"{arch}-apple-macosx13.0",
        "-framework", "AppKit", "-framework", "WebKit", ROOT / "macos/Desktop.swift",
        "-o", contents / "MacOS/BMCDHCP")
    run("/usr/bin/codesign", "--force", "--deep", "--sign", "-", staging)
    run("/usr/bin/codesign", "--verify", "--deep", "--strict", staging)

    app = ROOT / "BMC DHCP.app"
    previous = BUILD / "previous.app"
    if previous.exists():
        shutil.rmtree(previous)
    if app.exists():
        app.rename(previous)
    try:
        staging.rename(app)
    except OSError:
        if previous.exists():
            previous.rename(app)
        raise
    if previous.exists():
        shutil.rmtree(previous)
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    archive = dist / f"BMC-DHCP-{version}-macOS-{arch}.zip"
    run("/usr/bin/ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", app, archive)
    checksum = archive.with_suffix(archive.suffix + ".sha256")
    checksum.write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + archive.name + "\n")
    print(f"App: {app}\nZIP: {archive}\nSHA256: {checksum}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
