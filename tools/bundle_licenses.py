"""Collect release-specific licenses, verified GPL sources and dependency inventory."""

from __future__ import annotations

import ast
import hashlib
from importlib import metadata
import json
from pathlib import Path
import platform
import shutil
import sys
import sysconfig

from source_bundle import build_source
from source_manifest import ROOT


def native_binaries(toc: Path) -> list[tuple[str, Path]]:
    result = []

    def visit(value):
        if not isinstance(value, (tuple, list)):
            return
        if len(value) == 3 and isinstance(value[2], str) and value[2] == "BINARY":
            result.append((str(value[0]), Path(value[1])))
        else:
            for child in value:
                visit(child)

    visit(ast.literal_eval(toc.read_text()))
    return result


def collect_licenses(resources: Path, toc: Path, version: str) -> None:
    licenses = resources / "Licenses"
    sources = resources / "Sources"
    licenses.mkdir()
    sources.mkdir()
    shutil.copy2(ROOT / "LICENSE", licenses / "LICENSE")
    shutil.copy2(ROOT / "THIRD_PARTY_NOTICES.md", licenses / "THIRD_PARTY_NOTICES.md")

    python_license = next((path for path in (
        Path(sysconfig.get_path("stdlib")) / "LICENSE.txt",
        Path(sys.base_prefix) / "LICENSE.txt", Path(sys.base_prefix) / "LICENSE",
    ) if path.is_file()), None)
    if python_license is None:
        raise RuntimeError("The CPython LICENSE.txt must be available to redistribute this interpreter")
    shutil.copy2(python_license, licenses / "Python.txt")
    distributions = []
    required = {"scapy", "pyinstaller", "pillow"}
    for distribution in sorted(metadata.distributions(), key=lambda item: item.metadata["Name"].lower()):
        name = distribution.metadata["Name"]
        normalized = name.lower().replace("_", "-")
        entries = []
        for item in distribution.files or []:
            if any(part.lower() == "licenses" for part in item.parts) or item.name.lower().startswith(("license", "copying", "notice")):
                original = distribution.locate_file(item)
                if original.is_file():
                    suffix = (str(item).split(".dist-info/", 1)[1]
                              if ".dist-info/" in str(item) else "notices/" + item.name)
                    if ".." in Path(suffix).parts:
                        raise RuntimeError(f"Unexpected license path for {name}")
                    destination = licenses / name / suffix
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(original, destination)
                    entries.append(destination.relative_to(resources).as_posix())
        if normalized in required and not entries:
            raise RuntimeError(f"Missing required dependency license text: {name}")
        distributions.append({"name": name, "version": distribution.version,
                              "license": distribution.metadata.get("License-Expression") or "NOASSERTION",
                              "licenseFiles": entries, "scope": "build-environment"})
        required.discard(normalized)
    if required:
        raise RuntimeError(f"Missing build dependencies: {sorted(required)}")

    native = []
    for relative, original in native_binaries(toc):
        name = original.name
        if "Python.framework" in relative:
            continue
        texts = []
        if sys.platform == "win32" and original.resolve().is_relative_to(Path(sys.base_prefix).resolve()):
            # DLLs shipped by the official CPython Windows distribution are
            # covered by that distribution's complete third-party license text.
            texts.append("Licenses/Python.txt")
        for parent in ([] if texts else original.resolve().parents):
            if parent.parent.parent.name == "Cellar":
                for candidate in parent.iterdir():
                    if candidate.is_file() and candidate.name.lower().startswith(("license", "copying", "notice", "copyright")):
                        destination = licenses / "native" / parent.parent.name / candidate.name
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(candidate, destination)
                        texts.append(destination.relative_to(resources).as_posix())
                break
        if not texts and "libpcap" in name:
            destination = licenses / "native/libpcap.txt"
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / "LICENSES/libpcap.txt", destination)
            texts.append(destination.relative_to(resources).as_posix())
        if not texts:
            raise RuntimeError(f"No license text found for collected native library {name}")
        native.append({"file": relative, "licenseFiles": texts})

    cache = ROOT / "build/third-party-sources"
    manifest = json.loads((cache / "scapy-source.json").read_text())
    archive = cache / manifest["filename"]
    if (Path(manifest["filename"]).name != manifest["filename"]
            or manifest["version"] != metadata.version("scapy")
            or hashlib.sha256(archive.read_bytes()).hexdigest() != manifest["sha256"]):
        raise RuntimeError("Scapy source cache does not match the installed version and recorded digest")
    shutil.copy2(archive, sources / archive.name)
    project_archive = ROOT / "dist" / f"bmcdhcp-{version}-source.tar.gz"
    build_source(project_archive)
    shutil.copy2(project_archive, sources / project_archive.name)
    inventory = {
        "application": {"name": "bmcdhcp", "version": version, "license": "GPL-2.0-only"},
        "python": {"version": platform.python_version(), "implementation": platform.python_implementation(),
                   "licenseFile": "Licenses/Python.txt"},
        "architecture": platform.machine(), "buildDependencies": distributions,
        "nativeLibraries": native, "scapySource": manifest,
        "projectSource": {"filename": project_archive.name,
                          "sha256": hashlib.sha256(project_archive.read_bytes()).hexdigest()},
        "scope": "Build-environment versions and bundled native-library inventory; not a runtime-only SBOM",
    }
    (resources / "DEPENDENCIES.json").write_text(json.dumps(inventory, indent=2, ensure_ascii=False) + "\n")
