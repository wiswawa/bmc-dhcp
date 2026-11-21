#!/usr/bin/env python3
"""Create a deterministic corresponding-source archive from the public allowlist."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
from pathlib import Path
import runpy
import tarfile

from source_manifest import ROOT, public_files


def build_source(destination: Path, root: Path = ROOT) -> Path:
    version = runpy.run_path(str(root / "src/bmcdhcp/__init__.py"))["__version__"]
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as output, gzip.GzipFile(fileobj=output, mode="wb", mtime=0,
                                                        filename="", compresslevel=9) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for path in public_files(root):
                data = path.read_bytes()
                relative = path.relative_to(root).as_posix()
                info = tarfile.TarInfo(f"bmcdhcp-{version}/{relative}")
                info.size = len(data)
                info.mode = 0o755 if relative in ("bmcd", "install.sh", "tools/make_app.sh") else 0o644
                info.mtime = 0
                archive.addfile(info, io.BytesIO(data))
    checksum = destination.with_suffix(destination.suffix + ".sha256")
    checksum.write_text(hashlib.sha256(destination.read_bytes()).hexdigest() + "  " + destination.name + "\n")
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    version = runpy.run_path(str(ROOT / "src/bmcdhcp/__init__.py"))["__version__"]
    output = args.output or ROOT / "dist" / f"bmcdhcp-{version}-source.tar.gz"
    print(build_source(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
