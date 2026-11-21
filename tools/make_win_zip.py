#!/usr/bin/env python3
"""Build the experimental Windows source ZIP from the shared public allowlist.

No Windows interpreter or executable is bundled. Hardware behavior remains
unverified; this only validates source packaging and license inclusion.
"""

from __future__ import annotations

from pathlib import Path
import runpy
import zipfile

from source_manifest import ROOT, public_files


def version() -> str:
    return runpy.run_path(str(ROOT / "src/bmcdhcp/__init__.py"))["__version__"]


def collect() -> list[str]:
    return [path.relative_to(ROOT).as_posix() for path in public_files()]


def main() -> int:
    output = ROOT / "dist" / f"bmcd-win-{version()}.zip"
    output.parent.mkdir(exist_ok=True)
    files = collect()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for relative in files:
            info = zipfile.ZipInfo("bmcd-win/" + relative, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o755 if relative.endswith((".cmd", ".sh")) or relative == "bmcd" else 0o644) << 16
            archive.writestr(info, (ROOT / Path(relative)).read_bytes())
    print(f"Windows source ZIP: {output.name} ({len(files)} files, GPL license and public docs included)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
