#!/usr/bin/env python3
"""Install a wheel outside the checkout and verify its CLI and bundled HTML."""

import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import venv


def main() -> int:
    if len(sys.argv) > 1:
        wheel = Path(sys.argv[1]).resolve()
    else:
        root = Path(__file__).resolve().parents[1]
        version = runpy.run_path(str(root / "src/bmcdhcp/__init__.py"))["__version__"]
        wheel = root / "dist" / f"bmcdhcp-{version}-py3-none-any.whl"
        sdist = root / "dist" / f"bmcdhcp-{version}.tar.gz"
        # Corresponding-source archives are not PyPI sdists. Check the exact
        # package names instead of passing every archive in dist/ to Twine.
        subprocess.run([sys.executable, "-m", "twine", "check", str(wheel), str(sdist)], check=True)
    with tempfile.TemporaryDirectory(prefix="bmcd-wheel-") as directory:
        root = Path(directory)
        venv.create(root / "venv", with_pip=True)
        py = root / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        env.pop("PYTHONHOME", None)
        subprocess.run([str(py), "-m", "pip", "install", "--no-deps", str(wheel)],
                       cwd=root, env=env, check=True, stdout=subprocess.DEVNULL)
        code = ("from importlib.resources import files; import bmcdhcp; "
                "html=files('bmcdhcp').joinpath('ui/index.html').read_text(); "
                "assert 'startBtn' in html and 'bmcdDesktop' in html; print(bmcdhcp.__version__)")
        installed = subprocess.run([str(py), "-c", code], cwd=root, env=env, check=True,
                                   capture_output=True, text=True).stdout.strip()
        cli = subprocess.run([str(py), "-m", "bmcdhcp", "--version"], cwd=root, env=env, check=True,
                             capture_output=True, text=True).stdout.strip()
        assert cli == f"bmcd {installed}", (cli, installed)
        print(cli)
    print("Installed wheel CLI and HTML checks passed outside the source checkout")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
