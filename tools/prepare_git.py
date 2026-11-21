#!/usr/bin/env python3
"""Initialize main and stage only reviewed public files; never commit or push."""

import subprocess

from check_release import check
from source_manifest import ROOT, public_files


def main() -> int:
    errors = check()
    if errors:
        raise SystemExit("\n".join(errors))
    result = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=ROOT,
                            capture_output=True, text=True)
    if result.returncode == 0 and result.stdout.strip() != str(ROOT):
        raise SystemExit("Refusing to stage into a parent repository")
    if not (ROOT / ".git").exists():
        subprocess.run(["git", "init", "-b", "main"], cwd=ROOT, check=True)
    files = [str(path.relative_to(ROOT)) for path in public_files()]
    subprocess.run(["git", "add", "--", *files], cwd=ROOT, check=True)
    subprocess.run(["git", "diff", "--cached", "--check"], cwd=ROOT, check=True)
    print(f"Staged {len(files)} public source files. No commit, remote or push was created.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
