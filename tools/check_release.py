#!/usr/bin/env python3
"""Check public source contents, metadata, documentation links and workflow safety."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tomllib
from urllib.parse import unquote

from source_manifest import ROOT, public_files

PATTERNS = {
    "private home path": re.compile(r"/Users/[A-Za-z0-9_.-]+/|/var/folders/[A-Za-z0-9_/.-]+"),
    "GitHub credential": re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}"),
    "AWS access key": re.compile(r"AKIA[A-Z0-9]{16}"),
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}
REQUIRED = (
    "LICENSE", "README.md", "README.zh-CN.md", "THIRD_PARTY_NOTICES.md", "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md", "SECURITY.md", "CHANGELOG.md", ".github/workflows/ci.yml",
    ".github/workflows/release.yml", "docs/RELEASING.md", "docs/VALIDATION.md",
)


def workflow_env_findings(text: str) -> list[str]:
    """Catch GitHub's case-insensitive env keys and job-context restrictions."""
    errors = []
    env_indent = None
    names = set()
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if re.fullmatch(r"\s*env:\s*", line):
            env_indent, names = indent, set()
            continue
        if env_indent is not None:
            if indent <= env_indent:
                env_indent = None
                continue
            match = re.match(r"\s*([A-Za-z_][A-Za-z_0-9]*):\s*(.*)", line)
            if match and indent == env_indent + 2:
                name, value = match.groups()
                if name.casefold() in names:
                    errors.append(f"line {number}: duplicate environment name ignoring case: {name}")
                names.add(name.casefold())
                if env_indent <= 4 and "runner." in value and "${{" in value:
                    errors.append(f"line {number}: runner context belongs in a step, not job-level env")
    return errors


def privacy_findings(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeError:
        return []
    return [name for name, pattern in PATTERNS.items() if pattern.search(text)]


def check(root: Path = ROOT) -> list[str]:
    errors = [f"Missing required file: {name}" for name in REQUIRED if not (root / name).is_file()]
    files = public_files(root)
    public = {path.resolve() for path in files}
    if (root / ".git").exists():
        tracked = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True)
        allowed = {path.relative_to(root).as_posix() for path in files}
        for name in tracked.stdout.decode().split("\0"):
            if name and name not in allowed:
                errors.append(f"Tracked file is outside the public source allowlist: {name}")
    for path in files:
        relative = path.relative_to(root).as_posix()
        errors.extend(f"{relative}: {finding}" for finding in privacy_findings(path))
        if path.suffix == ".md":
            for target in re.findall(r"\]\(([^\s)]+)(?:\s+[^)]*)?\)", path.read_text()):
                target = unquote(target.strip("<>").split("#", 1)[0])
                if not target or re.match(r"[A-Za-z][A-Za-z0-9+.-]*:", target):
                    continue
                resolved = (path.parent / target).resolve()
                if resolved not in public:
                    errors.append(f"{relative}: link is missing or not public: {target}")
    metadata = tomllib.loads((root / "pyproject.toml").read_text())
    if metadata["project"].get("license") != "GPL-2.0-only":
        errors.append("Project license must match the selected GPL-2.0-only license")
    if metadata["tool"]["setuptools"]["dynamic"]["version"]["attr"] != "bmcdhcp.__version__":
        errors.append("Package metadata must use the single source of version truth")
    for path in (root / ".github/workflows").glob("*.yml"):
        text = path.read_text()
        errors.extend(f"{path.name}: {error}" for error in workflow_env_findings(text))
        if "pull_request_target" in text:
            errors.append(f"{path.name}: privileged pull_request_target trigger is not allowed")
        for action in re.findall(r"uses:\s*([^\s#]+)", text):
            if not action.startswith("./") and not re.search(r"@[0-9a-f]{40}$", action):
                errors.append(f"{path.name}: action is not pinned to a full commit SHA: {action}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list-files", action="store_true", help="Print the exact public source allowlist")
    args = parser.parse_args()
    if args.list_files:
        print("\n".join(path.relative_to(ROOT).as_posix() for path in public_files()))
        return 0
    errors = check()
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    version = runpy.run_path(str(ROOT / "src/bmcdhcp/__init__.py"))["__version__"]
    print(f"Release preparation checks passed: {version}, {len(public_files())} public files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
