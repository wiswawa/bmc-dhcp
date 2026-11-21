"""A shared allowlist for GitHub preparation and corresponding-source archives."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    ".editorconfig", ".gitattributes", ".gitignore", "LICENSE", "README.md", "README.zh-CN.md",
    "WIN-README.md", "CHANGELOG.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "SECURITY.md",
    "THIRD_PARTY_NOTICES.md", "MANIFEST.in", "pyproject.toml", "requirements-macos-build.txt",
    "app.py", "app_win.py", "bmcd", "bmcd.cmd", "BMC DHCP.cmd", "install.sh", "requirements-windows-build.txt",
    "docs/QUICKSTART.md", "docs/ARCHITECTURE.md", "docs/CLI_REFERENCE.zh-CN.md",
    "docs/RELEASING.md", "docs/VALIDATION.md", "docs/readme-hero.svg",
    "docs/screenshot-macos.png", "docs/social-preview.png",
)
DIRECTORIES = ("src", "tests", "tools", "macos", "windows", ".github", "LICENSES")
SKIP_PARTS = {"__pycache__", ".git", "eval", "validation", "local-notes"}
SKIP_SUFFIXES = {".pyc", ".pyo", ".log", ".jsonl", ".pcap", ".pcapng"}
LOCAL_IMAGES = {"docs/screenshot-error.png", "docs/screenshot-running.png", "docs/screenshot-stopped.png"}
LOCAL_TOOLS = {"tools/prepare_git.py"}


def public_files(root: Path = ROOT) -> list[Path]:
    files = {root / name for name in FILES if (root / name).is_file()}
    for directory in DIRECTORIES:
        for path in (root / directory).rglob("*"):
            if path.relative_to(root).as_posix() in LOCAL_IMAGES | LOCAL_TOOLS:
                continue
            if any(part in SKIP_PARTS or part.endswith(".egg-info") for part in path.relative_to(root).parts):
                continue
            if path.name == ".DS_Store" or path.suffix in SKIP_SUFFIXES:
                continue
            if path.is_file():
                if path.is_symlink():
                    raise ValueError(f"Public source must not depend on a symlink: {path.relative_to(root)}")
                files.add(path)
    for path in files:
        if path.is_symlink():
            raise ValueError(f"Public source must not depend on a symlink: {path.relative_to(root)}")
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())
