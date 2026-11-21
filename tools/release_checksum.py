"""Write checksum sidecars with a stable encoding across build platforms."""

from __future__ import annotations

import hashlib
from pathlib import Path


def write_sha256(path: Path) -> Path:
    """Create a coreutils-compatible SHA-256 sidecar using LF on every OS."""
    checksum = path.with_suffix(path.suffix + ".sha256")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    checksum.write_bytes(f"{digest}  {path.name}\n".encode("ascii"))
    return checksum
