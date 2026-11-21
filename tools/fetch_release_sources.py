#!/usr/bin/env python3
"""Fetch pinned Scapy source and verify PyPI's published SHA-256 before caching."""

from __future__ import annotations

import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "build/third-party-sources"


def download(url: str, limit: int = 64 * 1024 * 1024) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "BMC-DHCP-release-preparation"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                data = response.read(limit + 1)
            if len(data) > limit:
                raise RuntimeError("Source download exceeds the size limit")
            return data
        except urllib.error.URLError:
            if attempt == 2:
                # Use the OS network stack if Python TLS is interrupted; keep
                # certificate verification enabled in both implementations.
                result = subprocess.run(["curl", "--fail", "--location", "--max-time", "60",
                                         "--silent", "--show-error", url], capture_output=True, check=True)
                if len(result.stdout) > limit:
                    raise RuntimeError("Source download exceeds the size limit")
                return result.stdout
            time.sleep(0.5 * (attempt + 1))
    raise RuntimeError("Source download failed")


def main() -> int:
    release = version("scapy")
    metadata = json.loads(download(f"https://pypi.org/pypi/scapy/{release}/json", 4 * 1024 * 1024))
    matches = [item for item in metadata["urls"] if item["packagetype"] == "sdist"]
    if len(matches) != 1:
        raise RuntimeError("Expected exactly one Scapy source distribution")
    item = matches[0]
    filename = item["filename"]
    if Path(filename).name != filename or not item["url"].startswith("https://files.pythonhosted.org/"):
        raise RuntimeError("Unexpected source archive origin or filename")
    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / filename
    digest = item["digests"]["sha256"]
    if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        data = download(item["url"])
        if len(data) > 64 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError("Scapy source digest/size verification failed")
        temporary = path.with_suffix(path.suffix + ".part")
        temporary.write_bytes(data)
        temporary.replace(path)
    manifest = {"name": "scapy", "version": release, "filename": filename,
                "url": item["url"], "sha256": digest, "license": "GPL-2.0-only"}
    (CACHE / "scapy-source.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Verified {filename}: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
