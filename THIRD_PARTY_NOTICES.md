# Third-party notices

BMC DHCP's original source code is licensed under **GPL-2.0-only**; see [LICENSE](LICENSE).
Third-party components keep their own copyrights and license terms.

| Component | Use | License / source |
| --- | --- | --- |
| Scapy | Ethernet/BPF DHCP and local-link discovery; optional for the source CLI, bundled in the Mac app | GPL-2.0-only; <https://github.com/secdev/scapy> |
| CPython | Bundled Python interpreter and standard library | PSF-2.0 and the notices in Python's `LICENSE.txt`; <https://www.python.org/> |
| PyInstaller | Frozen application loader and runtime hooks | GPL-2.0-or-later with the project's bootloader exception; see its complete `COPYING.txt`; <https://pyinstaller.org/> |
| Pillow | Build-time icon generation | HPND and its included third-party notices; <https://python-pillow.org/> |
| libpcap | Packet-filter compilation when collected by the builder | BSD license and component copyright notices; <https://www.tcpdump.org/> |
| OpenSSL | TLS used by the bundled Python interpreter | Apache-2.0 and upstream notices for OpenSSL 3.x; <https://openssl-library.org/> |
| libmpdec | Python decimal support, when collected | BSD-2-Clause; <https://www.bytereef.org/mpdecimal/> |
| liblzma / XZ | Python compression support, when collected | Upstream XZ license notices, including 0BSD for recent liblzma releases; <https://tukaani.org/xz/> |

The macOS app (`Contents/Resources`) and Windows EXE package (`Resources`) contain these release-specific materials:

- `Licenses/`: the project's GPL text and the exact license files collected from installed dependencies and native-library distributions.
- `Sources/`: the complete BMC DHCP source archive and the exact Scapy source distribution, verified against PyPI's SHA-256 digest.
- `DEPENDENCIES.json`: build versions, source archive digests and a list of bundled native libraries. Build tools are identified as build tools; this is a dependency inventory, not a claim that every build-environment package is used at runtime.

The release builder fails if required license texts or the Scapy source archive are missing. It does not make a network request for source code implicitly: maintainers prepare the verified cache using `tools/fetch_release_sources.py` before building.

System frameworks supplied by macOS (AppKit, WebKit and other Apple frameworks) are not redistributed. The Windows EXE package bundles the official CPython runtime; the separate Windows source ZIP retains the Python-based launchers. Npcap is not redistributed.

When redistributing a Mac binary, retain these materials and provide the matching source archive with it. Review the inventory after changing dependencies; license obligations are not established solely by a package's metadata label.
