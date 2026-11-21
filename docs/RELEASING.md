# Release guide

## Prepare an isolated build

Use macOS, Python 3.11+ and Xcode Command Line Tools. Python 3.13 is the validated desktop build interpreter. Build on each target architecture separately; an arm64 build does not validate Intel operation.

```bash
python3 -m venv .mac-build-venv
.mac-build-venv/bin/python -m pip install -r requirements-macos-build.txt
python3 tools/check_release.py
.mac-build-venv/bin/python tools/fetch_release_sources.py
./tools/make_app.sh
.mac-build-venv/bin/python tools/verify_macos.py
```

The explicit source-fetch step queries the installed Scapy version on PyPI, downloads its source distribution and verifies the published SHA-256. The build fails without a matching verified cache or required license texts. Do not use `--skip-freeze` after Python, dependency or HTML changes; it is intended only for native-shell/documentation iteration.

Outputs include the architecture-specific Mac ZIP, SHA-256 sidecar and a deterministic corresponding-source archive. The app contains `Licenses`, `Sources` and `DEPENDENCIES.json` under `Contents/Resources`. Native-library license discovery is supported for Homebrew build inputs and the documented libpcap license; a missing notice fails the build rather than silently dropping it.

## Validate source and wheel distributions

In a development environment with `.[dev]` installed:

```bash
python tools/check_release.py
NO_PROXY='*' no_proxy='*' python -m unittest discover -s tests -v
python -m pyflakes src/bmcdhcp tests tools app.py app_win.py
node tools/ui_smoke.mjs --quiet
python -m build
python tools/verify_wheel.py
python tools/source_bundle.py
```

The wheel verifier installs outside the checkout without runtime dependencies and confirms that the CLI and bundled HTML are present. CLI use with raw Ethernet requires the `raw` extra. Python wheel creation does not build the native macOS app.

## Review before publishing

- Confirm the single version in `src/bmcdhcp/__init__.py`, changelog and validation record agree.
- Review the curated source file list with `python tools/check_release.py --list-files`. Inspect Git's staged diff and source archive contents.
- Check the dependency inventory, full license files, matching Scapy source and matching project source. Retain all of these in binary redistribution.
- Verify ZIP checksums and signatures after the final build, not before copying new resources into the app.
- Mark Apple Silicon, Intel, macOS versions and BMC models as tested only when actually exercised. For a non-beta claim, record real DHCP allocation, management-page access and NIC restore on an isolated physical link.
- Enable GitHub private vulnerability reporting, configure a reachable maintainer contact, and review branch protection and required CI checks.

## GitHub Actions

`ci.yml` runs on pushes to `main` and pull requests. `release.yml` is manual: enter the exact version without `v`. It builds separate arm64 and Intel candidates and uploads Actions artifacts with a 14-day retention period. It has read-only repository permissions and does **not** publish a Release or push a tag.

Review successful hosted checks and downloaded artifacts before creating a GitHub Release. Attach the Mac ZIP/checksum and corresponding source/checksum, and clearly state any unverified hardware/platform boundary. Preparing these workflows locally does not mean they have run successfully on GitHub.

## Signing and notarization

Local builds use ad-hoc signing. They are not notarized and may be blocked on first launch after download. A public maintainer may add Developer ID signing and notarization using their own account and protected secrets; no certificate, Apple ID, private key or app-specific password belongs in this repository. The current scripts do not imply that such signing has been configured.

Do not run tests or release builds with sudo. Only the end-user networking backend requests elevated privileges when used on a physical interface.
