# Changelog

Version numbers follow semantic versioning. Unreleased and unverified work is labeled explicitly.

## 1.9.0 — 2026-11-21

### Fixed

- Persist network recovery records atomically before changing an interface; abort a change when the backup cannot be saved.
- Keep failed cleanup records and allow another stop attempt; refuse to overwrite an unresolved original backup.
- Never lease the server, subnet or broadcast address through a requested-IP hint or a persisted sticky mapping.
- Use ephemeral ports for concurrent DHCP self-tests and report expired offers as free capacity.
- Make CLI, wheel metadata and desktop versions use the same version source.
- Restrict console binding to loopback and compare omitted HTTP Origin ports using the actual default port.
- Keep API clients from overriding the launcher's lease storage path.
- Emit portable LF-only SHA-256 sidecars so release archives validate with coreutils on every platform.

### Added

- GPL-2.0-only project licensing, third-party notices and release-specific license/source materials.
- Bilingual project entry points, contributor/security policies, issue forms, PR template and release instructions.
- GitHub Actions configurations for tests, packaging and manual desktop release builds; SHA-pinned actions and dependency update configuration.
- Curated reproducible source archives, privacy/release checks, package metadata checks and verified dependency source retrieval.
- Isolated WebKit storage in nonprivileged native QA mode, preserving the user's saved settings.

### Verification boundary

Automated checks are recorded in [VALIDATION.md](docs/VALIDATION.md). GitHub-hosted normal CI, Apple Silicon, Intel and Windows x64 release candidates have completed successfully. Physical BMC DHCP, Npcap, firewall, UAC and privileged NIC recovery remain hardware-specific verification targets.

## 1.8.0 — 2026-11-13

- Added a native AppKit/WKWebView shell and a relocatable, self-contained Apple Silicon app.
- Corrected UDP source ports and macOS interface binding.
- Added desktop shutdown synchronization, UI heartbeat cleanup and packaged-runtime checks.
- Validated the local loopback/packaging path; physical BMC operation was not tested.
