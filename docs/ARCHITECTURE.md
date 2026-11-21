# Architecture

## Data path

```text
Native AppKit/WKWebView window (normal user)
  → bundled launcher → macOS administrator authorization
    → loopback HTTP API + Session
      → selected NIC configuration + DHCP transport
        → DHCP codec → ServerCore → LeaseManager
      → asynchronous management-service fingerprinting
```

| Module | Responsibility |
| --- | --- |
| `macos/Desktop.swift` | Native window/menu, local navigation boundary, clipboard bridge and orderly quit |
| `app.py` | Runtime staging, session handshake, administrator startup and source-browser compatibility |
| `webapp.py` | Loopback control API, token/Host/Origin checks, bounded request reads and UI heartbeat |
| `session.py` | Validated configuration, lifecycle locking, interface backup/restore, logs and probe scheduling |
| `dhcp.py` | Pure BOOTP/DHCPv4 encoding, decoding and options |
| `core.py` | DISCOVER/OFFER/REQUEST/ACK/NAK/INFORM/RELEASE/DECLINE decisions |
| `leases.py` | Sticky allocation, reservation/expiry, reserved-address exclusion and lease persistence |
| `stateio.py` | Private temporary files, flush/fsync and atomic JSON replacement |
| `engines.py` | Raw Scapy/BPF, interface-bound UDP and optional dnsmasq transports |
| `iface.py` / `winnet.py` | Platform commands and interface enumeration |
| `discover.py` / `vendors.py` | Service fingerprints, evidence and confidence |
| `scan.py` | Local-link static address discovery, bounded scans and temporary aliases |

## Network changes and recovery

One Session manages one interface. Before configuring it, the session recovers an unresolved previous record or refuses to overwrite it. The original configuration is written to a private atomic JSON file before any mutation; an unsuccessful write aborts startup.

Startup failures unwind acquired resources. Stopping the DHCP engine is independent of NIC recovery: a recovery failure keeps the record and permits another stop attempt. A subsequent launch compares the current address with the one the tool applied before restoring anything, to avoid overwriting a user's later manual changes.

Recovery is conditional on macOS accepting the relevant commands. It cannot guarantee restoration after arbitrary hardware removal, external configuration changes or disk failure. Physical recovery scenarios must be validated separately from mocked lifecycle tests.

## Concurrency

- Lifecycle transitions use the Session lifecycle lock; snapshots and events use its state lock.
- DHCP transport handles allocation; fingerprinting is queued on background workers.
- API start/stop operations are serialized. App shutdown has a separate lock so a second caller cannot cause process exit before the first has finished cleanup.
- Desktop heartbeat loss closes the backend after 120 seconds when enabled. A desktop launcher initializes the heartbeat even if the first page fails to load.

## Release boundary

Nonprivileged native QA uses a nonpersistent WebKit data store, separate from the user’s saved form settings. The launcher/CLI selects the lease output path; control API requests cannot redirect that output.

The source allowlist is shared by release checks, source archive generation. Personal evaluation logs, virtual environments, `.app` bundles, packet captures and state files are excluded from the public source.

Mac builds use a separate pinned build environment. They include license files, verified Scapy source, the matching project source and dependency inventory. Signing remains ad-hoc until a maintainer supplies a proper Developer ID signing/notarization process.
