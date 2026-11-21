# BMC DHCP

Temporary DHCP and BMC discovery for directly connected management interfaces on macOS and Windows.

[简体中文](README.zh-CN.md) · [Quick start](docs/QUICKSTART.md) · [Architecture](docs/ARCHITECTURE.md) · [Validation](docs/VALIDATION.md)

Connect a Mac Ethernet adapter to a server's BMC port, start DHCP on that interface, and open the leased address in your browser. Designed for first contact with iDRAC, iLO, XCC, iBMC and other IPMI/BMC controllers.

```text
Mac + Ethernet adapter        isolated cable/switch          BMC
10.99.0.1/24          <-------------------------------->    DHCP client
                       DISCOVER → OFFER → REQUEST → ACK
```

![Native macOS console, nonprivileged test mode](docs/screenshot-macos.png)

## What it does

- Native AppKit/WKWebView window with a bundled Python runtime; no Homebrew, Chrome or Python installation needed for the Mac app.
- Select one interface, configure a temporary subnet/pool, and track short leases with sticky MAC-to-IP allocation.
- Discover management URLs using service/HTTP/TLS evidence, and show the confidence of vendor identification.
- Find statically configured BMCs with local-link discovery and bounded ARP scans of user-selected subnets.
- Save the original NIC configuration before a change, restore it on stop, and retain recovery records if cleanup fails.
- Provide a loopback-only control API, live logs, diagnostics and a source CLI.

This is a **beta**. Automated protocol, loopback, packaging and native-window checks have been run locally. Physical BMC DHCP and privileged NIC recovery have not yet been validated on hardware. See [the exact verification boundary](docs/VALIDATION.md).

## Use the Mac app

The current binary release requires macOS 15+ (the bundled Python runtime sets the minimum). Use the ZIP matching your Mac architecture when a release is available. Current local validation covers Apple Silicon; Intel release builds are configured but not yet run.

1. Connect your Ethernet adapter to the dedicated BMC port or an isolated management switch. The BMC must have DHCP enabled.
2. Open **BMC DHCP.app** and complete macOS administrator authorization.
3. Select the connected Ethernet interface and click **启动服务**.
4. Wait for a lease, then click the management link. Stop the service or quit the app when finished.

Defaults: Mac `10.99.0.1/24`, pool `10.99.0.100–10.99.0.200`, lease 300 seconds. Change these if they overlap an existing network. The tool does not provide NAT, Internet Sharing, DNS forwarding, PXE or TFTP. Do not start a second DHCP server on a shared office network.

The current release candidate is ad-hoc signed, not Developer ID signed or notarized. Cross-machine first launch may require an explicit macOS Open Anyway action. The app does not bypass that check.

## Run from source

Python 3.11+ is required. From the repository directory:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[raw]'
.venv/bin/bmcd ifaces
.venv/bin/bmcd selftest
```

For physical DHCP, use `./bmcd --iface en7` with your adapter's actual name; the launcher requests `sudo`. A source checkout used by a privileged process should live outside macOS-protected Documents/Desktop/Downloads folders. The native app handles runtime staging automatically.

See [CLI and discovery reference](docs/CLI_REFERENCE.zh-CN.md) for pools, static-IP discovery and troubleshooting. The [Windows x64 package](WIN-README.md) includes GUI/CLI executables and its own Python/Scapy runtime. Windows CI validates packaging and loopback behavior; physical BMC, Npcap, firewall and UAC interaction still require hardware validation.

## Build and contribute

- [Contributing and tests](CONTRIBUTING.md)
- [Release builds, source archives and signing](docs/RELEASING.md)
- [Changes](CHANGELOG.md) · [Security policy](SECURITY.md) · [Community conduct](CODE_OF_CONDUCT.md)

CI configurations cover lint, UI smoke checks, wheel installation, macOS tests and manually requested desktop build candidates. They do not constitute a successful GitHub-hosted run until executed in the repository. Release workflows upload reviewable Actions artifacts and do not automatically publish a GitHub Release.

## License

[GPL-2.0-only](LICENSE). Scapy uses GPL-2.0-only; other components retain their original licenses. Mac distributions include corresponding project/Scapy sources, license texts and a dependency inventory. See [third-party notices](THIRD_PARTY_NOTICES.md).

Repository: https://github.com/zyf18195378233/bmc-dhcp · Downloads: https://github.com/zyf18195378233/bmc-dhcp/releases
