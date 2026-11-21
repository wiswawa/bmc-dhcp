# Contributing

Thank you for helping make first contact with a BMC less painful. Small, reproducible fixes are welcome. English and Chinese issues and pull requests are both welcome.

## Development

Use Python 3.11 or newer on macOS:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
NO_PROXY='*' no_proxy='*' .venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m pyflakes src/bmcdhcp tests tools app.py app_win.py
node tools/ui_smoke.mjs --quiet
PYTHONPATH=src .venv/bin/python -m bmcdhcp selftest
```

Tests use mock network configuration and real loopback sockets on ephemeral ports. They do not configure a physical NIC or need administrator privileges. Do not add fixed listening ports to tests or self-tests.

For a desktop build, follow [RELEASING.md](docs/RELEASING.md). `--no-elevate` is a developer-only way to inspect a native window without configuring an interface.

## Changes worth testing

- Protocol fixes: show the request and expected reply using synthetic MACs and private test addresses.
- Lifecycle fixes: cover startup failure, failed recovery persistence and stop/restore failure, not only successful startup.
- UI fixes: verify loading, empty states and errors in the actual native window when relevant.
- Hardware results: record macOS version, NIC/chipset, BMC model/firmware and topology. Distinguish a simulation from a physical-wire test.

Keep the pure DHCP/state logic separate from transport and platform commands. Preserve Windows compatibility where possible, but label Windows results as simulated unless tested on Windows.

## Pull requests

Explain the concrete problem and resulting behavior, then list the checks you ran and any limits. Keep changes focused. Include screenshots for visible changes, with hostnames, personal paths, tokens and hardware identifiers removed.

By contributing, you agree that your contribution is licensed under GPL-2.0-only. No contributor license agreement is required.

## Reporting security issues

Use the process in [SECURITY.md](SECURITY.md). Do not paste live session tokens, packet captures or customer BMC details into a public issue.
