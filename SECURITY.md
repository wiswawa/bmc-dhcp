# Security policy

## Supported versions

Security fixes target the current `main` branch and the latest release. Older releases are not maintained independently. The initial public release is a beta until physical BMC and privileged NIC recovery checks are recorded in the release notes.

## Report privately

Use **Security → Report a vulnerability** when private vulnerability reporting is enabled in the GitHub repository. If that channel is unavailable, contact a maintainer privately using the contact information on their public profile. A public issue may request a private contact without disclosing the vulnerability itself.

Include the affected version, macOS version, a minimal reproducible example, the expected and observed behavior, and the impact. Replace real MACs, session tokens, BMC hostnames and personal paths with synthetic values. Do not send customer packet captures unless a maintainer has agreed on a private transfer method.

There is no paid bug bounty or guaranteed response time. Maintainers will acknowledge, investigate and coordinate disclosure as their availability permits. Please allow coordination before public disclosure.

## Trust boundaries

- The desktop window is unprivileged; the networking backend requests macOS administrator authorization.
- The local HTTP console is restricted to loopback, uses a random session token, validates Host/Origin and does not serve arbitrary filesystem paths.
- The launcher/CLI chooses the lease output path; control API clients cannot override it.
- The backend can configure the selected NIC. Its runtime, source checkout and build artifacts must be trusted by the administrator running it.
- No BMC credentials are collected, stored or automatically used. Management links open in the user's browser.
- DHCP belongs on a directly connected or isolated management network. The tool does not isolate an existing shared network or resolve every competing-server/IP conflict automatically.
- Recovery is best effort when the OS refuses a network change. Failed cleanup retains its recovery record; hardware results and limitations belong in release notes.

Maintainers must enable GitHub private vulnerability reporting and identify a reachable maintainer contact before public launch; the presence of this file does not enable either setting automatically.
