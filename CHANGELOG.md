# Changelog

All notable changes to TRAPD Sensor are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and releases use
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- End-to-end supervised FRITZ!Box capture in the daemon, including fresh-session
  reconnects, interface validation, Ethernet PCAP ingestion through the existing
  passive observer, bounded backpressure, status/metrics/diagnose/check output,
  and hidden-password interactive setup.

- **Installation editions.** `install.sh --edition homelab|enterprise` (also
  `TRAPD_EDITION`) selects how the network setup is answered — guided for
  homelab, flag-driven for enterprise — using one installer and one setup
  implementation. `--profile`, `--vantage`, `--interface` and
  `--probe-gateway` are passed through; `--non-interactive` disables every
  prompt including the token prompt. Omitting `--edition` keeps the previous
  behaviour exactly.
- **`trapd-sensorctl setup`** records how the sensor is attached: detects
  interface, default gateway and LAN from `/proc/net/route`, asks how the
  network is managed (FRITZ!Box, UniFi, OPNsense, pfSense, OpenWrt, managed
  switch with SPAN, generic router, manual), and writes the new `[deployment]`
  block plus `capture.interfaces`/`capture.promiscuous`. Re-runnable, so
  changing the network source, the vantage point or the interface no longer
  needs a reinstall. Edits `config.toml` in place with `toml_edit` (comments
  survive), replaces it atomically and preserves owner and mode. It never
  writes `sensor.mode` or anything under `[active]`.
- Optional, opt-in gateway identification during setup: one unauthenticated
  HTTP request to the host's own default gateway (TR-064 descriptor on 49000,
  the page on 80) plus a TCP connect to 443/8443. No credentials, no response
  bodies in output or logs, and nothing of this in the daemon.
- **`trapd-sensorctl visibility [--json]`** reports what the sensor can see at
  its vantage point — asset discovery, new-device detection, fingerprinting,
  local discovery, gateway, DNS, internal/internet traffic and full frames —
  with a reason for every line, plus the live capture state from the running
  daemon. The same derivation feeds `/admin/status`, `diagnose` and
  `trapd-sensord --check`, so no component can claim a different reach than
  another.
- `deployment.*` configuration (edition, profile, vantage, gateway_ip,
  lan_cidr). The section is optional: configurations without it keep working
  unchanged and fall back to the conservative "manually configured LAN host"
  assumption, which claims no visibility nobody verified.
- `diagnose` reports the recorded deployment, the visibility matrix as one
  machine-readable line, and flags the silent failure mode of a mirror-port
  deployment running with `capture.promiscuous = false`.

- Production CI for formatting, linting, tests, dependency policy, security
  advisories, and x86_64/aarch64 release builds.
- Bounded IPv6 extension-header and ICMPv6 Neighbor Discovery parsing.
- Scope-checked, rate-limited, read-only SNMPv2c system discovery.
- `scripts/install.sh`: one-line installer for the Homelab quickstart —
  downloads the release for the host's architecture, verifies checksums,
  installs binaries/systemd unit/sysusers/tmpfiles, grants capabilities,
  enrolls, and starts the service. Idempotent (safe for upgrades), never
  touches an existing `config.toml` or `/var/lib/trapd-sensor`. Published as
  a release asset (`install.sh`), alongside a new `packaging.tar.gz` asset it
  depends on.

### Fixed

### Added

- Vendor-isolated FRITZ!OS authentication and live-capture primitives: legacy
  and PBKDF2 challenge responses, router-advertised interface discovery,
  redirect-safe streaming capture, a bounded incremental classic-PCAP decoder,
  redacted 0600 credential storage, and bounded reconnect scheduling.
- Optional `[capture.fritzbox]` configuration. A `fritzbox` deployment profile
  remains backwards-compatible and does not enable or require router access.

- `trapd-sensorctl diagnose` checked its own (always-empty) process
  capabilities instead of the `trapd-sensord` daemon's, permanently
  reporting `CAP_NET_RAW`/`CAP_NET_ADMIN` as missing even on a correctly
  configured install.

[Unreleased]: https://github.com/TRAPD-CLOUD/TRAPD-Sensor/compare/v0.1.0...HEAD
