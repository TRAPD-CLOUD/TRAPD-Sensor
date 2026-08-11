# Changelog

All notable changes to TRAPD Sensor are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and releases use
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

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

- `trapd-sensorctl diagnose` checked its own (always-empty) process
  capabilities instead of the `trapd-sensord` daemon's, permanently
  reporting `CAP_NET_RAW`/`CAP_NET_ADMIN` as missing even on a correctly
  configured install.

[Unreleased]: https://github.com/TRAPD-CLOUD/TRAPD-Sensor/compare/v0.1.0...HEAD
