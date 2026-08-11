# Deployment

Supported production targets are systemd-based x86_64 and aarch64 Linux
systems, including current Debian/Ubuntu and RHEL/Fedora/Rocky releases.

## Recommended: `scripts/install.sh`

```bash
curl -fsSL https://github.com/TRAPD-CLOUD/TRAPD-Sensor/releases/latest/download/install.sh | sudo bash
```

Downloads the binaries and packaging files for the host's architecture
(amd64/arm64), verifies them against the release's `SHA256SUMS`, installs
everything below by hand, and then enrolls (prompting for a token if none was
supplied) and starts the service. Idempotent — re-running it upgrades
binaries/unit in place, never overwrites an existing `config.toml`, and never
touches `/var/lib/trapd-sensor` (identity + offline queue). See the
[README quickstart](../README.md#homelab-quickstart) for the non-interactive
form and flags (`--version`, `--force-enroll`, `--skip-enroll`).

## Manual (DEB/RPM)

Install the DEB or RPM, copy `config.toml.example` to `config.toml`, review its
permissions and local policy, enroll, run diagnostics, then explicitly enable
the service. Packages intentionally do not start an unenrolled sensor.

```bash
sudo install -m 0640 -o root -g trapd-sensor \
  /etc/trapd-sensor/config.toml.example /etc/trapd-sensor/config.toml
sudo -u trapd-sensor trapd-sensorctl enroll --token "$TOKEN"
sudo -u trapd-sensor trapd-sensorctl diagnose
sudo systemctl enable --now trapd-sensor
```

Normal uninstall preserves `/var/lib/trapd-sensor`. Back up or explicitly
remove that directory only when the enrollment identity and queued telemetry
are no longer required.

