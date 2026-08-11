# Deployment

Supported production targets are systemd-based x86_64 and aarch64 Linux
systems, including current Debian/Ubuntu and RHEL/Fedora/Rocky releases.

## Recommended: `scripts/install.sh`

```bash
curl -fsSL https://github.com/TRAPD-CLOUD/TRAPD-Sensor/releases/latest/download/install.sh | sudo bash -s -- --edition homelab
curl -fsSL https://github.com/TRAPD-CLOUD/TRAPD-Sensor/releases/latest/download/install.sh | sudo bash -s -- --edition enterprise
```

Downloads the binaries and packaging files for the host's architecture
(amd64/arm64), verifies them against the release's `SHA256SUMS`, installs
everything below by hand, runs the network setup for the selected edition, and
then enrolls (prompting for a token if none was supplied) and starts the
service. Idempotent — re-running it upgrades binaries/unit in place, never
overwrites an existing `config.toml` beyond the setup keys, and never touches
`/var/lib/trapd-sensor` (identity + offline queue). See the
[README quickstart](../README.md#homelab-quickstart) for the non-interactive
form and flags (`--version`, `--force-enroll`, `--skip-enroll`).

## Editions

One installer, one setup implementation, two ways of answering it:

| | Homelab | Enterprise |
|---|---|---|
| Setup | guided on `/dev/tty` | flags (`--profile`, `--vantage`, `--interface`) |
| Requires SPAN/TAP | no | no, but that is the usual deployment |
| Unattended | falls back to detection when no terminal exists | `--non-interactive` |

The edition is recorded in `deployment.edition` and changes nothing about what
the sensor is allowed to do: `sensor.mode` remains the local cap, and active
discovery still needs its three separate approvals. `trapd-sensorctl setup`
writes only `[deployment]`, `capture.interfaces` and `capture.promiscuous`.

Omitting `--edition` skips the setup step entirely, which is exactly how the
installer behaved before editions existed.

The setup step runs before enrollment so the enroll request reports the chosen
capture interfaces. It runs as root (the config is `0640 root:trapd-sensor`)
and asks its questions on `/dev/tty`, which works even when the installer
itself arrived through a pipe.

## Reconfiguring without reinstalling

```bash
sudo trapd-sensorctl setup                                       # ask again
sudo trapd-sensorctl setup --profile span --vantage mirror_port  # FRITZ!Box → SPAN
sudo trapd-sensorctl setup --profile unifi                       # generic → UniFi
sudo trapd-sensorctl setup --interface eth1                      # change interface
sudo trapd-sensorctl setup --dry-run --profile span              # preview only
trapd-sensorctl visibility [--json]                              # current state
sudo systemctl restart trapd-sensor                              # apply
```

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

