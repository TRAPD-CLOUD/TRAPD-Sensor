# Deployment

Supported production targets are systemd-based x86_64 and aarch64 Linux
systems, including current Debian/Ubuntu and RHEL/Fedora/Rocky releases.

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

