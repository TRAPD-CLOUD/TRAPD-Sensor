#!/bin/sh
set -eu

if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers /usr/lib/sysusers.d/trapd-sensor.conf || true
fi
if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/trapd-sensor.conf || true
fi

cat <<'EOF'
TRAPD Sensor installed but not started.
1. Copy /etc/trapd-sensor/config.toml.example to config.toml and review it.
2. Enroll with trapd-sensorctl enroll --token <TOKEN>.
3. Run trapd-sensorctl diagnose.
4. Enable the service explicitly: systemctl enable --now trapd-sensor.
EOF
