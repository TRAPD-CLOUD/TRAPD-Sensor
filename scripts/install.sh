#!/usr/bin/env bash
# TRAPD Network Sensor — one-line installer for systemd-based Linux.
#
# Recommended usage (see README.md):
#
#   curl -fsSL https://github.com/TRAPD-CLOUD/TRAPD-Sensor/releases/latest/download/install.sh | sudo bash
#
# Without a token, the script still installs everything and prompts for one
# interactively (input hidden, read from the controlling terminal so it works
# even when the script itself arrived via a pipe — this is the only form
# that never puts the token in shell history) — Ctrl-C at the prompt skips
# enrollment and leaves the sensor installed-but-not-started, exactly like
# the DEB/RPM packages do.
#
# For non-interactive/automated enrollment, keep the token in a file and
# read it from there — typing `TRAPD_ENROLL_TOKEN=enroll_xxx ...` at a live
# prompt still records that whole line, env var or not:
#
#   curl -fsSL https://github.com/TRAPD-CLOUD/TRAPD-Sensor/releases/latest/download/install.sh -o install.sh
#   sudo TRAPD_ENROLL_TOKEN="$(cat /path/to/token-file)" bash install.sh
#
# What it does, in order: downloads the requested release (default: latest)
# for the host's architecture, installs the two binaries plus the systemd
# unit/sysusers/tmpfiles definitions, creates the trapd-sensor system user
# and state/config directories, grants CAP_NET_RAW/CAP_NET_ADMIN, enrolls
# with the token, starts the service, then runs `status` and `diagnose` so
# the operator sees a live sensor (or a clear reason why not) before the
# script exits.
#
# Idempotent: safe to re-run for upgrades. Never overwrites an existing
# config.toml, never touches /var/lib/trapd-sensor (enrollment identity +
# offline queue survive upgrades), and skips enrollment if the sensor is
# already enrolled unless --force is given.

set -Eeuo pipefail

REPO="TRAPD-CLOUD/TRAPD-Sensor"
VERSION="${TRAPD_SENSOR_VERSION:-latest}"
TOKEN="${TRAPD_ENROLL_TOKEN:-}"
FORCE_ENROLL=0
SKIP_ENROLL=0
BIN_DIR="/usr/bin"
CONFIG_DIR="/etc/trapd-sensor"
STATE_DIR="/var/lib/trapd-sensor"
SYSTEMD_UNIT_DIR="/etc/systemd/system"
SYSUSERS_DIR="/usr/lib/sysusers.d"
TMPFILES_DIR="/usr/lib/tmpfiles.d"
WORKDIR=""

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m warning:\033[0m %s\n' "$*" >&2; }

# Runs a command as the trapd-sensor service user. The script already
# requires real root (checked below), so this only needs *some* way to
# drop privileges, not sudo specifically — minimal server/container images
# often don't ship sudo at all. Prefers runuser (util-linux, effectively
# always present on a systemd host) over sudo, falls back to su.
as_sensor() {
  if command -v runuser >/dev/null 2>&1; then
    runuser -u trapd-sensor -- "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -u trapd-sensor "$@"
  else
    su -s /bin/sh trapd-sensor -c "$(printf '%q ' "$@")"
  fi
}

# Same as as_sensor, but forwards TRAPD_ENROLLMENT_TOKEN through the
# environment instead of a CLI argument — trapd-sensorctl's `enroll --token`
# would otherwise put the secret in this process's argv, readable by any
# local user via `ps`/`/proc/<pid>/cmdline` for as long as the enroll
# request is in flight. `enroll` already reads this exact variable (clap
# `env = "TRAPD_ENROLLMENT_TOKEN"` on sensor-cli's --token), so this needs
# no changes on the Rust side. runuser/su inherit the calling environment by
# default (no -l/login-shell reset here); sudo does not, so it needs
# --preserve-env explicitly.
as_sensor_with_token() {
  local token="$1"
  shift
  if command -v runuser >/dev/null 2>&1; then
    TRAPD_ENROLLMENT_TOKEN="$token" runuser -u trapd-sensor -- "$@"
  elif command -v sudo >/dev/null 2>&1; then
    TRAPD_ENROLLMENT_TOKEN="$token" sudo --preserve-env=TRAPD_ENROLLMENT_TOKEN -u trapd-sensor "$@"
  else
    TRAPD_ENROLLMENT_TOKEN="$token" su -s /bin/sh trapd-sensor -c "$(printf '%q ' "$@")"
  fi
}

# die() is for expected, already-explained failures (bad args, missing
# prerequisites, a rejected token) — the message alone is the whole story,
# so it disables the ERR trap first to avoid a second, generic "something
# failed" line underneath a specific one.
die()  { trap - ERR; printf '\033[1;31m error:\033[0m %s\n' "$*" >&2; exit 1; }

# Catches everything unexpected: a command failing for a reason this script
# didn't anticipate. Re-running is safe (see the idempotency notes above).
on_err() {
  local line=$1
  printf '\033[1;31m error:\033[0m installation failed unexpectedly at line %s — nothing after that point ran. Re-running this script is safe (it'"'"'s idempotent) once the cause above is fixed.\n' "$line" >&2
  exit 1
}
trap 'on_err $LINENO' ERR

cleanup() {
  # Must always return 0: this runs from the EXIT trap, and with -E
  # (errtrace) an ERR trap still fires for a failing command inside a
  # function called from another trap — a bare `[[ ... ]] && rm -rf` whose
  # condition is false (e.g. --help exits before WORKDIR is ever set) would
  # itself "fail", triggering on_err and turning a clean `exit 0` into 1.
  if [[ -n "$WORKDIR" && -d "$WORKDIR" ]]; then
    rm -rf "$WORKDIR"
  fi
  return 0
}
trap cleanup EXIT

usage() {
  cat <<'EOF'
Usage: install.sh [options]

Options:
  --token <TOKEN>     Enrollment token. Avoid this and TRAPD_ENROLL_TOKEN on
                       a shared/interactive shell — both land in history if
                       typed at a live prompt. Prefer the interactive hidden
                       prompt (run with neither), or read the value from a
                       file: TRAPD_ENROLL_TOKEN="$(cat token-file)".
  --version <TAG>     Install a specific release tag instead of latest,
                       e.g. --version v0.1.0. Default: latest.
  --force-enroll      Re-enroll even if this host already has an identity
                       (replaces /var/lib/trapd-sensor/identity.json).
  --skip-enroll       Install everything but do not enroll or start the
                       service, even if a token is available.
  -h, --help          Show this help.

Environment variables:
  TRAPD_ENROLL_TOKEN   Same as --token.
  TRAPD_SENSOR_VERSION Same as --version.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --token) TOKEN="${2:?--token requires a value}"; shift 2 ;;
    --version) VERSION="${2:?--version requires a value}"; shift 2 ;;
    --force-enroll) FORCE_ENROLL=1; shift ;;
    --skip-enroll) SKIP_ENROLL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

# --- Preflight ---------------------------------------------------------

[[ "$(uname -s)" == "Linux" ]] || die "TRAPD Sensor only supports Linux."
command -v systemctl >/dev/null 2>&1 || die "systemd (systemctl) not found — this installer targets systemd-based distributions only."
[[ -d /run/systemd/system ]] || die "systemctl is present but systemd is not running as PID 1 (common in plain containers/chroots) — this installer needs a real systemd instance to create the service user (systemd-sysusers) and manage the unit. Install manually instead; see docs/deployment.md."
command -v curl >/dev/null 2>&1 || die "curl is required. Install it (e.g. 'apt install curl' or 'dnf install curl') and re-run."

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  die "this installer needs root (it creates a system user and installs to /usr/bin, /etc, /var/lib). Re-run with sudo."
fi

case "$(uname -m)" in
  x86_64|amd64) TARGET="x86_64-unknown-linux-gnu" ;;
  aarch64|arm64) TARGET="aarch64-unknown-linux-gnu" ;;
  *) die "unsupported architecture: $(uname -m) — TRAPD Sensor releases cover amd64 and arm64 only." ;;
esac
log "detected architecture: $(uname -m) -> $TARGET"

# --- Resolve download base URL -----------------------------------------

if [[ "$VERSION" == "latest" ]]; then
  RELEASE_PATH="latest/download"
  log "installing the latest release"
else
  RELEASE_PATH="download/${VERSION}"
  log "installing release ${VERSION}"
fi
# Overridable for testing or an internal mirror/air-gapped staging server;
# not a supported public flag, deliberately undocumented in --help.
BASE_URL="${TRAPD_INSTALL_BASE_URL:-https://github.com/${REPO}/releases/${RELEASE_PATH}}"

WORKDIR="$(mktemp -d)"

fetch() {
  local name="$1" dest="$2"
  curl -fsSL --retry 3 --retry-connrefused -o "$dest" "${BASE_URL}/${name}" \
    || die "could not download ${name} from ${BASE_URL} — check the version/network, or see README.md for a from-source install."
}

log "downloading trapd-sensord, trapd-sensorctl and packaging files (${TARGET})"
fetch "trapd-sensord-${TARGET}" "$WORKDIR/trapd-sensord"
fetch "trapd-sensorctl-${TARGET}" "$WORKDIR/trapd-sensorctl"
fetch "packaging.tar.gz" "$WORKDIR/packaging.tar.gz"
fetch "SHA256SUMS" "$WORKDIR/SHA256SUMS"

log "verifying checksums"
(
  cd "$WORKDIR"
  awk -v a="trapd-sensord-${TARGET}" -v b="trapd-sensorctl-${TARGET}" \
    '$2==a || $2==b || $2=="packaging.tar.gz" {print}' SHA256SUMS > expected.sums
  [[ $(wc -l < expected.sums) -eq 3 ]] || exit 2
  sed -e "s/trapd-sensord-${TARGET}/trapd-sensord/" -e "s/trapd-sensorctl-${TARGET}/trapd-sensorctl/" expected.sums > renamed.sums
  sha256sum --check --strict renamed.sums >&2
) || {
  status=$?
  if [[ $status -eq 2 ]]; then
    die "SHA256SUMS did not list all three downloaded files (binaries + packaging.tar.gz) — refusing to install unverified files."
  else
    die "checksum verification failed — downloaded files do not match SHA256SUMS. Not installing."
  fi
}
chmod 0755 "$WORKDIR/trapd-sensord" "$WORKDIR/trapd-sensorctl"

tar -xzf "$WORKDIR/packaging.tar.gz" -C "$WORKDIR"
[[ -f "$WORKDIR/packaging/systemd/trapd-sensor.service" ]] \
  || die "packaging.tar.gz did not contain the expected files — release asset looks corrupt."

# --- Install (idempotent: upgrades binaries/unit, never touches state) --

RESTART_AFTER=0
if systemctl is-active --quiet trapd-sensor 2>/dev/null; then
  RESTART_AFTER=1
fi

log "installing trapd-sensord and trapd-sensorctl to ${BIN_DIR}"
install -m 0755 "$WORKDIR/trapd-sensord" "${BIN_DIR}/trapd-sensord"
install -m 0755 "$WORKDIR/trapd-sensorctl" "${BIN_DIR}/trapd-sensorctl"

log "installing systemd unit, sysusers.d and tmpfiles.d definitions"
install -m 0644 "$WORKDIR/packaging/systemd/trapd-sensor.service" "${SYSTEMD_UNIT_DIR}/trapd-sensor.service"
install -Dm 0644 "$WORKDIR/packaging/systemd/trapd-sensor.sysusers" "${SYSUSERS_DIR}/trapd-sensor.conf"
install -Dm 0644 "$WORKDIR/packaging/systemd/trapd-sensor.tmpfiles" "${TMPFILES_DIR}/trapd-sensor.conf"

log "creating the trapd-sensor system user and state directories"
systemd-sysusers "${SYSUSERS_DIR}/trapd-sensor.conf"
systemd-tmpfiles --create "${TMPFILES_DIR}/trapd-sensor.conf"
systemctl daemon-reload

log "granting CAP_NET_RAW/CAP_NET_ADMIN on the daemon binary"
if command -v setcap >/dev/null 2>&1; then
  setcap cap_net_raw,cap_net_admin+eip "${BIN_DIR}/trapd-sensord" \
    || warn "setcap failed — the packaged systemd unit's AmbientCapabilities= still grants these at service start, so this is not fatal, but running the binary outside systemd will need it. Install 'libcap2-bin' (Debian/Ubuntu) or 'libcap' (RHEL/Fedora) and re-run to fix."
else
  warn "setcap not found — relying on the systemd unit's AmbientCapabilities= (fine for 'systemctl start trapd-sensor', not for running the binary directly). Install 'libcap2-bin' (Debian/Ubuntu) or 'libcap' (RHEL/Fedora) if you need the latter."
fi

if [[ ! -f "${CONFIG_DIR}/config.toml" ]]; then
  log "installing default config to ${CONFIG_DIR}/config.toml"
  install -m 0640 -g trapd-sensor "$WORKDIR/packaging/config.example.toml" "${CONFIG_DIR}/config.toml"
  # The example's name/site are sample values ("homelab-sensor-01"/"Keller"),
  # not placeholders trapd-sensorctl replaces on its own — left as-is, every
  # quickstart install would enroll under the same display name. Give each
  # host a distinct default (its hostname, no site) and say so; still worth
  # a look before enrolling on a sensitive network.
  hn="$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo trapd-sensor)"
  sed -i \
    -e "s/^name = \"homelab-sensor-01\"/name = \"${hn}\"/" \
    -e '/^site = "Keller"/d' \
    "${CONFIG_DIR}/config.toml"
  log "  name defaulted to this host's hostname (${hn}); review ${CONFIG_DIR}/config.toml before enrolling on a sensitive network"
else
  log "existing ${CONFIG_DIR}/config.toml left untouched"
fi
install -m 0644 -o root -g root "$WORKDIR/packaging/config.example.toml" "${CONFIG_DIR}/config.toml.example"

# state_dir is configurable; the packaged systemd unit only grants write
# access to the default via ReadWritePaths=, but an operator's config.toml
# could still name a different (writable) path, and enrollment/start
# decisions below must agree with where trapd-sensorctl actually put the
# identity file. Read it via the real config parser (--check) rather than
# a bash TOML regex, so any valid TOML (indentation, quoting, comments)
# the binaries themselves accept is resolved correctly instead of drifting
# from their parser.
configured_state_dir="$("${BIN_DIR}/trapd-sensord" --config "${CONFIG_DIR}/config.toml" --check 2>/dev/null \
  | sed -n 's/^ *state directory: *//p' | head -1)"
[[ -n "$configured_state_dir" ]] && STATE_DIR="$configured_state_dir"

# --- Enroll --------------------------------------------------------------

ALREADY_ENROLLED=0
[[ -f "${STATE_DIR}/identity.json" ]] && ALREADY_ENROLLED=1

if [[ "$SKIP_ENROLL" -eq 1 ]]; then
  log "skipping enrollment (--skip-enroll)"
elif [[ "$ALREADY_ENROLLED" -eq 1 && "$FORCE_ENROLL" -eq 0 ]]; then
  log "sensor is already enrolled (${STATE_DIR}/identity.json exists) — leaving identity as-is. Pass --force-enroll to replace it."
else
  if [[ -z "$TOKEN" ]]; then
    # -r only checks the permission bit; the open itself can still fail
    # (no controlling terminal — piped-and-backgrounded, CI, containers
    # without a tty). Both the prompt and the read must be probed as an
    # `if` condition, not run bare, or that failure would trip `set -e`.
    if exec 3<>/dev/tty 2>/dev/null; then
      printf 'Enrollment token (from the TRAPD dashboard, input hidden — leave empty to skip): ' >&3
      IFS= read -rs TOKEN <&3 || true
      printf '\n' >&3
      exec 3>&-
    else
      warn "no enrollment token and no terminal to prompt on — skipping enrollment. Run 'trapd-sensorctl enroll --token <TOKEN>' as the trapd-sensor user once you have one."
    fi
  fi

  if [[ -n "$TOKEN" ]]; then
    log "enrolling with the TRAPD backend"
    ENROLL_ARGS=(enroll)
    [[ "$FORCE_ENROLL" -eq 1 ]] && ENROLL_ARGS+=(--force)
    # Token goes through the environment (TRAPD_ENROLLMENT_TOKEN, which
    # `enroll --token` already reads via clap's env fallback), not argv —
    # see as_sensor_with_token's doc comment.
    if ! as_sensor_with_token "$TOKEN" "${BIN_DIR}/trapd-sensorctl" "${ENROLL_ARGS[@]}"; then
      die "enrollment failed (see the error above — usually an expired/invalid token or an unreachable backend.api_url in ${CONFIG_DIR}/config.toml). Everything else is installed; fix the cause and re-run: sudo -u trapd-sensor trapd-sensorctl enroll --token <TOKEN>"
    fi
  fi
fi
unset TOKEN

# --- Start + verify -------------------------------------------------------

if [[ "$SKIP_ENROLL" -eq 0 && -f "${STATE_DIR}/identity.json" ]]; then
  if [[ "$RESTART_AFTER" -eq 1 ]]; then
    log "restarting trapd-sensor (was already running — upgrading in place)"
    systemctl restart trapd-sensor
  else
    log "starting trapd-sensor"
    systemctl enable --now trapd-sensor
  fi
  sleep 1
  echo
  as_sensor "${BIN_DIR}/trapd-sensorctl" status || warn "status check failed — the service may still be starting; try 'trapd-sensorctl status' again in a few seconds."
elif [[ "$SKIP_ENROLL" -eq 1 ]]; then
  log "not starting the service (--skip-enroll)."
  echo "Enroll and start it with:"
  echo "  sudo -u trapd-sensor trapd-sensorctl enroll --token <TOKEN>"
  echo "  sudo systemctl enable --now trapd-sensor"
else
  log "not starting the service — the sensor is installed but not enrolled yet."
  echo "Enroll and start it with:"
  echo "  sudo -u trapd-sensor trapd-sensorctl enroll --token <TOKEN>"
  echo "  sudo systemctl enable --now trapd-sensor"
fi

echo
log "running diagnostics"
as_sensor "${BIN_DIR}/trapd-sensorctl" diagnose || true

echo
log "done. 'systemctl status trapd-sensor' and 'journalctl -u trapd-sensor -f' for logs."
