# Security model

- The service runs as `trapd-sensor` with only `CAP_NET_RAW` and, when
  promiscuous capture is enabled, `CAP_NET_ADMIN`.
- The systemd sandbox preserves AF_PACKET, AF_INET/AF_INET6, and AF_UNIX while
  denying privilege acquisition and writes outside managed state paths.
- Identity secrets and WAL state use private directories. Secrets are redacted
  by their Rust type and are never exposed as metric labels or diagnostics.
- Remote configuration cannot raise the local mode cap or set
  `active.acknowledged`. `passive_only` therefore remains passive.
- The installation edition (`deployment.edition`) is descriptive, not a
  permission: enterprise installs are allowed exactly what homelab installs
  are. `trapd-sensorctl setup` writes only `[deployment]`,
  `capture.interfaces` and `capture.promiscuous`, and never `sensor.mode`,
  `active.enabled`, `active.acknowledged` or `active.targets` — it cannot make
  a sensor send packets it would not have sent before.
- Setup's optional gateway identification is operator-invoked, requires an
  explicit confirmation (or `--probe-gateway`), targets only the host's own
  default gateway, sends no credentials, and never logs response bodies.
  Device-supplied strings are sanitized like service banners before display.
  The daemon performs no such requests.
- SNMP is v2c GET-only, uses only configured communities, and never performs
  SET, WALK, or credential guessing.
- Packet and BER parsers enforce size, depth, and collection bounds. The sensor
  stores normalized observations, not full packet captures.

Report security issues privately to the repository maintainers. Do not attach
real captures, enrollment identities, or communities to public issues.

