# Diagnostics

`trapd-sensorctl diagnose` checks configuration, ownership/modes, service
installation, effective Linux capabilities, interfaces, MTU, IPv6, AF_PACKET,
state/WAL writability and capacity, backend DNS/TCP reachability, and live admin
status. It does not call an assumed unauthenticated backend route and does not
print enrollment or SNMP secrets.

Use `--json` for schema-versioned automation. Exit codes are `0` for all OK,
`1` when warnings exist, `2` when any check failed, and `3` for an internal
diagnostic failure. JSON consumers must inspect `schema_version` before relying
on fields.

The admin endpoints expose health, readiness, bounded status JSON, and
Prometheus metrics on the configured loopback listener. `degraded` means core
capture remains usable but a recoverable subsystem has errors; `unhealthy`
means the core capture/persistence pipeline cannot fulfill its purpose.

