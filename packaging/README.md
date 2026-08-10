# Distribution packages

Packages are built with [nFPM](https://nfpm.goreleaser.com/) from one shared
manifest so Debian and RPM payloads cannot drift. They install binaries,
systemd/sysusers/tmpfiles definitions, and a `config.toml.example`; they never
replace an operator's `config.toml`, start an unenrolled service, or remove
`/var/lib/trapd-sensor` on normal uninstall.

```bash
cargo build --workspace --release --locked
PACKAGE_VERSION=0.1.0 PACKAGE_ARCH=amd64 BINARY_DIR=target/release \
  envsubst < packaging/nfpm.yaml > /tmp/trapd-sensor-nfpm.yaml
nfpm package --config /tmp/trapd-sensor-nfpm.yaml --packager deb --target dist/
PACKAGE_VERSION=0.1.0 PACKAGE_ARCH=x86_64 BINARY_DIR=target/release \
  envsubst < packaging/nfpm.yaml > /tmp/trapd-sensor-nfpm.yaml
nfpm package --config /tmp/trapd-sensor-nfpm.yaml --packager rpm --target dist/
```

Purging state remains an explicit operator action. This avoids accidental loss
of the enrollment identity and buffered observations during package changes.
