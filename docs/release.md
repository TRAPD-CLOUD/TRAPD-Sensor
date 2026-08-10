# Release and verification

Tags matching `v*` run the full quality and supply-chain gates, cross-build
AMD64/ARM64 binaries, build DEB/RPM packages, create an SPDX JSON SBOM and
`SHA256SUMS`, and publish a GitHub Release. The checksum file is keyless-signed
with Sigstore using GitHub OIDC; no long-lived signing key is stored.

```bash
sha256sum --check SHA256SUMS
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp 'github.com/TRAPD-CLOUD/TRAPD-Sensor' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

Future package infrastructure should ingest only a verified GitHub Release,
verify its Sigstore bundle and checksums, retain the SBOM, and then sign native
repository metadata with infrastructure-managed keys. This workflow does not
publish to `packages.trapd.cloud` and is not a self-update mechanism.

