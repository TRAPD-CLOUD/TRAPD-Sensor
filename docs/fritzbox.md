# FRITZ!Box live capture

The **FRITZ!Box deployment profile is not the capture provider**. The profile
describes the network; `[capture.fritzbox].enabled = true` separately opts into
remote packet access. Old configurations remain local-only.

TRAPD authenticates through `login_sid.lua` (modern PBKDF2 and legacy challenge
flows), discovers rather than guesses capture IDs, and consumes the capture CGI
as an arbitrary byte stream. The incremental PCAP decoder accepts split headers
and records and rejects malformed lengths before allocating packet storage.
Decoded frames are intended for the ordinary passive packet pipeline; full
payloads must never enter the WAL, database, events, or logs.

## Credentials and threat model

Configuration contains only the secret path. The username and password are in
a separate file created atomically with mode `0600`; its directory is `0700`.
This protects against other unprivileged local users and accidental config,
diagnostic, or remote-config disclosure. It does not protect a secret from root,
the sensor service account, or a fully compromised host. `Credentials` zeroizes
memory on drop and its debug representation is always redacted.

The provider rejects URLs containing user info, paths, queries, or fragments,
does not follow redirects, and disables content decompression. HTTPS uses normal
rustls certificate validation; self-signed certificates are not silently
trusted. HTTP is supported for the common LAN-only interface but exposes router
credentials to an attacker already able to observe that LAN. Prefer a correctly
trusted HTTPS certificate. Never expose the router capture endpoint to the
Internet.

## Compatibility and limitations

The capture CGI and page markup are undocumented FRITZ!OS internals and may
change. Empty discovery results are a compatibility failure, not evidence that
particular interfaces exist. Interface IDs are opaque and model-specific.
Multiple IDs are represented in configuration for future concurrent capture;
overlapping sources can duplicate observations, so production concurrency must
add a bounded deduplication window before it is enabled.

This release provides the hardened provider primitives and schema. Daemon
supervision, interactive credential prompting, provider status/metrics, and
automatic frame injection are intentionally not enabled until router fixture
testing validates current FRITZ!OS endpoint variants. Merely enabling the schema
does not yet start a daemon capture task.
