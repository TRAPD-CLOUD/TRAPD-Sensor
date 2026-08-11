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
change. Discovery therefore understands the semantic `data.lua?page=cap`
response as well as standalone capture-page variants, and extracts opaque IDs
from start controls or `ifaceorminor` parameters instead of matching interface
names. Empty discovery results are a compatibility failure, not evidence that
particular interfaces exist. The resulting error includes bounded response
metadata and a short sanitized preview (session IDs are redacted), so a new
firmware response can be identified without logging credentials. Interface IDs
are opaque and model-specific.

For a response summary even when discovery succeeds, run setup with capture
debug logging enabled:

```console
sudo env RUST_LOG=trapd_sensor_capture=debug trapd-sensorctl setup --profile fritzbox
```

Multiple configured IDs run as independent workers. Some firmware may reject
simultaneous captures; that source is then reported degraded rather than being
silently discarded or taking down the other workers. The fixture set provides
no evidence that advertised sources overlap, so runtime does not currently
deduplicate them. Operators should avoid overlapping selections; a future
bounded, short-window deduplicator can be added without changing packet parsing.

## Setup and operation

Run `trapd-sensorctl setup --profile fritzbox`, enable live capture, and enter a
FRITZ!Box account. Password input is read from `/dev/tty` with echo disabled.
Use a dedicated least-privilege router user where the installed FRITZ!OS version
offers capture-only rights. Setup authenticates, displays only sources returned
by that router, and requires a valid Ethernet PCAP packet before saving.

The daemon starts one independently supervised worker per configured source.
Every reconnect obtains a fresh SID and rediscovers the source; EOF, router
reboot, malformed PCAP, session failure, and DNS/network errors degrade only the
remote provider and trigger bounded backoff. Decoded Ethernet frames go directly
through the existing `PassiveObserver` and bounded observation channel. Raw
frames are dropped after analysis and never enter the WAL.

`trapd-sensorctl status` reports provider state, selected opaque IDs, packet
counts, sanitized failure code, and retry delay. `diagnose` checks the protected
credential file, authentication, discovery, and configured source availability;
`trapd-sensord --check` performs static address, secret, timeout, and limit
validation without requiring the router online.

Re-run setup to change credentials, address, or sources, or answer “no” to
disable the provider. The service must be restarted after configuration changes.
Source names and IDs have no standardized visibility semantics, so TRAPD does
not infer full LAN or east-west visibility merely from their labels.

Runtime behavior is covered by a deterministic local FRITZ!Box HTTP fixture,
including login, discovery, one-byte-fragmented PCAP streaming, Ethernet link
validation, and delivery into the ordinary passive pipeline. No claim is made
for a particular physical model or firmware release; the undocumented endpoints
may still require compatibility updates.
