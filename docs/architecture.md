# Architecture

TRAPD Sensor answers **what exists and communicates in the network**. It does
not build the global asset graph or decide final asset state; those remain
backend responsibilities.

Capture tasks feed bounded observation channels. The processor normalizes and
fingerprints observations, then one uploader task owns the segmented WAL and
persists events before upload. Capture and processing are critical tasks;
backend upload and remote configuration are recoverable because the WAL keeps
capture independent from backend availability. Active discovery is optional
and remains under the local mode cap, acknowledgement, CIDR scope, and token
bucket.

Shutdown stops active discovery and capture first, drains observations into the
WAL, closes the uploader channel, flushes the WAL, and finally stops the admin
server. A global timeout prevents systemd stop jobs from hanging indefinitely.

