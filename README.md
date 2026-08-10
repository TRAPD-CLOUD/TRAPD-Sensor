# TRAPD Network Sensor

Ein eigenständiger, ressourcenschonender Netzwerksensor für Homelabs und
Unternehmensnetze. Er erkennt Geräte, Dienste und Netzbeziehungen, normalisiert
das Ergebnis und schickt es an das TRAPD-Backend. Der Sensor selbst enthält
keine Plattform — er beobachtet und meldet.

> **Status:** frühe Entwicklung (v0.1). Die passive Erfassung, die
> Offline-Pufferung und die Backend-Anbindung stehen; siehe
> [Stand der Umsetzung](#stand-der-umsetzung).

---

## Was er tut

**Passiv** (sendet nichts):

- ARP/NDP — IP↔MAC-Zuordnung aus dem laufenden Verkehr
- DHCP — Hostname, Vendor-Klasse und Option-55-Fingerprint
- mDNS — Gerätenamen und beworbene Dienste
- SSDP/UPnP — Gerätetyp und Stack-Kennung
- DNS — beobachtete Abfragen (abschaltbar, siehe [Privacy](#privacy))
- Flow-Metadaten — Byte-/Paketzähler je 5-Tupel und Zeitfenster
- VLAN-Erkennung aus 802.1Q-Tags
- Offene Ports aus beobachteten SYN-ACKs — ohne ein einziges gesendetes Paket

**Aktiv** (nur nach ausdrücklicher Freigabe):

- ICMP-Erreichbarkeit
- TCP-Connect auf einem definierten Port-Katalog
- Banner offener Dienste (nur `active`-Modus)

**Was er ausdrücklich nicht tut:** kein Full-Packet-Capture, keine
Payload-Inspektion, kein SYN-Stealth, kein Erraten von Zugangsdaten, keine
Schwachstellen-Tests. Der Sensor stellt fest, was da ist — er sondiert nicht,
wie man hineinkommt.

---

## Installation

```bash
# Paket installieren (siehe packaging/)
sudo install -m 0755 target/release/trapd-sensord    /usr/bin/
sudo install -m 0755 target/release/trapd-sensorctl  /usr/bin/

sudo install -m 0644 packaging/systemd/trapd-sensor.service  /etc/systemd/system/
sudo install -m 0644 packaging/systemd/trapd-sensor.sysusers /usr/lib/sysusers.d/trapd-sensor.conf
sudo install -m 0644 packaging/systemd/trapd-sensor.tmpfiles /usr/lib/tmpfiles.d/trapd-sensor.conf
sudo systemd-sysusers && sudo systemd-tmpfiles --create

sudo install -m 0640 -g trapd-sensor packaging/config.example.toml /etc/trapd-sensor/config.toml
sudoedit /etc/trapd-sensor/config.toml
```

Enrollment mit einem Einmal-Token aus dem Dashboard:

```bash
sudo -u trapd-sensor trapd-sensorctl enroll --token enroll_xxxxxxxxxxxx
sudo systemctl enable --now trapd-sensor
trapd-sensorctl status
```

Vor dem ersten Start lohnt sich:

```bash
trapd-sensorctl diagnose     # Konfiguration, Rechte, Interfaces, Speicher
trapd-sensord --check        # zeigt, was der Sensor mit dieser Config täte
```

---

## Rechte

Der Sensor läuft **nicht als root**. Er braucht genau zwei Capabilities:

| Capability | Wofür | Wann nötig |
|---|---|---|
| `CAP_NET_RAW` | AF_PACKET-Socket, ICMP-Proben | immer |
| `CAP_NET_ADMIN` | Promiscuous Mode | nur bei `capture.promiscuous = true` |

Die systemd-Unit vergibt sie über `AmbientCapabilities` und deckelt mit
`CapabilityBoundingSet` alles Übrige. Ohne systemd:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/trapd-sensord
```

Der Admin-Endpunkt hört auf `127.0.0.1:9531` — Port über 1024, damit kein
`CAP_NET_BIND_SERVICE` nötig ist.

---

## Betriebsmodi

| Modus | Sendet Pakete | Geeignet für |
|---|---|---|
| `passive_only` | nie | SPAN-/Mirror-Port, sensible Umgebungen |
| `balanced` | ICMP + Port-Allowlist | Homelab-Standard |
| `active` | freier Port-Katalog, Banner, SNMP | bewusste Inventarisierung |

Aktive Erkennung braucht **drei unabhängige Freigaben**:

1. `sensor.mode` erlaubt es (`balanced` oder `active`),
2. `active.enabled = true`,
3. `active.acknowledged = true` — die Zusage des Betreibers, dass dieser Host
   in diesem Netz sondieren darf,

und ein Ziel muss in `active.targets` liegen. Fehlt eines davon, wird kein
Paket gesendet; `trapd-sensorctl status` nennt dann den Grund.

### Was das Dashboard steuern darf

Das Backend kann im laufenden Betrieb Module an- und abschalten, Ziele, Ports
und Rate-Limits setzen, SNMP-Communities hinterlegen und Auto-Update umlegen.

Zwei Dinge kann es **nicht**: den Betriebsmodus anheben und die aktive
Erkennung quittieren. Beides bleibt in der Datei auf dem Host. Damit ist der
Modus eine lokale Obergrenze — ein übernommenes Backend kann aus einem
`passive_only`-Sensor keinen Scanner machen. Der Preis ist eine einmalige
Handlung auf dem Host, bevor aktive Erkennung möglich wird; die Zustimmung zum
Senden von Paketen gehört dorthin, wo die Pakete entstehen.

---

## Privacy

Der Sensor läuft in privaten Netzen. Entsprechend ist er gebaut:

- **Kein Full-Packet-Capture.** Nicht als abgeschaltete Option — der Codepfad
  existiert nicht. Verkehr wird zu Zählern verdichtet, nicht gespeichert.
- **Nur benannte Klartextfelder** werden gelesen: DHCP-Optionen, mDNS/SSDP-
  Kopfzeilen, DNS-Query-Namen. Es gibt keinen generischen Payload-Pfad.
- **DNS ist vollständig abschaltbar** (`privacy.dns_observation = false`), mit
  Ausschlusslisten für Domains und Clients und optionaler Pseudonymisierung der
  Namen.
- **`LOCATION`-URLs aus SSDP werden gemeldet, aber nie abgerufen.**
- Banner werden auf 256 Byte gekappt und auf druckbares ASCII reduziert.

---

## Offline-Betrieb

Fällt das Backend aus, arbeitet der Sensor weiter. Events gehen zuerst auf die
Platte und werden erst nach bestätigtem Upload freigegeben (at-least-once;
Doppel fängt das Backend über `event_id` ab).

- Write-Ahead-Log mit CRC je Record; ein Absturz kostet höchstens den gerade
  halb geschriebenen Eintrag.
- Drei Prioritätsstufen: Statusmeldungen überleben, Flow-Daten fallen zuerst.
- Harte Platten-Obergrenze (`buffer.max_disk_bytes`, Vorgabe 256 MiB). Sie gilt
  ausnahmslos — ein Backend-Ausfall darf keinen Host volllaufen lassen.
- Exponentielles Backoff mit Jitter, damit nicht alle Sensoren eines Tenants im
  Gleichtakt gegen ein wiederanlaufendes Backend rennen.

---

## Beobachtbarkeit

```
http://127.0.0.1:9531/admin/health    Liveness (hängt an nichts)
http://127.0.0.1:9531/admin/ready     Readiness mit Begründung
http://127.0.0.1:9531/admin/metrics   Prometheus
http://127.0.0.1:9531/admin/status    JSON, Grundlage von `sensorctl status`
```

`/admin/health` hängt bewusst an keiner Abhängigkeit: ein Backend-Ausfall darf
keinen Neustart auslösen, der Sensor puffert ja gerade.

---

## Aufbau

```
crates/
  sensor-core         Konfiguration, Policy, Beobachtungsmodell, Identität
  sensor-buffer       Segmentiertes WAL mit prioritätsbewusster Retention
  sensor-transport    Enrollment, Upload, Remote-Config, Backoff
  sensor-capture      AF_PACKET-Socket, Interface-Erkennung
  sensor-passive      Protokoll-Parser und Flow-Aggregation
  sensor-fingerprint  Mehrstufige, gewichtete Geräteerkennung
  sensor-active       Rate-limitierte aktive Proben
  sensor-daemon       trapd-sensord
  sensor-cli          trapd-sensorctl
packaging/            systemd-Unit, sysusers, tmpfiles, Beispielkonfiguration
```

Datenfluss:

```
capture(iface) ─┐
sweep           ├──▶ processor ──▶ WAL-Queue ──▶ uploader ──▶ ingest-gateway
heartbeat       ─┘       │
                         └──▶ registry ──▶ Fingerprints
```

---

## Entwicklung

```bash
cargo build --workspace
cargo test  --workspace
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Die Protokoll-Parser sind reine Funktionen über Byte-Slices und vollständig
ohne Netzwerk oder erhöhte Rechte testbar — dort liegt der Großteil der Tests.

---

## Stand der Umsetzung

Umgesetzt:

- passive Erfassung (ARP, DHCP, mDNS, SSDP, DNS, Flows, VLAN)
- Fingerprinting Stufe 1–3 mit Confidence-Aggregation und Belegen
- persistente Queue mit Prioritäten und Platten-Obergrenze
- Enrollment, Bearer-Auth, Batch-Upload, Remote-Config
- aktive Erkennung: ICMP, TCP-Connect, Banner, Rate-Limit, Scope-Prüfung
- systemd-Packaging mit Least-Privilege-Härtung

Geplant:

- SNMP-Discovery (Konfiguration und Policy sind vorhanden, die Abfrage fehlt)
- mTLS mit Zertifikatsrotation und Pinning (v0.1 nutzt Bearer-Token)
- signierter Self-Update-Mechanismus mit Rollback-Schutz
- eBPF-Capture-Backend für hohe Lasten (heute AF_PACKET mit Userspace-Filter)
- IPv6-ICMP und NDP-Auswertung

---

## Lizenz

Apache-2.0 — siehe [LICENSE](LICENSE).
