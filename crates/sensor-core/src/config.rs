//! Sensor-Konfiguration (`/etc/trapd-sensor/config.toml`) und das daraus
//! abgeleitete, *bereits durch den Betriebsmodus gefilterte* Regelwerk.
//!
//! Zwei Ebenen, bewusst getrennt:
//!
//! * [`SensorConfig`] ist das, was auf der Platte steht bzw. was das Backend als
//!   Remote-Config schickt — reine Wünsche.
//! * [`EffectivePolicy`] ist das, was der Daemon tatsächlich tun darf. Der
//!   Betriebsmodus ([`SensorMode`]) ist dabei eine **Obergrenze**, keine
//!   Voreinstellung: was der Modus nicht erlaubt, kann keine Config-Option und
//!   keine Backend-Antwort wieder anschalten.
//!
//! Diese Trennung ist der Kern der "defensive by default"-Zusage. Aktive
//! Erkennung erfordert *drei* unabhängige Ja: Modus ≥ Balanced, `enabled = true`
//! und ein explizit gesetztes `acknowledged = true`.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::deployment::DeploymentConfig;
use crate::error::{Result, SensorError};

/// Default-Pfad der Konfigurationsdatei.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/trapd-sensor/config.toml";

// ---------------------------------------------------------------------------
// Betriebsmodus
// ---------------------------------------------------------------------------

/// Betriebsmodus des Sensors. Ordnung: `PassiveOnly < Balanced < Active`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorMode {
    /// Nur Beobachtung. Der Sensor sendet kein einziges Paket ins Netz.
    /// Der richtige Modus für SPAN-/Mirror-Ports und für Umgebungen, in denen
    /// jede aktive Probe erklärungsbedürftig wäre.
    PassiveOnly,
    /// Standard für Homelabs: passive Erkennung plus zurückhaltende aktive
    /// Ergänzung (ICMP, TCP-Connect auf einer kurzen Port-Allowlist).
    #[default]
    Balanced,
    /// Erweiterte aktive Erkennung — größerer Port-Katalog, Banner-Grab, SNMP.
    /// Muss zusätzlich quittiert werden (siehe [`ActiveDiscoveryConfig`]).
    Active,
}

impl SensorMode {
    /// Darf der Modus überhaupt Pakete aktiv erzeugen?
    pub fn allows_active(self) -> bool {
        self >= Self::Balanced
    }

    /// Darf der Modus die erweiterten (auffälligeren) Verfahren nutzen —
    /// Banner-Grab, SNMP, freier Port-Katalog?
    pub fn allows_extended_active(self) -> bool {
        self == Self::Active
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PassiveOnly => "passive_only",
            Self::Balanced => "balanced",
            Self::Active => "active",
        }
    }
}

// ---------------------------------------------------------------------------
// Konfigurationsstruktur
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SensorConfig {
    pub sensor: SensorIdentityConfig,
    /// Wie und wo dieser Sensor im Netz hängt. Fehlt der Abschnitt, gelten die
    /// konservativen Vorgaben (siehe [`DeploymentConfig`]) — bestehende
    /// Konfigurationen bleiben dadurch unverändert gültig.
    pub deployment: DeploymentConfig,
    pub backend: BackendConfig,
    pub capture: CaptureConfig,
    pub passive: PassiveDiscoveryConfig,
    pub active: ActiveDiscoveryConfig,
    pub privacy: PrivacyConfig,
    pub buffer: BufferConfig,
    pub update: UpdateConfig,
    pub admin: AdminConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SensorIdentityConfig {
    /// Anzeigename im Dashboard. Nur kosmetisch — die Identität ist die
    /// `sensor_id` aus dem Enrollment.
    pub name: String,
    /// Freitext-Standort ("Rack 2", "Home"), landet in `network_sensor_configs.site`.
    pub site: Option<String>,
    pub mode: SensorMode,
    /// Verzeichnis für Identity/Secrets. Muss dem Service-User gehören.
    pub state_dir: PathBuf,
}

impl Default for SensorIdentityConfig {
    fn default() -> Self {
        Self {
            name: default_sensor_name(),
            site: None,
            mode: SensorMode::default(),
            state_dir: PathBuf::from("/var/lib/trapd-sensor"),
        }
    }
}

fn default_sensor_name() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "trapd-sensor".to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackendConfig {
    /// Control-Plane (Enrollment, Remote-Config, Update-Manifest).
    pub api_url: String,
    /// Ingest-Gateway. Getrennt konfigurierbar, weil beide in Produktion hinter
    /// verschiedenen Hostnamen/LBs liegen.
    pub ingest_url: String,
    /// Maximale Events pro Upload-Batch.
    pub batch_max_events: usize,
    /// Spätestens nach dieser Zeit wird auch ein unvollständiger Batch gesendet.
    pub flush_interval_secs: u64,
    /// Abstand zwischen zwei Remote-Config-Abrufen.
    pub config_poll_interval_secs: u64,
    /// Heartbeat-Intervall.
    pub heartbeat_interval_secs: u64,
    /// Timeout je HTTP-Request.
    pub request_timeout_secs: u64,
    /// Optionale SHA-256-Pins der akzeptierten CA-Zertifikate (Base64/Hex).
    /// Leer = normale Systemvertrauenskette.
    pub tls_ca_pins_sha256: Vec<String>,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            api_url: "https://api.trapd.io".into(),
            ingest_url: "https://ingest.trapd.io".into(),
            batch_max_events: 500,
            flush_interval_secs: 10,
            config_poll_interval_secs: 300,
            heartbeat_interval_secs: 60,
            request_timeout_secs: 30,
            tls_ca_pins_sha256: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CaptureConfig {
    /// Zu belauschende Interfaces. Leer = Auto-Detect (alle aktiven, nicht-Loopback).
    pub interfaces: Vec<String>,
    /// Promiscuous Mode. Für SPAN-/Mirror-Ports erforderlich, benötigt `CAP_NET_ADMIN`.
    pub promiscuous: bool,
    /// Bytes, die je Paket aus dem Kernel geholt werden. Bewusst klein: der
    /// Sensor liest Header und ausgewählte Klartext-Felder, keine Payloads.
    pub snaplen: usize,
    /// Aggregationsfenster für Flow-Metadaten.
    pub flow_window_secs: u64,
    /// Obergrenze gleichzeitig verfolgter Flows (Cardinality-Schutz).
    pub max_tracked_flows: usize,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interfaces: Vec::new(),
            promiscuous: true,
            snaplen: 512,
            flow_window_secs: 60,
            max_tracked_flows: 50_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PassiveDiscoveryConfig {
    pub arp: bool,
    pub dhcp: bool,
    pub mdns: bool,
    pub ssdp: bool,
    pub dns: bool,
    pub flows: bool,
}

impl Default for PassiveDiscoveryConfig {
    fn default() -> Self {
        Self {
            arp: true,
            dhcp: true,
            mdns: true,
            ssdp: true,
            dns: true,
            flows: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ActiveDiscoveryConfig {
    /// Aktive Erkennung gewünscht.
    pub enabled: bool,
    /// Bewusste Quittierung durch den Betreiber. Ohne dieses Flag bleibt aktive
    /// Erkennung aus, auch wenn `enabled = true` und der Modus es erlauben würde.
    /// Absicht: ein kopiertes Config-Snippet soll nicht versehentlich in einem
    /// fremden Netz scannen.
    pub acknowledged: bool,
    /// Erlaubte Ziel-Netze in CIDR-Notation. **Leer bedeutet: nichts scannen.**
    /// Es gibt bewusst kein "scanne, was du siehst".
    pub targets: Vec<String>,
    /// Netze, die auch innerhalb von `targets` nie berührt werden.
    pub exclude: Vec<String>,
    /// Globales Probe-Budget pro Sekunde über alle aktiven Module.
    pub rate_limit_per_sec: u32,
    pub icmp: bool,
    pub tcp_connect: bool,
    /// Port-Katalog für den TCP-Connect-Probe. Im Balanced-Modus wird zusätzlich
    /// auf [`BALANCED_PORT_ALLOWLIST`] geschnitten.
    pub ports: Vec<u16>,
    /// Banner nach erfolgreichem Connect lesen (nur `Active`).
    pub banner_grab: bool,
    /// Ein voller Sweep-Durchlauf höchstens alle N Sekunden.
    pub sweep_interval_secs: u64,
    pub snmp: SnmpConfig,
}

impl Default for ActiveDiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            acknowledged: false,
            targets: Vec::new(),
            exclude: Vec::new(),
            rate_limit_per_sec: 5,
            icmp: true,
            tcp_connect: true,
            ports: BALANCED_PORT_ALLOWLIST.to_vec(),
            banner_grab: false,
            sweep_interval_secs: 3_600,
            snmp: SnmpConfig::default(),
        }
    }
}

/// Ports, die im Balanced-Modus angefasst werden dürfen: durchweg Dienste, deren
/// bloße Erreichbarkeit ohnehin Teil des Netzbetriebs ist. Kein Datenbank-,
/// Management- oder OT-Port — dort ist schon ein Connect-Versuch unhöflich.
pub const BALANCED_PORT_ALLOWLIST: &[u16] = &[
    22,   // SSH
    53,   // DNS
    80,   // HTTP
    139,  // NetBIOS Session
    443,  // HTTPS
    445,  // SMB
    515,  // LPD
    631,  // IPP
    8080, // HTTP alt
    8443, // HTTPS alt
    9100, // JetDirect
];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SnmpConfig {
    pub enabled: bool,
    /// Community-Strings. Bewusst ohne Default: der Sensor probiert **nie** von
    /// sich aus `public`/`private` durch — das wäre Credential-Guessing und
    /// genau die Grenze zum Scanner-Werkzeug, die dieses Produkt nicht
    /// überschreitet.
    pub communities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivacyConfig {
    /// DNS-Beobachtung überhaupt aktiv. Die sensibelste Quelle des Sensors —
    /// abschaltbar, ohne den Rest zu verlieren.
    pub dns_observation: bool,
    /// Query-Namen dieser Domains (Suffix-Match) werden verworfen.
    pub dns_exclude_domains: Vec<String>,
    /// Traffic dieser Clients wird gar nicht erst betrachtet.
    pub exclude_clients: Vec<String>,
    /// Aufgelöste Antwort-IPs mitschicken. Aus = nur der Query-Name.
    pub store_dns_answers: bool,
    /// Query-Namen vor dem Senden hashen. Erhält Korrelierbarkeit
    /// ("derselbe Name wie gestern") ohne den Namen preiszugeben.
    pub hash_dns_names: bool,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            dns_observation: true,
            dns_exclude_domains: Vec::new(),
            exclude_clients: Vec::new(),
            store_dns_answers: true,
            hash_dns_names: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BufferConfig {
    pub dir: PathBuf,
    /// Harte Obergrenze der Queue auf der Platte. Wird sie erreicht, verwirft
    /// der Sensor Events (niedrigste Priorität zuerst) statt zu wachsen.
    pub max_disk_bytes: u64,
    /// Zielgröße eines WAL-Segments.
    pub segment_bytes: u64,
    /// Obergrenze der In-Memory-Übergabe zwischen Collectors und Uploader.
    pub channel_capacity: usize,
}

impl Default for BufferConfig {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("/var/lib/trapd-sensor/queue"),
            max_disk_bytes: 256 * 1024 * 1024,
            segment_bytes: 8 * 1024 * 1024,
            channel_capacity: 10_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpdateConfig {
    /// Selbsttätiges Einspielen von Updates. Default aus; im Dashboard
    /// umschaltbar (die Remote-Config überschreibt dieses Feld).
    pub auto_update: bool,
    pub channel: String,
    pub check_interval_secs: u64,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            auto_update: false,
            channel: "stable".into(),
            check_interval_secs: 21_600,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    /// Health-/Metrics-Listener. Loopback-Default und Port > 1024, damit der
    /// Sensor ohne `CAP_NET_BIND_SERVICE` auskommt.
    pub listen: String,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:9531".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Laden & Validieren
// ---------------------------------------------------------------------------

impl SensorConfig {
    /// Lädt die Konfiguration. Eine fehlende Datei ist kein Fehler — dann gelten
    /// die Defaults (Balanced, aktive Erkennung aus).
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            tracing::info!(path = %path.display(), "config file not found, using defaults");
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path).map_err(|source| SensorError::ConfigRead {
            path: path.to_path_buf(),
            source,
        })?;
        let cfg: Self = toml::from_str(&raw).map_err(|source| SensorError::ConfigParse {
            path: path.to_path_buf(),
            source,
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        self.deployment.validate().map_err(SensorError::Config)?;
        if self.backend.api_url.trim().is_empty() {
            return Err(SensorError::Config(
                "backend.api_url must not be empty".into(),
            ));
        }
        if self.backend.ingest_url.trim().is_empty() {
            return Err(SensorError::Config(
                "backend.ingest_url must not be empty".into(),
            ));
        }
        // Klartext-HTTP würde Sensor-Secret und Telemetrie offenlegen. Für lokale
        // Entwicklung bleibt Loopback erlaubt, sonst ist TLS Pflicht.
        for url in [&self.backend.api_url, &self.backend.ingest_url] {
            if url.starts_with("http://") && !is_loopback_url(url) {
                return Err(SensorError::Config(format!(
                    "refusing plaintext HTTP backend url {url} — use https:// (loopback is exempt)"
                )));
            }
        }
        if self.backend.batch_max_events == 0 {
            return Err(SensorError::Config(
                "backend.batch_max_events must be > 0".into(),
            ));
        }
        if self.backend.request_timeout_secs == 0 {
            return Err(SensorError::Config(
                "backend.request_timeout_secs must be > 0".into(),
            ));
        }
        if self.buffer.channel_capacity == 0 {
            return Err(SensorError::Config(
                "buffer.channel_capacity must be > 0".into(),
            ));
        }
        if self.buffer.max_disk_bytes < self.buffer.segment_bytes {
            return Err(SensorError::Config(
                "buffer.max_disk_bytes must be >= buffer.segment_bytes".into(),
            ));
        }
        if self.capture.snaplen < 64 {
            return Err(SensorError::Config("capture.snaplen must be >= 64".into()));
        }
        if self.active.enabled && self.active.rate_limit_per_sec == 0 {
            return Err(SensorError::Config(
                "active.rate_limit_per_sec must be > 0 when active discovery is enabled".into(),
            ));
        }
        for community in &self.active.snmp.communities {
            if community.is_empty()
                || community.len() > 128
                || community.chars().any(char::is_control)
            {
                return Err(SensorError::Config(
                    "SNMP communities must contain 1..=128 non-control characters".into(),
                ));
            }
        }
        for cidr in self.active.targets.iter().chain(self.active.exclude.iter()) {
            Cidr::parse(cidr).map_err(|e| {
                SensorError::Config(format!("invalid CIDR '{cidr}' in active discovery: {e}"))
            })?;
        }
        Ok(())
    }

    /// Verrechnet Konfiguration und Betriebsmodus zu dem, was der Daemon
    /// tatsächlich ausführen darf.
    pub fn effective_policy(&self) -> EffectivePolicy {
        EffectivePolicy::derive(self)
    }

    /// Was der Sensor an diesem Anschluss überhaupt sehen kann.
    pub fn visibility(&self) -> crate::visibility::VisibilityReport {
        crate::visibility::VisibilityReport::derive(self)
    }
}

fn is_loopback_url(url: &str) -> bool {
    let rest = url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let host = rest
        .split('/')
        .next()
        .unwrap_or("")
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or_else(|| rest.split('/').next().unwrap_or(""));
    host == "localhost"
        || host
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Effektive Policy
// ---------------------------------------------------------------------------

/// Was der Daemon tun darf — bereits durch den Modus geschnitten.
#[derive(Debug, Clone)]
pub struct EffectivePolicy {
    pub mode: SensorMode,
    pub passive: PassiveDiscoveryConfig,
    /// `None` = keinerlei aktive Erkennung.
    pub active: Option<EffectiveActivePolicy>,
    pub privacy: PrivacyConfig,
    /// Grund, warum aktive Erkennung (falls konfiguriert) trotzdem aus ist —
    /// für Log und Health-Endpoint, damit "warum scannt er nicht?" ohne
    /// Rätselraten beantwortbar ist.
    pub active_disabled_reason: Option<&'static str>,
}

#[derive(Debug, Clone)]
pub struct EffectiveActivePolicy {
    pub targets: Vec<Cidr>,
    pub exclude: Vec<Cidr>,
    pub rate_limit_per_sec: u32,
    pub icmp: bool,
    pub tcp_connect: bool,
    pub ports: Vec<u16>,
    pub banner_grab: bool,
    pub sweep_interval_secs: u64,
    pub snmp_communities: Vec<String>,
}

impl EffectivePolicy {
    fn derive(cfg: &SensorConfig) -> Self {
        let mode = cfg.sensor.mode;
        let mut privacy = cfg.privacy.clone();
        let mut passive = cfg.passive.clone();

        // Privacy-Schalter schlägt Modul-Schalter.
        if !privacy.dns_observation {
            passive.dns = false;
        }
        if !passive.dns {
            privacy.dns_observation = false;
        }

        let (active, reason) = Self::derive_active(cfg, mode);
        Self {
            mode,
            passive,
            active,
            privacy,
            active_disabled_reason: reason,
        }
    }

    fn derive_active(
        cfg: &SensorConfig,
        mode: SensorMode,
    ) -> (Option<EffectiveActivePolicy>, Option<&'static str>) {
        if !mode.allows_active() {
            return (None, Some("sensor mode is passive_only"));
        }
        if !cfg.active.enabled {
            return (None, Some("active.enabled is false"));
        }
        if !cfg.active.acknowledged {
            return (
                None,
                Some("active.acknowledged is false — set it to confirm you own this network"),
            );
        }

        // Ohne Ziel-CIDR gibt es nichts zu tun. Der Sensor leitet Ziele bewusst
        // nicht aus dem beobachteten Traffic ab: sonst würde ein an einen
        // Uplink gehängter Sensor fremde Netze anfassen.
        let targets: Vec<Cidr> = cfg
            .active
            .targets
            .iter()
            .filter_map(|c| Cidr::parse(c).ok())
            .collect();
        if targets.is_empty() {
            return (None, Some("active.targets is empty"));
        }
        let exclude: Vec<Cidr> = cfg
            .active
            .exclude
            .iter()
            .filter_map(|c| Cidr::parse(c).ok())
            .collect();

        let extended = mode.allows_extended_active();

        // Balanced schneidet den Port-Katalog auf die Allowlist. Wer mehr will,
        // muss in den Active-Modus wechseln — sichtbar und auditierbar.
        let allow: BTreeSet<u16> = BALANCED_PORT_ALLOWLIST.iter().copied().collect();
        let mut ports: Vec<u16> = if extended {
            cfg.active.ports.clone()
        } else {
            cfg.active
                .ports
                .iter()
                .copied()
                .filter(|p| allow.contains(p))
                .collect()
        };
        ports.sort_unstable();
        ports.dedup();

        let snmp_communities = if extended && cfg.active.snmp.enabled {
            cfg.active.snmp.communities.clone()
        } else {
            Vec::new()
        };

        (
            Some(EffectiveActivePolicy {
                targets,
                exclude,
                rate_limit_per_sec: cfg.active.rate_limit_per_sec.max(1),
                icmp: cfg.active.icmp,
                tcp_connect: cfg.active.tcp_connect && !ports.is_empty(),
                ports,
                banner_grab: cfg.active.banner_grab && extended,
                sweep_interval_secs: cfg.active.sweep_interval_secs.max(60),
                snmp_communities,
            }),
            None,
        )
    }

    /// Darf dieses Ziel aktiv angefasst werden? Einzige Stelle, die das
    /// entscheidet — alle aktiven Module fragen hier.
    pub fn may_probe(&self, ip: IpAddr) -> bool {
        let Some(active) = &self.active else {
            return false;
        };
        if active.exclude.iter().any(|c| c.contains(ip)) {
            return false;
        }
        active.targets.iter().any(|c| c.contains(ip))
    }
}

// ---------------------------------------------------------------------------
// CIDR
// ---------------------------------------------------------------------------

/// Minimaler CIDR-Typ für v4 und v6. Bewusst selbst implementiert statt einer
/// weiteren Abhängigkeit — der benötigte Umfang ist genau "parsen und
/// enthält-Test".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> std::result::Result<Self, String> {
        let s = s.trim();
        let (addr_part, prefix_part) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr_part
            .parse()
            .map_err(|_| format!("'{addr_part}' is not an IP address"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_part {
            Some(p) => p
                .parse::<u8>()
                .map_err(|_| format!("'{p}' is not a prefix length"))?,
            None => max,
        };
        if prefix > max {
            return Err(format!("prefix /{prefix} exceeds /{max}"));
        }
        Ok(Self {
            network: mask(addr, prefix),
            prefix,
        })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                mask(ip, self.prefix) == self.network
            }
            _ => false,
        }
    }

    pub fn network(&self) -> IpAddr {
        self.network
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Anzahl adressierbarer Hosts — Grundlage für die Sweep-Budgetierung.
    /// `None`, wenn das Netz zu groß ist, um es sinnvoll zu durchlaufen.
    pub fn host_count(&self) -> Option<u64> {
        let max = if self.network.is_ipv4() { 32 } else { 128 };
        let bits = max - self.prefix as u32;
        if bits > 20 {
            return None;
        }
        Some(1u64 << bits)
    }

    /// Iteriert die Adressen des Netzes. Nur für v4 und nur für Netze, die
    /// [`Self::host_count`] als durchlaufbar meldet.
    pub fn hosts(&self) -> Vec<IpAddr> {
        let IpAddr::V4(net) = self.network else {
            return Vec::new();
        };
        let Some(count) = self.host_count() else {
            return Vec::new();
        };
        let base = u32::from(net);
        // Netz- und Broadcast-Adresse auslassen, außer bei /31 und /32.
        let (start, end) = if count <= 2 {
            (0, count)
        } else {
            (1, count - 1)
        };
        (start..end)
            .map(|i| IpAddr::V4(std::net::Ipv4Addr::from(base + i as u32)))
            .collect()
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

fn mask(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let m = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix as u32)
            };
            IpAddr::V4(std::net::Ipv4Addr::from(bits & m))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let m = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix as u32)
            };
            IpAddr::V6(std::net::Ipv6Addr::from(bits & m))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test ip")
    }

    #[test]
    fn cidr_contains_v4() {
        let c = Cidr::parse("192.168.1.0/24").expect("parse");
        assert!(c.contains(ip("192.168.1.1")));
        assert!(c.contains(ip("192.168.1.255")));
        assert!(!c.contains(ip("192.168.2.1")));
        assert!(!c.contains(ip("::1")));
    }

    #[test]
    fn cidr_bare_address_is_single_host() {
        let c = Cidr::parse("10.0.0.5").expect("parse");
        assert_eq!(c.prefix(), 32);
        assert!(c.contains(ip("10.0.0.5")));
        assert!(!c.contains(ip("10.0.0.6")));
    }

    #[test]
    fn cidr_rejects_garbage() {
        assert!(Cidr::parse("not-an-ip/24").is_err());
        assert!(Cidr::parse("192.168.1.0/33").is_err());
    }

    #[test]
    fn cidr_hosts_skips_network_and_broadcast() {
        let c = Cidr::parse("192.168.1.0/30").expect("parse");
        let hosts = c.hosts();
        assert_eq!(hosts, vec![ip("192.168.1.1"), ip("192.168.1.2")]);
    }

    #[test]
    fn cidr_hosts_refuses_huge_networks() {
        let c = Cidr::parse("10.0.0.0/8").expect("parse");
        assert!(c.host_count().is_none());
        assert!(c.hosts().is_empty());
    }

    #[test]
    fn passive_only_mode_never_probes() {
        let mut cfg = SensorConfig::default();
        cfg.sensor.mode = SensorMode::PassiveOnly;
        cfg.active.enabled = true;
        cfg.active.acknowledged = true;
        cfg.active.targets = vec!["192.168.1.0/24".into()];

        let policy = cfg.effective_policy();
        assert!(policy.active.is_none());
        assert!(!policy.may_probe(ip("192.168.1.10")));
    }

    #[test]
    fn active_requires_acknowledgement() {
        let mut cfg = SensorConfig::default();
        cfg.sensor.mode = SensorMode::Active;
        cfg.active.enabled = true;
        cfg.active.targets = vec!["192.168.1.0/24".into()];
        // acknowledged bleibt false
        let policy = cfg.effective_policy();
        assert!(policy.active.is_none());
        assert_eq!(
            policy.active_disabled_reason,
            Some("active.acknowledged is false — set it to confirm you own this network")
        );
    }

    #[test]
    fn balanced_mode_clamps_ports_and_disables_extended_features() {
        let mut cfg = SensorConfig::default();
        cfg.sensor.mode = SensorMode::Balanced;
        cfg.active.enabled = true;
        cfg.active.acknowledged = true;
        cfg.active.targets = vec!["192.168.1.0/24".into()];
        cfg.active.ports = vec![22, 3389, 5432, 443];
        cfg.active.banner_grab = true;
        cfg.active.snmp.enabled = true;
        cfg.active.snmp.communities = vec!["secret".into()];

        let policy = cfg.effective_policy();
        let active = policy.active.expect("active policy");
        assert_eq!(active.ports, vec![22, 443], "non-allowlisted ports dropped");
        assert!(!active.banner_grab, "banner grab is active-mode only");
        assert!(
            active.snmp_communities.is_empty(),
            "snmp is active-mode only"
        );
    }

    #[test]
    fn active_mode_keeps_configured_ports() {
        let mut cfg = SensorConfig::default();
        cfg.sensor.mode = SensorMode::Active;
        cfg.active.enabled = true;
        cfg.active.acknowledged = true;
        cfg.active.targets = vec!["192.168.1.0/24".into()];
        cfg.active.ports = vec![3389, 22];
        cfg.active.banner_grab = true;

        let active = cfg.effective_policy().active.expect("active policy");
        assert_eq!(active.ports, vec![22, 3389]);
        assert!(active.banner_grab);
    }

    #[test]
    fn exclude_wins_over_target() {
        let mut cfg = SensorConfig::default();
        cfg.sensor.mode = SensorMode::Balanced;
        cfg.active.enabled = true;
        cfg.active.acknowledged = true;
        cfg.active.targets = vec!["192.168.0.0/16".into()];
        cfg.active.exclude = vec!["192.168.99.0/24".into()];

        let policy = cfg.effective_policy();
        assert!(policy.may_probe(ip("192.168.1.5")));
        assert!(!policy.may_probe(ip("192.168.99.5")));
        assert!(!policy.may_probe(ip("10.0.0.1")), "outside every target");
    }

    #[test]
    fn empty_targets_disable_active_discovery() {
        let mut cfg = SensorConfig::default();
        cfg.sensor.mode = SensorMode::Active;
        cfg.active.enabled = true;
        cfg.active.acknowledged = true;
        let policy = cfg.effective_policy();
        assert!(policy.active.is_none());
        assert_eq!(
            policy.active_disabled_reason,
            Some("active.targets is empty")
        );
    }

    #[test]
    fn privacy_switch_disables_dns_module() {
        let mut cfg = SensorConfig::default();
        cfg.privacy.dns_observation = false;
        let policy = cfg.effective_policy();
        assert!(!policy.passive.dns);
    }

    #[test]
    fn plaintext_backend_url_is_rejected_but_loopback_allowed() {
        let mut cfg = SensorConfig::default();
        cfg.backend.api_url = "http://api.example.com".into();
        assert!(cfg.validate().is_err());

        cfg.backend.api_url = "http://127.0.0.1:8080".into();
        cfg.backend.ingest_url = "http://localhost:8082".into();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn default_config_roundtrips_through_toml() {
        let cfg = SensorConfig::default();
        let text = toml::to_string(&cfg).expect("serialize");
        let parsed: SensorConfig = toml::from_str(&text).expect("deserialize");
        assert_eq!(parsed.sensor.mode, cfg.sensor.mode);
        assert_eq!(parsed.buffer.max_disk_bytes, cfg.buffer.max_disk_bytes);
    }
}
