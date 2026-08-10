//! Der gemeinsam gelesene Zustand des Daemons.
//!
//! Alle Tasks schreiben hier ihre Zähler hinein, der Admin-Endpunkt und der
//! Heartbeat lesen sie. Ausschließlich Atomics und ein kurz gehaltener Mutex
//! für Zeichenketten — kein Task soll je auf einen anderen warten, nur um eine
//! Zahl hochzuzählen.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use trapd_sensor_transport::UploaderStats;

use crate::admin::Uptime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    Healthy,
    Degraded,
    Unhealthy,
}

impl HealthState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
        }
    }
    fn metric(self) -> u64 {
        match self {
            Self::Healthy => 0,
            Self::Degraded => 1,
            Self::Unhealthy => 2,
        }
    }
}

pub struct SensorState {
    pub sensor_id: String,
    pub uptime: Uptime,
    pub uploader: Arc<UploaderStats>,

    mode: Mutex<String>,
    interfaces_up: AtomicU64,
    interfaces_configured: AtomicU64,
    packets_captured: AtomicU64,
    packets_dropped: AtomicU64,
    capture_bytes: AtomicU64,
    parser_errors: AtomicU64,
    observations_emitted: AtomicU64,
    devices_tracked: AtomicU64,
    sweeps_completed: AtomicU64,
    config_version: AtomicU64,
    enabled: AtomicBool,
    /// Grund, warum aktive Erkennung aus ist (falls sie es ist).
    active_disabled_reason: Mutex<Option<String>>,
    last_error: Mutex<Option<String>>,
    unhealthy: AtomicBool,
    remote_config_errors: AtomicU64,
    remote_config_ok: AtomicBool,
    task_failures: AtomicU64,
    active_probes: AtomicU64,
    active_probe_errors: AtomicU64,
    snmp_queries: AtomicU64,
    snmp_errors: AtomicU64,
}

impl SensorState {
    pub fn new(sensor_id: String, mode: String) -> Self {
        Self {
            sensor_id,
            uptime: Uptime::start(),
            uploader: Arc::new(UploaderStats::default()),
            mode: Mutex::new(mode),
            interfaces_up: AtomicU64::new(0),
            interfaces_configured: AtomicU64::new(0),
            packets_captured: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            capture_bytes: AtomicU64::new(0),
            parser_errors: AtomicU64::new(0),
            observations_emitted: AtomicU64::new(0),
            devices_tracked: AtomicU64::new(0),
            sweeps_completed: AtomicU64::new(0),
            config_version: AtomicU64::new(0),
            enabled: AtomicBool::new(true),
            active_disabled_reason: Mutex::new(None),
            last_error: Mutex::new(None),
            unhealthy: AtomicBool::new(false),
            remote_config_errors: AtomicU64::new(0),
            remote_config_ok: AtomicBool::new(true),
            task_failures: AtomicU64::new(0),
            active_probes: AtomicU64::new(0),
            active_probe_errors: AtomicU64::new(0),
            snmp_queries: AtomicU64::new(0),
            snmp_errors: AtomicU64::new(0),
        }
    }

    pub fn mode(&self) -> String {
        self.mode.lock().map(|m| m.clone()).unwrap_or_default()
    }

    pub fn set_interfaces_up(&self, count: u64) {
        self.interfaces_up.store(count, Ordering::Relaxed);
    }

    pub fn set_interfaces_configured(&self, count: u64) {
        self.interfaces_configured.store(count, Ordering::Relaxed);
    }

    pub fn add_packets(&self, captured: u64, dropped: u64) {
        self.packets_captured.store(captured, Ordering::Relaxed);
        self.packets_dropped.store(dropped, Ordering::Relaxed);
    }
    pub fn add_capture_bytes(&self, bytes: u64) {
        self.capture_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
    pub fn set_parser_errors(&self, errors: u64) {
        self.parser_errors.store(errors, Ordering::Relaxed);
    }

    pub fn add_observations(&self, count: u64) {
        self.observations_emitted
            .fetch_add(count, Ordering::Relaxed);
    }

    pub fn set_devices_tracked(&self, count: u64) {
        self.devices_tracked.store(count, Ordering::Relaxed);
    }

    pub fn record_sweep(&self, stats: trapd_sensor_active::SweepStats) {
        self.sweeps_completed.fetch_add(1, Ordering::Relaxed);
        self.active_probes
            .fetch_add(stats.probes_total as u64, Ordering::Relaxed);
        self.active_probe_errors
            .fetch_add(stats.probe_errors as u64, Ordering::Relaxed);
        self.snmp_queries
            .fetch_add(stats.snmp_queries as u64, Ordering::Relaxed);
        self.snmp_errors
            .fetch_add(stats.snmp_errors as u64, Ordering::Relaxed);
    }

    pub fn set_config_version(&self, version: u64) {
        self.config_version.store(version, Ordering::Relaxed);
    }

    pub fn config_version(&self) -> u64 {
        self.config_version.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_active_disabled_reason(&self, reason: Option<String>) {
        if let Ok(mut slot) = self.active_disabled_reason.lock() {
            *slot = reason;
        }
    }

    pub fn set_last_error(&self, error: Option<String>) {
        if let Ok(mut slot) = self.last_error.lock() {
            *slot = error;
        }
    }

    pub fn mark_unhealthy(&self, error: impl Into<String>) {
        self.unhealthy.store(true, Ordering::Relaxed);
        self.task_failures.fetch_add(1, Ordering::Relaxed);
        self.set_last_error(Some(error.into()));
    }

    pub fn record_remote_config_error(&self) {
        self.remote_config_errors.fetch_add(1, Ordering::Relaxed);
        self.remote_config_ok.store(false, Ordering::Relaxed);
    }
    pub fn record_remote_config_success(&self) {
        self.remote_config_ok.store(true, Ordering::Relaxed);
    }

    pub fn health(&self) -> (HealthState, String) {
        if self.unhealthy.load(Ordering::Relaxed) {
            return (
                HealthState::Unhealthy,
                self.last_error
                    .lock()
                    .ok()
                    .and_then(|e| e.clone())
                    .unwrap_or_else(|| "critical subsystem failed".into()),
            );
        }
        if self.interfaces_up.load(Ordering::Relaxed) == 0 {
            return (HealthState::Unhealthy, "no capture interface is up".into());
        }
        let uploader = self.uploader.snapshot();
        if (uploader.backend_requests > 0 && !uploader.backend_available)
            || !self.remote_config_ok.load(Ordering::Relaxed)
            || self.packets_dropped.load(Ordering::Relaxed) > 0
        {
            return (
                HealthState::Degraded,
                "capture is available, but a recoverable subsystem reports errors".into(),
            );
        }
        (HealthState::Healthy, "ok".into())
    }

    /// Ist der Sensor betriebsbereit? Der Grund gehört zur Antwort — eine
    /// nackte 503 zwingt zum Log-Wühlen.
    pub fn readiness(&self) -> (bool, String) {
        if !self.is_enabled() {
            return (false, "sensor is disabled by the backend".into());
        }
        if self.interfaces_up.load(Ordering::Relaxed) == 0 {
            return (
                false,
                "no capture interface is up — check permissions (CAP_NET_RAW) and configuration"
                    .into(),
            );
        }
        let (health, reason) = self.health();
        (health != HealthState::Unhealthy, reason)
    }

    pub fn render_prometheus(&self) -> String {
        let uploader = self.uploader.snapshot();
        let mut out = String::new();

        let mut gauge = |name: &str, help: &str, value: u64| {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}\n"
            ));
        };

        gauge(
            "trapd_sensor_up",
            "1 while the daemon state is available.",
            1,
        );
        gauge(
            "trapd_wal_bytes",
            "Bytes occupied by the WAL.",
            uploader.queue_bytes,
        );
        gauge(
            "trapd_wal_records",
            "Records currently pending in the WAL.",
            uploader.queue_pending,
        );
        gauge(
            "trapd_sensor_health_state",
            "Health state: 0 healthy, 1 degraded, 2 unhealthy.",
            self.health().0.metric(),
        );
        gauge(
            "trapd_sensor_interfaces_up",
            "Capture interfaces currently receiving packets.",
            self.interfaces_up.load(Ordering::Relaxed),
        );
        gauge(
            "trapd_sensor_interfaces_configured",
            "Capture interfaces the sensor was asked to use.",
            self.interfaces_configured.load(Ordering::Relaxed),
        );
        gauge(
            "trapd_sensor_devices_tracked",
            "Devices currently held in the fingerprint registry.",
            self.devices_tracked.load(Ordering::Relaxed),
        );
        gauge(
            "trapd_sensor_queue_pending_events",
            "Events buffered on disk waiting for upload.",
            uploader.queue_pending,
        );
        gauge(
            "trapd_sensor_queue_disk_bytes",
            "Bytes the on-disk event queue currently occupies.",
            uploader.queue_bytes,
        );
        gauge(
            "trapd_sensor_config_version",
            "Version of the remote configuration currently applied.",
            self.config_version.load(Ordering::Relaxed),
        );
        gauge(
            "trapd_sensor_enabled",
            "1 when the backend has the sensor enabled.",
            u64::from(self.is_enabled()),
        );
        gauge(
            "trapd_sensor_uptime_seconds",
            "Seconds since the sensor started.",
            self.uptime.secs(),
        );
        gauge(
            "trapd_backend_latency_seconds",
            "Latency of the most recent backend request in seconds.",
            uploader.backend_latency_micros / 1_000_000,
        );

        let mut counter = |name: &str, help: &str, value: u64| {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"
            ));
        };

        counter(
            "trapd_sensor_task_failures_total",
            "Unexpected critical task failures.",
            self.task_failures.load(Ordering::Relaxed),
        );
        counter(
            "trapd_capture_packets_total",
            "Packets read from capture sockets.",
            self.packets_captured.load(Ordering::Relaxed),
        );
        counter(
            "trapd_capture_bytes_total",
            "Bytes read from capture sockets.",
            self.capture_bytes.load(Ordering::Relaxed),
        );
        counter(
            "trapd_capture_kernel_drops_total",
            "Packets dropped by the capture socket in the kernel.",
            self.packets_dropped.load(Ordering::Relaxed),
        );
        counter(
            "trapd_events_generated_total",
            "Normalized events generated.",
            self.observations_emitted.load(Ordering::Relaxed),
        );
        counter(
            "trapd_events_queued_total",
            "Events accepted by the WAL.",
            uploader.events_accepted,
        );
        counter(
            "trapd_events_uploaded_total",
            "Events accepted by the backend.",
            uploader.events_uploaded,
        );
        counter(
            "trapd_events_dropped_total",
            "Events evicted or permanently rejected.",
            uploader.events_dropped,
        );
        counter(
            "trapd_backend_requests_total",
            "Backend batch requests.",
            uploader.backend_requests,
        );
        counter(
            "trapd_backend_errors_total",
            "Backend batch errors.",
            uploader.upload_failures,
        );
        counter(
            "trapd_active_probes_total",
            "Active probes attempted.",
            self.active_probes.load(Ordering::Relaxed),
        );
        counter(
            "trapd_active_probe_errors_total",
            "Active probe errors.",
            self.active_probe_errors.load(Ordering::Relaxed),
        );
        counter(
            "trapd_snmp_queries_total",
            "SNMP GET requests attempted.",
            self.snmp_queries.load(Ordering::Relaxed),
        );
        counter(
            "trapd_snmp_errors_total",
            "SNMP request errors.",
            self.snmp_errors.load(Ordering::Relaxed),
        );
        counter(
            "trapd_parser_errors_total",
            "Frames rejected by the passive parser.",
            self.parser_errors.load(Ordering::Relaxed),
        );
        counter(
            "trapd_task_restarts_total",
            "Supervised task restarts (restart policy is currently process-level).",
            0,
        );
        counter(
            "trapd_sensor_packets_captured_total",
            "Packets read from the capture sockets.",
            self.packets_captured.load(Ordering::Relaxed),
        );
        counter(
            "trapd_sensor_packets_dropped_total",
            "Packets the kernel dropped before the sensor could read them.",
            self.packets_dropped.load(Ordering::Relaxed),
        );
        counter(
            "trapd_sensor_observations_total",
            "Observations produced by the discovery modules.",
            self.observations_emitted.load(Ordering::Relaxed),
        );
        counter(
            "trapd_sensor_events_uploaded_total",
            "Events accepted by the backend.",
            uploader.events_uploaded,
        );
        counter(
            "trapd_sensor_events_dropped_total",
            "Events lost to queue eviction or permanent backend rejection.",
            uploader.events_dropped,
        );
        counter(
            "trapd_sensor_upload_failures_total",
            "Failed upload attempts.",
            uploader.upload_failures,
        );
        counter(
            "trapd_sensor_sweeps_total",
            "Completed active discovery sweeps.",
            self.sweeps_completed.load(Ordering::Relaxed),
        );

        out
    }

    pub fn render_status_json(&self) -> String {
        let uploader = self.uploader.snapshot();
        let (ready, reason) = self.readiness();
        let (health, health_reason) = self.health();

        let value = serde_json::json!({
            "sensor_id": self.sensor_id,
            "version": trapd_sensor_core::VERSION,
            "mode": self.mode(),
            "enabled": self.is_enabled(),
            "ready": ready,
            "readiness_reason": reason,
            "health": health.as_str(),
            "health_reason": health_reason,
            "uptime_secs": self.uptime.secs(),
            "config_version": self.config_version(),
            "interfaces": {
                "configured": self.interfaces_configured.load(Ordering::Relaxed),
                "up": self.interfaces_up.load(Ordering::Relaxed),
            },
            "packets": {
                "captured": self.packets_captured.load(Ordering::Relaxed),
                "dropped": self.packets_dropped.load(Ordering::Relaxed),
            },
            "devices_tracked": self.devices_tracked.load(Ordering::Relaxed),
            "queue": {
                "pending": uploader.queue_pending,
                "disk_bytes": uploader.queue_bytes,
                "dropped": uploader.events_dropped,
            },
            "uploads": {
                "events": uploader.events_uploaded,
                "batches": uploader.batches_sent,
                "failures": uploader.upload_failures,
            },
            "active_discovery_disabled_reason": self
                .active_disabled_reason
                .lock()
                .ok()
                .and_then(|r| r.clone()),
            "last_error": self.last_error.lock().ok().and_then(|e| e.clone()),
        });

        serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> SensorState {
        SensorState::new("sensor_1".into(), "balanced".into())
    }

    #[test]
    fn a_disabled_sensor_is_not_ready() {
        let s = state();
        s.set_interfaces_up(1);
        assert!(s.readiness().0);

        s.set_enabled(false);
        let (ready, reason) = s.readiness();
        assert!(!ready);
        assert!(reason.contains("disabled"));
    }

    #[test]
    fn readiness_reason_points_at_capabilities_when_no_interface_is_up() {
        let (ready, reason) = state().readiness();
        assert!(!ready);
        assert!(
            reason.contains("CAP_NET_RAW"),
            "the most common cause deserves a direct hint: {reason}"
        );
    }

    #[test]
    fn metrics_expose_every_counter_with_help_and_type() {
        let s = state();
        let rendered = s.render_prometheus();

        for metric in [
            "trapd_sensor_interfaces_up",
            "trapd_sensor_devices_tracked",
            "trapd_sensor_queue_pending_events",
            "trapd_sensor_packets_dropped_total",
            "trapd_sensor_events_uploaded_total",
            "trapd_sensor_sweeps_total",
        ] {
            assert!(
                rendered.contains(&format!("# HELP {metric} ")),
                "{metric} has no HELP line"
            );
            assert!(
                rendered.contains(&format!("# TYPE {metric} ")),
                "{metric} has no TYPE line"
            );
        }
    }

    #[test]
    fn counters_move_when_the_sensor_works() {
        let s = state();
        s.add_packets(1000, 7);
        s.add_observations(12);
        s.add_observations(3);
        s.set_devices_tracked(5);
        s.record_sweep(trapd_sensor_active::SweepStats::default());

        let rendered = s.render_prometheus();
        assert!(rendered.contains("trapd_sensor_packets_captured_total 1000"));
        assert!(rendered.contains("trapd_sensor_packets_dropped_total 7"));
        assert!(rendered.contains("trapd_sensor_observations_total 15"));
        assert!(rendered.contains("trapd_sensor_devices_tracked 5"));
        assert!(rendered.contains("trapd_sensor_sweeps_total 1"));
    }

    #[test]
    fn status_json_carries_the_reason_active_discovery_is_off() {
        let s = state();
        s.set_active_disabled_reason(Some("active.targets is empty".into()));

        let parsed: serde_json::Value =
            serde_json::from_str(&s.render_status_json()).expect("valid json");
        assert_eq!(
            parsed["active_discovery_disabled_reason"],
            "active.targets is empty"
        );
    }

    #[test]
    fn the_operating_mode_is_visible_in_status() {
        let s = SensorState::new("sensor_1".into(), "passive_only".into());
        let parsed: serde_json::Value =
            serde_json::from_str(&s.render_status_json()).expect("valid json");
        assert_eq!(parsed["mode"], "passive_only");
    }
}
