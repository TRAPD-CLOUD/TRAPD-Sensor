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

pub struct SensorState {
    pub sensor_id: String,
    pub uptime: Uptime,
    pub uploader: Arc<UploaderStats>,

    mode: Mutex<String>,
    interfaces_up: AtomicU64,
    interfaces_configured: AtomicU64,
    packets_captured: AtomicU64,
    packets_dropped: AtomicU64,
    observations_emitted: AtomicU64,
    devices_tracked: AtomicU64,
    sweeps_completed: AtomicU64,
    config_version: AtomicU64,
    enabled: AtomicBool,
    /// Grund, warum aktive Erkennung aus ist (falls sie es ist).
    active_disabled_reason: Mutex<Option<String>>,
    last_error: Mutex<Option<String>>,
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
            observations_emitted: AtomicU64::new(0),
            devices_tracked: AtomicU64::new(0),
            sweeps_completed: AtomicU64::new(0),
            config_version: AtomicU64::new(0),
            enabled: AtomicBool::new(true),
            active_disabled_reason: Mutex::new(None),
            last_error: Mutex::new(None),
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

    pub fn add_observations(&self, count: u64) {
        self.observations_emitted
            .fetch_add(count, Ordering::Relaxed);
    }

    pub fn set_devices_tracked(&self, count: u64) {
        self.devices_tracked.store(count, Ordering::Relaxed);
    }

    pub fn record_sweep(&self) {
        self.sweeps_completed.fetch_add(1, Ordering::Relaxed);
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
        (true, "ok".into())
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

        let mut counter = |name: &str, help: &str, value: u64| {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"
            ));
        };

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

        let value = serde_json::json!({
            "sensor_id": self.sensor_id,
            "version": trapd_sensor_core::VERSION,
            "mode": self.mode(),
            "enabled": self.is_enabled(),
            "ready": ready,
            "readiness_reason": reason,
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
        s.record_sweep();

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
