//! Die Verdrahtung: welche Task tut was, und wie hängen sie zusammen.
//!
//! ```text
//!  capture(eth0) ─┐
//!  capture(eth1) ─┼──▶ processor ──▶ uploader ──▶ Backend
//!  sweep         ─┤      │  ▲
//!  heartbeat     ─┘      │  └── registry (Fingerprints)
//!                        └───── SensorState (Metriken)
//! ```
//!
//! Jede Beobachtung nimmt denselben Weg: sie entsteht in einem Modul, wird vom
//! Processor mit Sequenznummer und Zeitstempel versehen und geht von dort in die
//! Queue. Ein einziger Umwandlungspunkt heißt: eine einzige Sequenzquelle, eine
//! einzige Stelle für Zählung und Fingerprint-Fütterung.
//!
//! Capture ist blockierendes I/O und läuft deshalb in `spawn_blocking`, nicht auf
//! dem Async-Executor — ein `recv()` auf einem stillen Interface würde sonst
//! einen Worker-Thread der Runtime belegen.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use trapd_sensor_active::Scanner;
use trapd_sensor_buffer::EventQueue;
use trapd_sensor_capture::{AfPacketSource, PacketSource};
use trapd_sensor_core::config::SensorConfig;
use trapd_sensor_core::identity::SensorIdentity;
use trapd_sensor_core::model::{
    HeartbeatObservation, InterfaceHealth, Observation, SensorEvent, StatusLevel, StatusObservation,
};
use trapd_sensor_fingerprint::{FingerprintEngine, OuiDatabase};
use trapd_sensor_passive::PassiveObserver;
use trapd_sensor_transport::{
    BackendClient, BackendSink, Uploader, UploaderConfig, UploaderOutcome,
};

use crate::registry::DeviceRegistry;
use crate::state::SensorState;

/// Wie lange ein `recv()` auf einem stillen Interface wartet, bevor die Schleife
/// wieder nach Shutdown und abgelaufenen Flow-Fenstern schaut.
const CAPTURE_READ_TIMEOUT: Duration = Duration::from_millis(500);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(15);

/// Obergrenze der Fingerprint-Registry.
const MAX_TRACKED_DEVICES: usize = 5_000;
/// Nach dieser Zeit ohne Lebenszeichen fliegt ein Gerät aus der Registry.
const DEVICE_TTL_SECS: i64 = 24 * 3600;

pub struct Daemon {
    config: SensorConfig,
    identity: SensorIdentity,
    state: Arc<SensorState>,
}

impl Daemon {
    pub fn new(config: SensorConfig, identity: SensorIdentity) -> Self {
        let state = Arc::new(SensorState::new(
            identity.sensor_id.clone(),
            config.sensor.mode.as_str().to_string(),
        ));
        Self {
            config,
            identity,
            state,
        }
    }

    pub fn state(&self) -> Arc<SensorState> {
        self.state.clone()
    }

    pub async fn run(self, shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
        let policy = self.config.effective_policy();
        self.state
            .set_active_disabled_reason(policy.active_disabled_reason.map(str::to_string));
        if let Some(reason) = policy.active_disabled_reason {
            tracing::info!(reason, "active discovery is not running");
        }

        // --- Queue und Uploader ---
        let queue = EventQueue::open(
            &self.config.buffer.dir,
            self.config.buffer.max_disk_bytes,
            self.config.buffer.segment_bytes,
        )?;

        let client = Arc::new(BackendClient::new(
            self.identity
                .api_url
                .as_deref()
                .unwrap_or(&self.config.backend.api_url),
            self.identity
                .ingest_url
                .as_deref()
                .unwrap_or(&self.config.backend.ingest_url),
            Duration::from_secs(self.config.backend.request_timeout_secs),
        )?);

        let sink = BackendSink::new(client.clone(), &self.identity);
        let uploader = Uploader::new(
            queue,
            sink,
            UploaderConfig::new(
                &self.identity,
                self.config.backend.batch_max_events,
                Duration::from_secs(self.config.backend.flush_interval_secs),
            ),
            self.state.uploader.clone(),
        );

        let (event_tx, event_rx) =
            mpsc::channel::<SensorEvent>(self.config.buffer.channel_capacity);
        let (obs_tx, obs_rx) = mpsc::channel::<Observation>(self.config.buffer.channel_capacity);

        let (producer_shutdown_tx, producer_shutdown) = watch::channel(false);
        let (uploader_shutdown_tx, uploader_shutdown) = watch::channel(false);
        let mut uploader_handle = tokio::spawn(uploader.run(event_rx, uploader_shutdown));

        // --- Processor ---
        let mut processor = tokio::spawn(run_processor(
            obs_rx,
            event_tx.clone(),
            self.state.clone(),
            self.config.sensor.state_dir.clone(),
        ));

        // --- Capture je Interface ---
        let interfaces = trapd_sensor_capture::select_interfaces(&self.config.capture.interfaces);
        self.state
            .set_interfaces_configured(interfaces.len() as u64);
        if interfaces.is_empty() {
            tracing::error!(
                "no capture interface available — the sensor will not observe anything"
            );
        }

        let mut capture_handles = tokio::task::JoinSet::new();
        let mut opened = 0u64;
        for interface in interfaces {
            let observer = PassiveObserver::new(
                interface.clone(),
                policy.clone(),
                self.config.capture.flow_window_secs,
                self.config.capture.max_tracked_flows,
            );
            match AfPacketSource::open(
                &interface,
                self.config.capture.promiscuous,
                CAPTURE_READ_TIMEOUT,
            ) {
                Ok(source) => {
                    opened += 1;
                    capture_handles.spawn(run_capture(
                        source,
                        observer,
                        self.config
                            .capture
                            .snaplen
                            .max(trapd_sensor_capture::RECOMMENDED_SNAPLEN),
                        obs_tx.clone(),
                        self.state.clone(),
                        producer_shutdown.clone(),
                    ));
                }
                Err(e) => {
                    // Ein Interface, das sich nicht öffnen lässt, darf den Sensor
                    // nicht insgesamt lahmlegen — aber es muss sichtbar werden,
                    // und zwar dort, wo jemand hinschaut: im Backend.
                    tracing::error!(interface, error = %e, "cannot capture on this interface");
                    self.state.set_last_error(Some(e.to_string()));
                    let _ = obs_tx
                        .send(Observation::Status(StatusObservation {
                            level: StatusLevel::Error,
                            code: "capture_unavailable".into(),
                            message: e.to_string(),
                            details: [("interface".to_string(), interface.clone())]
                                .into_iter()
                                .collect(),
                        }))
                        .await;
                }
            }
        }
        self.state.set_interfaces_up(opened);
        if opened == 0 {
            self.state
                .mark_unhealthy("no capture interface could be opened");
            return Err(anyhow::anyhow!("no capture interface could be opened"));
        }

        // --- Heartbeat ---
        let heartbeat = tokio::spawn(run_heartbeat(
            obs_tx.clone(),
            self.state.clone(),
            Duration::from_secs(self.config.backend.heartbeat_interval_secs),
            producer_shutdown.clone(),
        ));

        // --- Remote-Config ---
        let config_poll = tokio::spawn(run_config_poll(
            client.clone(),
            self.identity.clone(),
            self.config.clone(),
            self.state.clone(),
            Duration::from_secs(self.config.backend.config_poll_interval_secs),
            producer_shutdown.clone(),
        ));

        // --- Aktive Erkennung ---
        let sweep = Scanner::new(policy.clone()).map(|scanner| {
            tokio::spawn(run_sweeps(
                scanner,
                obs_tx.clone(),
                self.state.clone(),
                Duration::from_secs(
                    policy
                        .active
                        .as_ref()
                        .map(|a| a.sweep_interval_secs)
                        .unwrap_or(3600),
                ),
                producer_shutdown.clone(),
            ))
        });

        // --- Supervisor: critical tasks may never disappear silently. ---
        let mut external_shutdown = shutdown;
        let failure = tokio::select! {
            _ = external_shutdown.changed() => None,
            result = &mut processor => Some(format!("event processor stopped unexpectedly: {}", join_description(result))),
            result = capture_handles.join_next() => Some(format!("capture task stopped unexpectedly: {}", join_option_description(result))),
            result = &mut uploader_handle => {
                match result {
                    Ok(UploaderOutcome::Revoked(reason)) => {
                        self.state.set_enabled(false);
                        Some(format!("sensor revoked: {reason}"))
                    }
                    Ok(UploaderOutcome::Shutdown) => Some("uploader stopped unexpectedly".into()),
                    Err(error) => Some(format!("uploader task failed: {error}")),
                }
            }
        };
        if let Some(error) = &failure {
            self.state.mark_unhealthy(error.clone());
            tracing::error!(
                event = "task_failed",
                subsystem = "supervisor",
                error,
                "critical runtime task failed"
            );
        } else {
            tracing::info!(
                event = "shutdown_started",
                subsystem = "supervisor",
                "graceful shutdown requested"
            );
        }

        let shutdown_result = tokio::time::timeout(SHUTDOWN_TIMEOUT, async {
            // Stop all producers first, so their bounded channels can drain.
            let _ = producer_shutdown_tx.send(true);
            while let Some(result) = capture_handles.join_next().await {
                if let Err(error) = result {
                    tracing::error!(%error, "capture task join failed during shutdown");
                }
            }
            let _ = heartbeat.await;
            let _ = config_poll.await;
            if let Some(sweep) = sweep {
                let _ = sweep.await;
            }
            drop(obs_tx);
            if !processor.is_finished() {
                let _ = (&mut processor).await;
            }
            drop(event_tx);
            // Channel closure lets the uploader persist every remaining event.
            if !uploader_handle.is_finished() {
                let _ = (&mut uploader_handle).await;
            }
            let _ = uploader_shutdown_tx.send(true);
        })
        .await;
        if shutdown_result.is_err() {
            self.state
                .mark_unhealthy("global shutdown timeout exceeded");
            return Err(anyhow::anyhow!(
                "shutdown exceeded {} seconds",
                SHUTDOWN_TIMEOUT.as_secs()
            ));
        }
        tracing::info!(
            event = "shutdown_complete",
            subsystem = "supervisor",
            "graceful shutdown complete"
        );
        failure.map_or(Ok(()), |error| Err(anyhow::anyhow!(error)))
    }
}

fn join_description(result: Result<(), tokio::task::JoinError>) -> String {
    match result {
        Ok(()) => "returned normally".into(),
        Err(error) => error.to_string(),
    }
}

fn join_option_description(
    result: Option<Result<anyhow::Result<()>, tokio::task::JoinError>>,
) -> String {
    match result {
        Some(Ok(Ok(()))) => "returned normally".into(),
        Some(Ok(Err(error))) => error.to_string(),
        Some(Err(error)) => error.to_string(),
        None => "all capture tasks disappeared".into(),
    }
}

/// Eine Capture-Schleife je Interface.
async fn run_capture(
    mut source: AfPacketSource,
    mut observer: PassiveObserver,
    snaplen: usize,
    obs_tx: mpsc::Sender<Observation>,
    state: Arc<SensorState>,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let mut buf = vec![0u8; snaplen];
        let interface = source.interface().to_string();
        tracing::info!(interface, snaplen, "capture loop started");

        loop {
            if *shutdown.borrow() {
                break;
            }

            match source.recv(&mut buf) {
                Ok(0) => {}
                Ok(n) => {
                    state.add_capture_bytes(n as u64);
                    let now = chrono::Utc::now();
                    for observation in observer.handle_frame(&buf[..n], now) {
                        // `blocking_send` bremst die Capture-Schleife, wenn der
                        // Processor nicht hinterherkommt. Genau das ist der
                        // gewünschte Gegendruck: lieber Pakete vom Kernel
                        // verworfen (und im Zähler sichtbar) als unbegrenzt
                        // wachsender Speicher.
                        if obs_tx.blocking_send(observation).is_err() {
                            return Ok(());
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(interface, error = %e, "capture read failed");
                    state.set_last_error(Some(e.to_string()));
                    return Err(e.into());
                }
            }

            // Abgelaufene Flow-Fenster abgeben.
            for observation in observer.expire(chrono::Utc::now()) {
                if obs_tx.blocking_send(observation).is_err() {
                    return Ok(());
                }
            }

            let stats = source.stats();
            state.add_packets(stats.packets_captured, stats.packets_dropped);
            state.set_parser_errors(observer.parser_errors());
        }

        // Beim Herunterfahren das offene Fenster noch abgeben.
        for observation in observer.drain() {
            if obs_tx.blocking_send(observation).is_err() {
                break;
            }
        }
        tracing::info!(interface, "capture loop stopped");
        Ok(())
    })
    .await??;
    Ok(())
}

/// Der einzige Ort, an dem aus einer Beobachtung ein Event wird.
async fn run_processor(
    mut obs_rx: mpsc::Receiver<Observation>,
    event_tx: mpsc::Sender<SensorEvent>,
    state: Arc<SensorState>,
    state_dir: std::path::PathBuf,
) {
    let oui = OuiDatabase::with_file(&state_dir.join(trapd_sensor_fingerprint::OUI_FILE));
    let mut registry = DeviceRegistry::new(
        FingerprintEngine::new(oui),
        MAX_TRACKED_DEVICES,
        DEVICE_TTL_SECS,
    );
    let mut sequence: u64 = 0;
    let mut fingerprint_ticker = tokio::time::interval(Duration::from_secs(30));
    fingerprint_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            received = obs_rx.recv() => {
                let Some(observation) = received else {
                    break;
                };
                let now = chrono::Utc::now();
                registry.observe(&observation, now);
                state.add_observations(1);

                sequence += 1;
                if event_tx.send(SensorEvent::new(sequence, observation)).await.is_err() {
                    break;
                }
            }

            _ = fingerprint_ticker.tick() => {
                let now = chrono::Utc::now();
                registry.prune(now);
                state.set_devices_tracked(registry.len() as u64);

                for fingerprint in registry.evaluate_dirty() {
                    sequence += 1;
                    let event = SensorEvent::new(sequence, Observation::Fingerprint(fingerprint));
                    if event_tx.send(event).await.is_err() {
                        return;
                    }
                }
            }
        }
    }

    // Was die Registry noch weiß, vor dem Ende abgeben.
    for fingerprint in registry.evaluate_dirty() {
        sequence += 1;
        let event = SensorEvent::new(sequence, Observation::Fingerprint(fingerprint));
        if event_tx.send(event).await.is_err() {
            break;
        }
    }
    tracing::info!("processor stopped");
}

async fn run_heartbeat(
    obs_tx: mpsc::Sender<Observation>,
    state: Arc<SensorState>,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
            _ = ticker.tick() => {
                let uploader = state.uploader.snapshot();
                let heartbeat = HeartbeatObservation {
                    sensor_version: trapd_sensor_core::VERSION.to_string(),
                    mode: state.mode(),
                    uptime_secs: state.uptime.secs(),
                    interfaces: vec![InterfaceHealth {
                        name: "aggregate".into(),
                        up: state.readiness().0,
                        promiscuous: true,
                        packets_captured: 0,
                        packets_dropped: 0,
                    }],
                    queue_depth: uploader.queue_pending,
                    queue_bytes: uploader.queue_bytes,
                    events_emitted: uploader.events_accepted,
                    events_dropped: uploader.events_dropped,
                    active_disabled_reason: None,
                };
                if obs_tx.send(Observation::Heartbeat(heartbeat)).await.is_err() {
                    return;
                }
            }
        }
    }
}

async fn run_config_poll(
    client: Arc<BackendClient>,
    identity: SensorIdentity,
    mut config: SensorConfig,
    state: Arc<SensorState>,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
            _ = ticker.tick() => {
                match client.fetch_config(&identity).await {
                    Ok(remote) => {
                        state.record_remote_config_success();
                        let outcome = remote.apply(&mut config, state.config_version());
                        if outcome.applied {
                            state.set_config_version(remote.config_version);
                            tracing::info!(
                                version = remote.config_version,
                                "applied remote configuration"
                            );
                        }
                        if state.is_enabled() != outcome.enabled {
                            tracing::warn!(
                                enabled = outcome.enabled,
                                "backend changed the sensor's enabled state"
                            );
                            state.set_enabled(outcome.enabled);
                        }
                    }
                    Err(e) => {
                        // Eine nicht erreichbare Control-Plane ist kein Grund,
                        // die Erfassung einzustellen — der Sensor arbeitet mit
                        // der zuletzt gültigen Konfiguration weiter.
                        tracing::warn!(error = %e, "could not fetch remote configuration");
                        state.record_remote_config_error();
                    }
                }
            }
        }
    }
}

async fn run_sweeps(
    mut scanner: Scanner,
    obs_tx: mpsc::Sender<Observation>,
    state: Arc<SensorState>,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    // Der erste Sweep läuft nicht sofort: beim Start soll erst die passive
    // Erkennung ein Bild aufbauen, damit der Sweep bestätigt statt zu raten.
    let mut ticker = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(60),
        interval,
    );
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
            _ = ticker.tick() => {
                if !state.is_enabled() {
                    continue;
                }
                let stats = scanner.sweep(&obs_tx, &mut shutdown).await;
                state.record_sweep(stats);
            }
        }
    }
}
