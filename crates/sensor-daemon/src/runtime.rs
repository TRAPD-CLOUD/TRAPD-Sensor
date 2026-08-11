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
use trapd_sensor_capture::fritzbox::{retry_delay, FritzBoxClient, PcapStreamDecoder, SecretStore};
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

        // Wo der Sensor hängt und was er dort sehen kann — einmal beim Start
        // berechnet, danach über `/admin/status` abrufbar. Im Log steht es,
        // weil "der Sensor meldet keine DNS-Abfragen" sonst als Fehlersuche
        // beginnt statt als Blick in die Auskunft.
        let visibility = self.config.visibility();
        tracing::info!(
            edition = visibility.edition.as_str(),
            profile = visibility.profile.as_str(),
            vantage = visibility.vantage.as_str(),
            configured = visibility.configured,
            "network vantage point"
        );
        self.state.set_deployment(deployment_status(&visibility));

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
        self.state.set_interfaces_configured(
            (interfaces.len()
                + if self.config.capture.fritzbox.enabled {
                    self.config.capture.fritzbox.interfaces.len()
                } else {
                    0
                }) as u64,
        );
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
        if opened == 0 && !self.config.capture.fritzbox.enabled {
            self.state
                .mark_unhealthy("no capture interface could be opened");
            return Err(anyhow::anyhow!("no capture interface could be opened"));
        }

        // Remote providers are recoverable producers: each configured router
        // interface supervises itself and never participates in the critical
        // task select below.
        let mut fritzbox_handles = tokio::task::JoinSet::new();
        if self.config.capture.fritzbox.enabled {
            let fb = self.config.capture.fritzbox.clone();
            self.state
                .init_fritzbox(fb.address.clone(), fb.interfaces.clone());
            for interface in fb.interfaces.clone() {
                fritzbox_handles.spawn(run_fritzbox_capture(
                    interface,
                    fb.clone(),
                    FritzBoxCaptureContext {
                        policy: policy.clone(),
                        flow_window_secs: self.config.capture.flow_window_secs,
                        max_tracked_flows: self.config.capture.max_tracked_flows,
                        obs_tx: obs_tx.clone(),
                        state: self.state.clone(),
                    },
                    producer_shutdown.clone(),
                ));
            }
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
            while let Some(result) = fritzbox_handles.join_next().await {
                if let Err(error) = result {
                    tracing::error!(%error, "FRITZ!Box capture task join failed during shutdown");
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

/// Die Deployment-/Sichtbarkeitsauskunft für `/admin/status`.
///
/// Bewusst dieselbe Herleitung wie `trapd-sensorctl visibility`: die eine
/// Quelle ist [`VisibilityReport`](trapd_sensor_core::visibility::VisibilityReport),
/// hier nur anders verpackt — Dashboard und CLI dürfen sich nicht
/// widersprechen.
fn deployment_status(
    report: &trapd_sensor_core::visibility::VisibilityReport,
) -> serde_json::Value {
    let capabilities: serde_json::Map<String, serde_json::Value> = report
        .capabilities
        .iter()
        .map(|capability| {
            (
                capability.id.to_string(),
                serde_json::json!({
                    "level": capability.level.as_str(),
                    "reason": capability.reason,
                }),
            )
        })
        .collect();

    serde_json::json!({
        "edition": report.edition.as_str(),
        "profile": report.profile.as_str(),
        "vantage": report.vantage.as_str(),
        "configured": report.configured,
        "visibility": capabilities,
        "notes": report.notes,
    })
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

struct FritzBoxCaptureContext {
    policy: trapd_sensor_core::config::EffectivePolicy,
    flow_window_secs: u64,
    max_tracked_flows: usize,
    obs_tx: mpsc::Sender<Observation>,
    state: Arc<SensorState>,
}

async fn run_fritzbox_capture(
    interface_id: String,
    config: trapd_sensor_core::config::FritzBoxCaptureConfig,
    context: FritzBoxCaptureContext,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut attempt = 0u32;
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        context.state.update_fritzbox(|h| {
            h.state = "authenticating".into();
            h.last_error_code = None;
        });
        let result = run_fritzbox_session(&interface_id, &config, &context, &mut shutdown).await;
        let auth_failure = matches!(&result, Err(code) if code == "authentication_failed" || code == "credentials_unavailable");
        if *shutdown.borrow() {
            return Ok(());
        }
        let delay = retry_delay(attempt, auth_failure);
        attempt = attempt.saturating_add(1);
        context.state.update_fritzbox(|h| {
            if h.active_interfaces.is_empty() {
                h.state = "backoff".into();
            }
            h.current_backoff_secs = delay.as_secs();
            h.reconnect_count += 1;
            h.last_error_code = result.err();
        });
        tokio::select! { _ = tokio::time::sleep(delay) => {}, _ = shutdown.changed() => if *shutdown.borrow() { return Ok(()); } }
    }
}

async fn run_fritzbox_session(
    interface_id: &str,
    config: &trapd_sensor_core::config::FritzBoxCaptureConfig,
    context: &FritzBoxCaptureContext,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<(), String> {
    let credentials = SecretStore::new(&config.credentials_file)
        .load()
        .map_err(|_| "credentials_unavailable".to_string())?;
    let client = FritzBoxClient::new(
        &config.address,
        Duration::from_secs(config.connect_timeout_secs),
        Duration::from_secs(config.read_timeout_secs),
    )
    .map_err(|_| "invalid_address".to_string())?;
    let session = client.authenticate(&credentials).await.map_err(|error| {
        context.state.update_fritzbox(|h| h.auth_failure_count += 1);
        tracing::warn!(interface = interface_id, error = %error, "FRITZ!Box authentication failed");
        "authentication_failed".to_string()
    })?;
    context.state.update_fritzbox(|h| {
        h.authenticated = true;
        h.last_successful_auth = Some(chrono::Utc::now().to_rfc3339());
        h.state = "discovering".into();
    });
    let interfaces = session
        .capture_interfaces()
        .await
        .map_err(|error| {
            tracing::warn!(interface = interface_id, error = %error, "FRITZ!Box interface discovery failed");
            "interface_discovery_failed".to_string()
        })?;
    let interface = interfaces
        .into_iter()
        .find(|candidate| candidate.id == interface_id && candidate.available)
        .ok_or_else(|| "configured_interface_unavailable".to_string())?;
    context
        .state
        .update_fritzbox(|h| h.state = "connecting".into());
    let mut response = session
        .start_capture(&interface, config.max_packet_bytes)
        .await
        .map_err(|error| {
            tracing::warn!(interface = interface_id, error = %error, "FRITZ!Box capture endpoint failed");
            "capture_endpoint_failed".to_string()
        })?;
    let response_diagnostic = trapd_sensor_capture::fritzbox::describe_capture_response(&response);
    // `target` pinned to the capture crate so `RUST_LOG=trapd_sensor_capture=debug`
    // (the documented way to see capture diagnostics) enables this line too,
    // even though it is logged from the daemon crate.
    tracing::debug!(target: "trapd_sensor_capture", interface = interface_id, response = %response_diagnostic, "FRITZ!Box capture response received");
    let mut decoder = PcapStreamDecoder::new(config.max_packet_bytes);
    // Only the first bytes of the stream, and only until the decoder proves the
    // stream is real PCAP — captured traffic payloads must never be logged.
    let mut preview: Vec<u8> = Vec::with_capacity(64);
    let mut header_logged = false;
    let mut observer = PassiveObserver::new(
        format!("fritzbox:{interface_id}"),
        context.policy.clone(),
        context.flow_window_secs,
        context.max_tracked_flows,
    );
    let mut active = false;
    let result = 'capture: loop {
        let chunk = tokio::select! {
            result = response.chunk() => match result {
                Ok(chunk) => chunk,
                Err(_) => {
                    context
                        .state
                        .update_fritzbox(|h| h.stream_error_count += 1);
                    break 'capture Err("stream_error".to_string());
                }
            },
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break 'capture Ok(());
                }
                continue;
            }
        };
        let Some(chunk) = chunk else {
            context.state.update_fritzbox(|h| h.stream_error_count += 1);
            break 'capture Err("stream_eof".into());
        };
        if decoder.link_type().is_none() && preview.len() < 64 {
            let take = (64 - preview.len()).min(chunk.len());
            preview.extend_from_slice(&chunk[..take]);
        }
        let push_result = decoder.push(&chunk);
        // After push, not before: a single chunk can carry the global header
        // and the first packet together, in which case the header only
        // becomes known as a side effect of this push call.
        if !header_logged {
            header_logged = trapd_sensor_capture::fritzbox::log_pcap_format_if_known(&decoder);
        }
        let packets = match push_result {
            Ok(packets) => packets,
            Err(error) => {
                context.state.update_fritzbox(|h| h.parser_error_count += 1);
                let reason = trapd_sensor_capture::fritzbox::classify_non_pcap(
                    &response_diagnostic.content_type,
                    &preview,
                );
                tracing::warn!(
                    interface = interface_id,
                    error = %error,
                    reason = %reason,
                    response = %response_diagnostic,
                    "FRITZ!Box capture stream did not decode as PCAP"
                );
                tracing::debug!(
                    target: "trapd_sensor_capture",
                    interface = interface_id,
                    preview = %trapd_sensor_capture::fritzbox::preview_stream_bytes(&preview),
                    "FRITZ!Box capture stream preview"
                );
                break 'capture Err("malformed_pcap".to_string());
            }
        };
        if let Some(link_type) = decoder.link_type() {
            if link_type != trapd_sensor_capture::fritzbox::LINKTYPE_ETHERNET {
                break 'capture Err("unsupported_link_type".into());
            }
        }
        for packet in packets {
            if !active {
                active = true;
                context.state.fritzbox_interface_up(interface_id);
            }
            let bytes = packet.data.len() as u64;
            context.state.add_capture_bytes(bytes);
            context.state.update_fritzbox(|h| {
                h.packets_received += 1;
                h.bytes_received += bytes;
                h.last_packet_at = Some(chrono::Utc::now().to_rfc3339());
            });
            for observation in observer.handle_frame(&packet.data, chrono::Utc::now()) {
                if context.obs_tx.send(observation).await.is_err() {
                    break 'capture Ok(());
                }
            }
        }
        for observation in observer.expire(chrono::Utc::now()) {
            if context.obs_tx.send(observation).await.is_err() {
                break 'capture Ok(());
            }
        }
    };

    for observation in observer.drain() {
        if context.obs_tx.send(observation).await.is_err() {
            break;
        }
    }
    if active {
        context.state.fritzbox_interface_down(interface_id);
    }
    result
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

#[cfg(test)]
mod fritzbox_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn pcap() -> Vec<u8> {
        let frame: [u8; 42] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 1, 2, 3, 4, 5, 0x08, 0x06, 0, 1, 0x08, 0, 6, 4,
            0, 2, 0, 1, 2, 3, 4, 5, 192, 168, 1, 2, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1,
        ];
        let mut bytes = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 1, 0, 0, 0,
        ];
        bytes.extend([1, 0, 0, 0, 0, 0, 0, 0, 42, 0, 0, 0, 42, 0, 0, 0]);
        bytes.extend(frame);
        bytes
    }

    /// Global header bytes captured directly from a FRITZ!Box 5590 Fiber's
    /// own `fritz.box/#/cap` capture UI (`fritzbox-vcc0_11.08.26_1736.eth`),
    /// independently identified by Linux `file(1)` as "pcap capture file,
    /// microsecond ts, extensions (little-endian) - version 2.4 (Ethernet,
    /// capture length 2048)". Confirms this is the real router output, not a
    /// synthetic approximation — see `docs/fritzbox.md`.
    fn extended_pcap() -> Vec<u8> {
        let frame: [u8; 42] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 1, 2, 3, 4, 5, 0x08, 0x06, 0, 1, 0x08, 0, 6, 4,
            0, 2, 0, 1, 2, 3, 4, 5, 192, 168, 1, 2, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1,
        ];
        // magic, version_major=2, version_minor=4, thiszone=0, sigfigs=0,
        // snaplen=2048, linktype=LINKTYPE_ETHERNET.
        let mut bytes = vec![0x34u8, 0xcd, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        bytes.extend(2048u32.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        assert_eq!(bytes.len(), 24);
        // Extended per-record header: ts_sec, ts_usec, incl_len, orig_len,
        // ifindex, protocol, pkt_type, pad — see PcapVariant::Extended.
        bytes.extend(1u32.to_le_bytes()); // ts_sec
        bytes.extend(0u32.to_le_bytes()); // ts_usec
        bytes.extend((frame.len() as u32).to_le_bytes()); // incl_len
        bytes.extend((frame.len() as u32).to_le_bytes()); // orig_len
        bytes.extend(0u32.to_le_bytes()); // ifindex
        bytes.extend(1u16.to_le_bytes()); // protocol
        bytes.push(4); // pkt_type
        bytes.push(0); // pad
        bytes.extend(frame);
        bytes
    }

    async fn fixture(body_for_step_3: Vec<u8>) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            for step in 0..4 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = vec![0; 4096];
                let _ = stream.read(&mut request).await.unwrap();
                let body=match step {0=>"<SessionInfo><Challenge>12345678</Challenge><SID>0000000000000000</SID></SessionInfo>".as_bytes().to_vec(),1=>"<SessionInfo><SID>0123456789abcdef</SID></SessionInfo>".as_bytes().to_vec(),2=>br#"<input name="capture" value="lan"> LAN"#.to_vec(),_=>body_for_step_3.clone()};
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(header.as_bytes()).await.unwrap();
                if step == 3 {
                    for byte in body {
                        stream.write_all(&[byte]).await.unwrap();
                    }
                } else {
                    stream.write_all(&body).await.unwrap();
                }
            }
        });
        (format!("http://{address}"), task)
    }

    async fn run_pipeline_test(pcap_bytes: Vec<u8>, max_packet_bytes: usize) {
        let (address, server) = fixture(pcap_bytes).await;
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret");
        SecretStore::new(&secret)
            .save(&trapd_sensor_capture::fritzbox::Credentials {
                username: "sensor".into(),
                password: "secret".into(),
            })
            .unwrap();
        let config = trapd_sensor_core::config::FritzBoxCaptureConfig {
            enabled: true,
            address,
            interfaces: vec!["lan".into()],
            credentials_file: secret,
            connect_timeout_secs: 2,
            read_timeout_secs: 2,
            max_packet_bytes,
        };
        let state = Arc::new(SensorState::new("test".into(), "balanced".into()));
        state.init_fritzbox(config.address.clone(), config.interfaces.clone());
        let (tx, mut rx) = mpsc::channel(8);
        let (_shutdown_tx, mut shutdown) = watch::channel(false);
        let context = FritzBoxCaptureContext {
            policy: trapd_sensor_core::config::SensorConfig::default().effective_policy(),
            flow_window_secs: 60,
            max_tracked_flows: 50_000,
            obs_tx: tx,
            state: state.clone(),
        };
        let result = run_fritzbox_session("lan", &config, &context, &mut shutdown).await;
        assert_eq!(result, Err("stream_eof".into()));
        assert!(rx.recv().await.is_some());
        let status: serde_json::Value = serde_json::from_str(&state.render_status_json()).unwrap();
        assert_eq!(
            status["capture_providers"]["fritzbox"]["packets_received"],
            1
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn remote_pcap_enters_the_existing_passive_pipeline() {
        run_pipeline_test(pcap(), 64).await;
    }

    /// Regression test for the real FRITZ!Box compatibility bug: a genuine
    /// router capture using the extended/Kuznetsov-modified pcap variant
    /// (magic `34 cd b2 a1`) must decode and reach the passive pipeline the
    /// same way a standard-variant capture does — previously this failed
    /// with "invalid PCAP stream".
    #[tokio::test]
    async fn remote_extended_pcap_enters_the_existing_passive_pipeline() {
        run_pipeline_test(extended_pcap(), 2048).await;
    }
}
