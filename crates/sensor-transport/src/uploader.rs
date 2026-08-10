//! Der Weg von der Queue zum Backend.
//!
//! Genau eine Task besitzt die [`EventQueue`]: sie nimmt Events der Collector-
//! Module über einen begrenzten Kanal entgegen, schreibt sie auf die Platte und
//! lädt sie stapelweise hoch. Kein geteilter Zustand, kein Mutex um Datei-I/O —
//! und der begrenzte Kanal erzeugt genau den Gegendruck, den ein überlasteter
//! Sensor braucht.
//!
//! Die Reihenfolge ist immer *erst persistieren, dann senden*: bestätigt wird in
//! der Queue erst, wenn das Backend den Batch angenommen hat (at-least-once).
//! Ein Absturz mitten im Upload kostet dadurch keine Events, sondern erzeugt
//! höchstens Doppel — die das Backend über `event_id` abfängt.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use trapd_sensor_buffer::{EventQueue, QueueStats};
use trapd_sensor_core::envelope::{IngestBatch, IngestResponse, WireEvent};
use trapd_sensor_core::identity::{Secret, SensorIdentity};
use trapd_sensor_core::model::SensorEvent;

use crate::backoff::{Backoff, BackoffConfig};
use crate::client::BackendClient;
use crate::error::{Result, TransportError};

/// Abstraktion über den Versand, damit die Schleife ohne HTTP-Server prüfbar ist.
pub trait BatchSink: Send + Sync + 'static {
    fn send_batch(
        &self,
        batch: IngestBatch,
    ) -> impl std::future::Future<Output = Result<IngestResponse>> + Send;
}

/// Produktiv-Sink: schickt an das Ingest-Gateway.
pub struct BackendSink {
    client: Arc<BackendClient>,
    secret: Secret,
}

impl BackendSink {
    pub fn new(client: Arc<BackendClient>, identity: &SensorIdentity) -> Self {
        Self {
            client,
            secret: identity.secret.clone(),
        }
    }
}

impl BatchSink for BackendSink {
    async fn send_batch(&self, batch: IngestBatch) -> Result<IngestResponse> {
        self.client.upload(&self.secret, &batch).await
    }
}

/// Laufende Zähler — vom Heartbeat und vom Admin-Endpoint gelesen.
///
/// Verlorene Events haben zwei getrennte Ursachen, die auch getrennt gezählt
/// werden: von der Queue verdrängt (Platten-Obergrenze) oder vom Uploader
/// verworfen (Backend hat die Nutzlast dauerhaft abgelehnt). Der eine Wert wird
/// aus der Queue *gesetzt*, der andere hochgezählt — auf einem gemeinsamen
/// Zähler würde das Setzen das Hochzählen überschreiben.
#[derive(Debug, Default)]
pub struct UploaderStats {
    pub events_accepted: AtomicU64,
    pub events_uploaded: AtomicU64,
    /// Von der Queue verdrängt (Spiegel von [`QueueStats::dropped`]).
    pub queue_dropped: AtomicU64,
    /// Vom Uploader verworfen, weil das Backend sie endgültig abgelehnt hat.
    pub upload_discarded: AtomicU64,
    pub batches_sent: AtomicU64,
    pub upload_failures: AtomicU64,
    pub queue_pending: AtomicU64,
    pub queue_bytes: AtomicU64,
}

impl UploaderStats {
    fn record_queue(&self, stats: &QueueStats) {
        self.queue_pending.store(stats.pending, Ordering::Relaxed);
        self.queue_bytes.store(stats.disk_bytes, Ordering::Relaxed);
        self.queue_dropped.store(stats.dropped, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> UploaderStatsSnapshot {
        let queue_dropped = self.queue_dropped.load(Ordering::Relaxed);
        let upload_discarded = self.upload_discarded.load(Ordering::Relaxed);
        UploaderStatsSnapshot {
            events_accepted: self.events_accepted.load(Ordering::Relaxed),
            events_uploaded: self.events_uploaded.load(Ordering::Relaxed),
            events_dropped: queue_dropped + upload_discarded,
            queue_dropped,
            upload_discarded,
            batches_sent: self.batches_sent.load(Ordering::Relaxed),
            upload_failures: self.upload_failures.load(Ordering::Relaxed),
            queue_pending: self.queue_pending.load(Ordering::Relaxed),
            queue_bytes: self.queue_bytes.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UploaderStatsSnapshot {
    pub events_accepted: u64,
    pub events_uploaded: u64,
    /// Summe aus [`Self::queue_dropped`] und [`Self::upload_discarded`].
    pub events_dropped: u64,
    pub queue_dropped: u64,
    pub upload_discarded: u64,
    pub batches_sent: u64,
    pub upload_failures: u64,
    pub queue_pending: u64,
    pub queue_bytes: u64,
}

/// Warum die Uploader-Schleife geendet hat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploaderOutcome {
    /// Regulärer Shutdown.
    Shutdown,
    /// Das Backend hat den Sensor abgelehnt oder widerrufen. Der Daemon fährt
    /// daraufhin herunter, statt weiter gegen eine geschlossene Tür zu laufen.
    Revoked(String),
}

pub struct UploaderConfig {
    pub sensor_id: String,
    pub sensor_version: String,
    pub batch_max_events: usize,
    pub flush_interval: Duration,
    pub backoff: BackoffConfig,
}

impl UploaderConfig {
    pub fn new(
        identity: &SensorIdentity,
        batch_max_events: usize,
        flush_interval: Duration,
    ) -> Self {
        Self {
            sensor_id: identity.sensor_id.clone(),
            sensor_version: trapd_sensor_core::VERSION.to_string(),
            batch_max_events: batch_max_events.max(1),
            flush_interval,
            backoff: BackoffConfig::default(),
        }
    }
}

pub struct Uploader<S: BatchSink> {
    queue: EventQueue,
    sink: S,
    config: UploaderConfig,
    stats: Arc<UploaderStats>,
    backoff: Backoff,
}

impl<S: BatchSink> Uploader<S> {
    pub fn new(
        queue: EventQueue,
        sink: S,
        config: UploaderConfig,
        stats: Arc<UploaderStats>,
    ) -> Self {
        let backoff = Backoff::new(config.backoff.clone());
        Self {
            queue,
            sink,
            config,
            stats,
            backoff,
        }
    }

    /// Läuft, bis `shutdown` gesetzt wird, der Event-Kanal schließt oder das
    /// Backend den Sensor widerruft.
    pub async fn run(
        mut self,
        mut events: mpsc::Receiver<SensorEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> UploaderOutcome {
        let mut ticker = tokio::time::interval(self.config.flush_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                biased;

                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("uploader: shutdown requested, draining queue");
                        // Letzter Versuch, das Gepufferte loszuwerden. Schlägt er
                        // fehl, bleibt alles in der Queue und der nächste Start
                        // holt es nach.
                        let _ = self.flush_once().await;
                        let _ = self.queue.flush();
                        return UploaderOutcome::Shutdown;
                    }
                }

                received = events.recv() => {
                    match received {
                        Some(event) => {
                            self.enqueue(event);
                            // Voller Batch beisammen? Dann nicht auf den Timer warten.
                            if self.queue.stats().pending >= self.config.batch_max_events as u64 {
                                if let Some(outcome) = self.flush_once().await {
                                    return outcome;
                                }
                            }
                        }
                        None => {
                            tracing::info!("uploader: event channel closed, draining queue");
                            let _ = self.flush_once().await;
                            let _ = self.queue.flush();
                            return UploaderOutcome::Shutdown;
                        }
                    }
                }

                _ = ticker.tick() => {
                    if let Some(outcome) = self.flush_once().await {
                        return outcome;
                    }
                }
            }
        }
    }

    fn enqueue(&mut self, event: SensorEvent) {
        match self.queue.push(&event) {
            Ok(outcome) => {
                if outcome.stored {
                    self.stats.events_accepted.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "uploader: failed to persist event");
                self.stats.upload_discarded.fetch_add(1, Ordering::Relaxed);
            }
        }
        let stats = self.queue.stats();
        self.stats.record_queue(&stats);
    }

    /// Ein Upload-Versuch. `Some(outcome)` = die Schleife muss enden.
    async fn flush_once(&mut self) -> Option<UploaderOutcome> {
        let batch = match self.queue.read_batch(self.config.batch_max_events) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(error = %e, "uploader: failed to read from queue");
                return None;
            }
        };

        if batch.events.is_empty() {
            // Unlesbare Records trotzdem bestätigen, sonst blockieren sie die Queue.
            if batch.undecodable > 0 {
                let _ = self.queue.commit(&batch);
            }
            return None;
        }

        let wire: Vec<WireEvent> = batch
            .events
            .iter()
            .filter_map(|e| match WireEvent::from_event(e) {
                Ok(w) => Some(w),
                Err(err) => {
                    tracing::error!(error = %err, "uploader: dropping unserializable event");
                    None
                }
            })
            .collect();

        let count = wire.len();
        let payload = IngestBatch::new(
            self.config.sensor_id.clone(),
            self.config.sensor_version.clone(),
            wire,
        );

        match self.sink.send_batch(payload).await {
            Ok(response) => {
                if let Err(e) = self.queue.commit(&batch) {
                    // Der Batch ist beim Backend angekommen, nur das lokale
                    // Bestätigen scheiterte. Beim nächsten Lauf geht er erneut
                    // raus — Doppel sind der akzeptierte Preis, Verlust nicht.
                    tracing::error!(error = %e, "uploader: upload succeeded but commit failed");
                }
                self.backoff.reset();
                self.stats.batches_sent.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .events_uploaded
                    .fetch_add(response.received as u64, Ordering::Relaxed);
                let stats = self.queue.stats();
                self.stats.record_queue(&stats);
                tracing::debug!(
                    sent = count,
                    accepted = response.received,
                    pending = stats.pending,
                    "uploader: batch delivered"
                );
                None
            }

            Err(err) if err.is_terminal() => {
                tracing::error!(
                    error = %err,
                    "uploader: backend rejected this sensor — stopping"
                );
                Some(UploaderOutcome::Revoked(err.to_string()))
            }

            // Nutzlast wird nie akzeptiert werden: bestätigen und weitermachen,
            // sonst blockiert ein einziger kaputter Batch die gesamte Queue.
            Err(err @ TransportError::BadRequest { .. }) | Err(err @ TransportError::Encode(_)) => {
                tracing::error!(
                    error = %err,
                    dropped = count,
                    "uploader: backend rejected the batch as invalid — discarding it"
                );
                let _ = self.queue.commit(&batch);
                self.stats
                    .upload_discarded
                    .fetch_add(count as u64, Ordering::Relaxed);
                self.stats.upload_failures.fetch_add(1, Ordering::Relaxed);
                None
            }

            Err(err) => {
                self.stats.upload_failures.fetch_add(1, Ordering::Relaxed);
                if let Some(retry_after) = err.retry_after() {
                    self.backoff.override_next(retry_after);
                }
                let delay = self.backoff.next_delay();
                tracing::warn!(
                    error = %err,
                    attempt = self.backoff.attempts(),
                    delay_ms = delay.as_millis(),
                    pending = self.queue.stats().pending,
                    "uploader: upload failed, retrying later"
                );
                // Warten blockiert bewusst nur diese Task; Collectors schreiben
                // derweil weiter in den Kanal, bis dessen Kapazität greift.
                tokio::time::sleep(delay).await;
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use trapd_sensor_core::model::{Observation, StatusLevel, StatusObservation};

    /// Test-Sink mit steuerbarem Verhalten.
    struct MockSink {
        /// Antworten in Reihenfolge; ist die Liste leer, wird Erfolg gemeldet.
        script: Mutex<Vec<MockResponse>>,
        received: Arc<Mutex<Vec<IngestBatch>>>,
    }

    #[derive(Clone)]
    enum MockResponse {
        Ok,
        Fail(&'static str),
        Reject,
        Revoke,
    }

    impl MockSink {
        fn new(script: Vec<MockResponse>) -> (Self, Arc<Mutex<Vec<IngestBatch>>>) {
            let received = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    script: Mutex::new(script),
                    received: received.clone(),
                },
                received,
            )
        }
    }

    impl BatchSink for MockSink {
        async fn send_batch(&self, batch: IngestBatch) -> Result<IngestResponse> {
            let next = {
                let mut script = self.script.lock().expect("lock");
                if script.is_empty() {
                    MockResponse::Ok
                } else {
                    script.remove(0)
                }
            };
            let count = batch.len();
            self.received.lock().expect("lock").push(batch);
            match next {
                MockResponse::Ok => Ok(IngestResponse {
                    received: count,
                    errors: 0,
                    request_id: None,
                }),
                MockResponse::Fail(msg) => Err(TransportError::Network(msg.into())),
                MockResponse::Reject => Err(TransportError::BadRequest {
                    status: 400,
                    message: "invalid".into(),
                }),
                MockResponse::Revoke => Err(TransportError::Revoked("quarantined".into())),
            }
        }
    }

    fn event(seq: u64) -> SensorEvent {
        SensorEvent::new(
            seq,
            Observation::Status(StatusObservation {
                level: StatusLevel::Info,
                code: format!("evt-{seq}"),
                message: "test".into(),
                details: BTreeMap::new(),
            }),
        )
    }

    fn queue(dir: &std::path::Path) -> EventQueue {
        EventQueue::open(dir, 4 * 1024 * 1024, 64 * 1024).expect("queue")
    }

    fn config() -> UploaderConfig {
        UploaderConfig {
            sensor_id: "sensor_test".into(),
            sensor_version: "0.1.0".into(),
            batch_max_events: 3,
            flush_interval: Duration::from_millis(20),
            backoff: BackoffConfig {
                initial: Duration::from_millis(5),
                max: Duration::from_millis(20),
                multiplier: 2.0,
            },
        }
    }

    #[tokio::test]
    async fn events_are_uploaded_and_the_queue_drains() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (sink, received) = MockSink::new(vec![]);
        let stats = Arc::new(UploaderStats::default());
        let uploader = Uploader::new(queue(dir.path()), sink, config(), stats.clone());

        let (tx, rx) = mpsc::channel(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let handle = tokio::spawn(uploader.run(rx, shutdown_rx));
        for i in 0..5 {
            tx.send(event(i)).await.expect("send");
        }
        tokio::time::sleep(Duration::from_millis(120)).await;
        shutdown_tx.send(true).expect("shutdown");
        let outcome = handle.await.expect("join");

        assert_eq!(outcome, UploaderOutcome::Shutdown);
        let batches = received.lock().expect("lock");
        let total: usize = batches.iter().map(|b| b.len()).sum();
        assert_eq!(total, 5, "every event must reach the sink exactly once");
        assert_eq!(stats.snapshot().events_uploaded, 5);
        assert_eq!(stats.snapshot().queue_pending, 0);
    }

    #[tokio::test]
    async fn batches_respect_the_configured_maximum() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (sink, received) = MockSink::new(vec![]);
        let uploader = Uploader::new(
            queue(dir.path()),
            sink,
            config(),
            Arc::new(UploaderStats::default()),
        );

        let (tx, rx) = mpsc::channel(64);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(uploader.run(rx, shutdown_rx));

        for i in 0..7 {
            tx.send(event(i)).await.expect("send");
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
        shutdown_tx.send(true).expect("shutdown");
        handle.await.expect("join");

        let batches = received.lock().expect("lock");
        assert!(
            batches.iter().all(|b| b.len() <= 3),
            "no batch may exceed batch_max_events"
        );
    }

    #[tokio::test]
    async fn a_failed_upload_is_retried_without_losing_events() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (sink, received) = MockSink::new(vec![
            MockResponse::Fail("backend down"),
            MockResponse::Fail("still down"),
        ]);
        let stats = Arc::new(UploaderStats::default());
        let uploader = Uploader::new(queue(dir.path()), sink, config(), stats.clone());

        let (tx, rx) = mpsc::channel(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(uploader.run(rx, shutdown_rx));

        tx.send(event(1)).await.expect("send");
        tokio::time::sleep(Duration::from_millis(200)).await;
        shutdown_tx.send(true).expect("shutdown");
        handle.await.expect("join");

        let batches = received.lock().expect("lock");
        assert!(batches.len() >= 3, "expected two failures and a success");
        assert!(
            batches.iter().all(|b| b.len() == 1),
            "the same single event is retried, not multiplied"
        );
        assert!(stats.snapshot().upload_failures >= 2);
        assert_eq!(stats.snapshot().events_uploaded, 1);
    }

    #[tokio::test]
    async fn events_survive_a_restart_while_the_backend_is_down() {
        let dir = tempfile::tempdir().expect("tempdir");

        // Erster Lauf: Backend antwortet nur mit Fehlern.
        {
            let (sink, _) = MockSink::new(vec![
                MockResponse::Fail("down"),
                MockResponse::Fail("down"),
                MockResponse::Fail("down"),
                MockResponse::Fail("down"),
                MockResponse::Fail("down"),
            ]);
            let uploader = Uploader::new(
                queue(dir.path()),
                sink,
                config(),
                Arc::new(UploaderStats::default()),
            );
            let (tx, rx) = mpsc::channel(16);
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let handle = tokio::spawn(uploader.run(rx, shutdown_rx));
            for i in 0..3 {
                tx.send(event(i)).await.expect("send");
            }
            tokio::time::sleep(Duration::from_millis(60)).await;
            shutdown_tx.send(true).expect("shutdown");
            handle.await.expect("join");
        }

        // Zweiter Lauf: Backend ist wieder da.
        let (sink, received) = MockSink::new(vec![]);
        let uploader = Uploader::new(
            queue(dir.path()),
            sink,
            config(),
            Arc::new(UploaderStats::default()),
        );
        let (tx, rx) = mpsc::channel(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(uploader.run(rx, shutdown_rx));
        tokio::time::sleep(Duration::from_millis(120)).await;
        drop(tx);
        shutdown_tx.send(true).expect("shutdown");
        handle.await.expect("join");

        let total: usize = received.lock().expect("lock").iter().map(|b| b.len()).sum();
        assert_eq!(total, 3, "buffered events are replayed after a restart");
    }

    #[tokio::test]
    async fn a_rejected_batch_is_discarded_instead_of_blocking_the_queue() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (sink, received) = MockSink::new(vec![MockResponse::Reject]);
        let stats = Arc::new(UploaderStats::default());
        let uploader = Uploader::new(queue(dir.path()), sink, config(), stats.clone());

        let (tx, rx) = mpsc::channel(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(uploader.run(rx, shutdown_rx));

        tx.send(event(1)).await.expect("send");
        tokio::time::sleep(Duration::from_millis(60)).await;
        tx.send(event(2)).await.expect("send");
        tokio::time::sleep(Duration::from_millis(80)).await;
        shutdown_tx.send(true).expect("shutdown");
        handle.await.expect("join");

        let batches = received.lock().expect("lock");
        assert!(
            batches.len() >= 2,
            "the queue kept moving after the rejection"
        );
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.events_dropped, 1, "only the poison batch is lost");
        assert_eq!(snapshot.events_uploaded, 1, "the next event went through");
    }

    #[tokio::test]
    async fn revocation_stops_the_uploader() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (sink, _) = MockSink::new(vec![MockResponse::Revoke]);
        let uploader = Uploader::new(
            queue(dir.path()),
            sink,
            config(),
            Arc::new(UploaderStats::default()),
        );

        let (tx, rx) = mpsc::channel(16);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(uploader.run(rx, shutdown_rx));

        tx.send(event(1)).await.expect("send");
        let outcome = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("uploader should stop on revocation")
            .expect("join");

        match outcome {
            UploaderOutcome::Revoked(msg) => assert!(msg.contains("quarantined")),
            other => panic!("expected Revoked, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn shutdown_flushes_what_is_still_queued() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (sink, received) = MockSink::new(vec![]);
        let mut cfg = config();
        // Langer Timer: ohne den Shutdown-Flush bliebe alles liegen.
        cfg.flush_interval = Duration::from_secs(30);
        let uploader = Uploader::new(
            queue(dir.path()),
            sink,
            cfg,
            Arc::new(UploaderStats::default()),
        );

        let (tx, rx) = mpsc::channel(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(uploader.run(rx, shutdown_rx));

        tx.send(event(1)).await.expect("send");
        tokio::time::sleep(Duration::from_millis(30)).await;
        shutdown_tx.send(true).expect("shutdown");
        handle.await.expect("join");

        let total: usize = received.lock().expect("lock").iter().map(|b| b.len()).sum();
        assert_eq!(total, 1, "shutdown must not silently strand queued events");
    }
}
