//! Der Sweep: geplante, budgetierte aktive Erkennung.
//!
//! Der Scanner ist die einzige Stelle, die entscheidet, *ob* etwas angefasst
//! wird. Er fragt für jedes Ziel [`EffectivePolicy::may_probe`] und holt für
//! jede einzelne Probe ein Token beim [`RateLimiter`]. Beides ist nicht
//! optional und lässt sich nicht umgehen — die Proben in
//! [`crate::probe`] kennen die Policy gar nicht.
//!
//! Ergebnisse werden nicht gesammelt, sondern laufend über einen Kanal
//! abgegeben: ein Sweep über ein /24 dauert bei 5 Probes/s eine ganze Weile,
//! und in dieser Zeit sollen die ersten Funde längst im Dashboard stehen.

use std::net::IpAddr;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use trapd_sensor_core::config::EffectivePolicy;
use trapd_sensor_core::model::{
    AssetObservation, DiscoveryMethod, Observation, ServiceObservation, TransportProtocol,
};

use crate::probe::{icmp_echo, tcp_banner, tcp_connect, PortState};
use crate::rate_limit::RateLimiter;
use crate::snmp::get_system;

/// Zeitlimit je einzelner Probe.
const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepStats {
    pub hosts_considered: usize,
    pub hosts_probed: usize,
    pub hosts_responding: usize,
    pub ports_probed: usize,
    pub ports_open: usize,
    pub snmp_responding: usize,
    pub probes_total: usize,
    pub probe_errors: usize,
    pub snmp_queries: usize,
    pub snmp_errors: usize,
    /// Ziele, die die Policy abgelehnt hat.
    pub hosts_skipped: usize,
}

pub struct Scanner {
    policy: EffectivePolicy,
    limiter: RateLimiter,
    probe_timeout: Duration,
}

impl Scanner {
    /// `None`, wenn die Policy keine aktive Erkennung erlaubt — der Aufrufer
    /// muss dann gar keine Sweep-Task starten.
    pub fn new(policy: EffectivePolicy) -> Option<Self> {
        let active = policy.active.as_ref()?;
        let limiter = RateLimiter::new(active.rate_limit_per_sec);
        Some(Self {
            policy,
            limiter,
            probe_timeout: DEFAULT_PROBE_TIMEOUT,
        })
    }

    pub fn with_probe_timeout(mut self, timeout: Duration) -> Self {
        self.probe_timeout = timeout;
        self
    }

    /// Alle Adressen der konfigurierten Ziel-Netze, ohne die ausgeschlossenen.
    pub fn targets(&self) -> Vec<IpAddr> {
        let Some(active) = &self.policy.active else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for cidr in &active.targets {
            if cidr.host_count().is_none() {
                // Ein Netz, das zu groß zum Durchlaufen ist, wird nicht
                // stillschweigend angeschnitten — es wird gemeldet und
                // übersprungen. Ein halb abgearbeitetes /8 wäre ein
                // Ergebnis, dem niemand ansieht, dass es unvollständig ist.
                tracing::warn!(
                    cidr = %cidr,
                    "target network is too large for a sweep — skipping it"
                );
                continue;
            }
            for ip in cidr.hosts() {
                if self.policy.may_probe(ip) {
                    out.push(ip);
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// Führt einen vollständigen Durchlauf aus.
    pub async fn sweep(
        &mut self,
        events: &mpsc::Sender<Observation>,
        shutdown: &mut watch::Receiver<bool>,
    ) -> SweepStats {
        let mut stats = SweepStats::default();
        let Some(active) = self.policy.active.clone() else {
            return stats;
        };

        let targets = self.targets();
        stats.hosts_considered = targets.len();
        tracing::info!(
            targets = targets.len(),
            rate_limit = active.rate_limit_per_sec,
            ports = active.ports.len(),
            "starting active discovery sweep"
        );

        for ip in targets {
            if *shutdown.borrow() {
                tracing::info!("sweep interrupted by shutdown");
                break;
            }
            // Doppelte Prüfung: `targets()` hat bereits gefiltert, aber die
            // Freigabe je Ziel gehört unmittelbar vor die Probe. Diese Zeile
            // ist die eigentliche Zusage.
            if !self.policy.may_probe(ip) {
                stats.hosts_skipped += 1;
                continue;
            }

            let mut host_responded = false;

            if active.icmp {
                self.limiter.acquire().await;
                stats.probes_total += 1;
                stats.hosts_probed += 1;
                match icmp_echo(ip, self.probe_timeout).await {
                    Ok(true) => {
                        host_responded = true;
                        stats.hosts_responding += 1;
                        let _ = events
                            .send(Observation::Asset(AssetObservation {
                                ip: Some(ip),
                                mac: None,
                                hostname: None,
                                vlan_id: None,
                                subnet: None,
                                method: DiscoveryMethod::IcmpProbe,
                                interface: None,
                            }))
                            .await;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        stats.probe_errors += 1;
                        tracing::debug!(%ip, error = %e, "icmp probe failed");
                    }
                }
            }

            if !active.tcp_connect {
                // SNMP is independent from TCP probing.
            }

            for community in &active.snmp_communities {
                if *shutdown.borrow() {
                    break;
                }
                self.limiter.acquire().await;
                stats.probes_total += 1;
                stats.snmp_queries += 1;
                let request_id = rand::random::<i32>() & i32::MAX;
                match get_system(ip, community, request_id, self.probe_timeout).await {
                    Ok(Some(system)) => {
                        stats.snmp_responding += 1;
                        if !host_responded {
                            host_responded = true;
                            stats.hosts_responding += 1;
                        }
                        let _ = events
                            .send(Observation::Asset(AssetObservation {
                                ip: Some(ip),
                                mac: None,
                                hostname: system.sys_name.clone(),
                                vlan_id: None,
                                subnet: None,
                                method: DiscoveryMethod::Snmp,
                                interface: None,
                            }))
                            .await;
                        let banner = system
                            .sys_descr
                            .as_deref()
                            .and_then(|s| trapd_sensor_core::model::sanitize_banner(s.as_bytes()));
                        let _ = events
                            .send(Observation::Service(ServiceObservation {
                                ip,
                                port: 161,
                                protocol: TransportProtocol::Udp,
                                service: Some("snmp".into()),
                                banner,
                                method: DiscoveryMethod::Snmp,
                            }))
                            .await;
                        break;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        stats.probe_errors += 1;
                        stats.snmp_errors += 1;
                        tracing::debug!(%ip, %error, "SNMP query failed");
                    }
                }
            }

            if !active.tcp_connect {
                continue;
            }

            for port in &active.ports {
                if *shutdown.borrow() {
                    break;
                }
                self.limiter.acquire().await;
                stats.probes_total += 1;
                stats.ports_probed += 1;

                let result = if active.banner_grab {
                    tcp_banner(ip, *port, self.probe_timeout).await
                } else {
                    tcp_connect(ip, *port, self.probe_timeout).await
                };

                match result.state {
                    PortState::Open => {
                        stats.ports_open += 1;
                        if !host_responded {
                            host_responded = true;
                            stats.hosts_responding += 1;
                        }
                        let _ = events
                            .send(Observation::Service(ServiceObservation {
                                ip,
                                port: *port,
                                protocol: TransportProtocol::Tcp,
                                service: None,
                                banner: result.banner,
                                method: if active.banner_grab {
                                    DiscoveryMethod::Banner
                                } else {
                                    DiscoveryMethod::TcpConnect
                                },
                            }))
                            .await;
                    }
                    // Ein abgelehnter Port beweist, dass der Host lebt — das
                    // ist eine Asset-Aussage, auch ohne offenen Dienst.
                    PortState::Closed => {
                        if !host_responded {
                            host_responded = true;
                            stats.hosts_responding += 1;
                            let _ = events
                                .send(Observation::Asset(AssetObservation {
                                    ip: Some(ip),
                                    mac: None,
                                    hostname: None,
                                    vlan_id: None,
                                    subnet: None,
                                    method: DiscoveryMethod::TcpConnect,
                                    interface: None,
                                }))
                                .await;
                        }
                    }
                    PortState::Filtered => {}
                }
            }
        }

        tracing::info!(?stats, "active discovery sweep finished");
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use trapd_sensor_core::config::{SensorConfig, SensorMode};

    fn policy_for(targets: &[&str], ports: &[u16], mode: SensorMode) -> EffectivePolicy {
        let mut cfg = SensorConfig::default();
        cfg.sensor.mode = mode;
        cfg.active.enabled = true;
        cfg.active.acknowledged = true;
        cfg.active.targets = targets.iter().map(|s| (*s).to_string()).collect();
        cfg.active.ports = ports.to_vec();
        cfg.active.icmp = false; // ICMP braucht Rechte, die im Test fehlen
        cfg.active.rate_limit_per_sec = 1000;
        cfg.effective_policy()
    }

    fn channel() -> (mpsc::Sender<Observation>, mpsc::Receiver<Observation>) {
        mpsc::channel(256)
    }

    #[tokio::test]
    async fn passive_only_policy_yields_no_scanner_at_all() {
        let policy = policy_for(&["127.0.0.1/32"], &[80], SensorMode::PassiveOnly);
        assert!(
            Scanner::new(policy).is_none(),
            "a passive sensor must not even be able to construct a scanner"
        );
    }

    #[tokio::test]
    async fn unacknowledged_policy_yields_no_scanner() {
        let mut cfg = SensorConfig::default();
        cfg.sensor.mode = SensorMode::Active;
        cfg.active.enabled = true;
        cfg.active.targets = vec!["127.0.0.1/32".into()];
        // acknowledged bleibt false
        assert!(Scanner::new(cfg.effective_policy()).is_none());
    }

    #[tokio::test]
    async fn targets_come_only_from_configured_networks() {
        let policy = policy_for(&["192.168.50.0/30"], &[80], SensorMode::Balanced);
        let scanner = Scanner::new(policy).expect("scanner");

        let targets = scanner.targets();
        assert_eq!(
            targets,
            vec![
                "192.168.50.1".parse::<IpAddr>().expect("ip"),
                "192.168.50.2".parse::<IpAddr>().expect("ip"),
            ],
            "network and broadcast addresses are not hosts"
        );
    }

    #[tokio::test]
    async fn excluded_ranges_never_become_targets() {
        let mut cfg = SensorConfig::default();
        cfg.sensor.mode = SensorMode::Balanced;
        cfg.active.enabled = true;
        cfg.active.acknowledged = true;
        cfg.active.targets = vec!["192.168.50.0/29".into()];
        cfg.active.exclude = vec!["192.168.50.2/31".into()];
        cfg.active.icmp = false;

        let scanner = Scanner::new(cfg.effective_policy()).expect("scanner");
        let targets = scanner.targets();

        assert!(targets.contains(&"192.168.50.1".parse().expect("ip")));
        assert!(!targets.contains(&"192.168.50.2".parse().expect("ip")));
        assert!(!targets.contains(&"192.168.50.3".parse().expect("ip")));
    }

    /// Ein /8 zu durchlaufen wäre weder sinnvoll noch harmlos. Der Scanner
    /// bricht nicht ab, sondern überspringt es sichtbar.
    #[tokio::test]
    async fn oversized_target_networks_are_skipped() {
        let policy = policy_for(
            &["10.0.0.0/8", "192.168.50.0/30"],
            &[80],
            SensorMode::Balanced,
        );
        let scanner = Scanner::new(policy).expect("scanner");

        let targets = scanner.targets();
        assert_eq!(targets.len(), 2, "only the small network is swept");
        assert!(targets
            .iter()
            .all(|ip| ip.to_string().starts_with("192.168.50.")));
    }

    #[tokio::test]
    async fn a_listening_port_is_discovered() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });

        // Ein flüchtiger Port liegt nicht auf der Balanced-Allowlist — für
        // diesen Test braucht es den Active-Modus.
        let policy = policy_for(&["127.0.0.1/32"], &[port], SensorMode::Active);
        let mut scanner = Scanner::new(policy)
            .expect("scanner")
            .with_probe_timeout(Duration::from_millis(500));

        let (tx, mut rx) = channel();
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let stats = scanner.sweep(&tx, &mut shutdown_rx).await;
        drop(tx);

        assert_eq!(stats.ports_open, 1);
        let mut found = Vec::new();
        while let Some(event) = rx.recv().await {
            found.push(event);
        }
        let service = found
            .iter()
            .find_map(|e| match e {
                Observation::Service(s) => Some(s),
                _ => None,
            })
            .expect("service observation");
        assert_eq!(service.port, port);
        assert_eq!(service.method, DiscoveryMethod::TcpConnect);
    }

    #[tokio::test]
    async fn banner_grab_is_only_used_when_the_policy_allows_it() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            if let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream.write_all(b"SSH-2.0-OpenSSH_9.2\r\n").await;
            }
        });

        // Balanced schneidet Banner-Grab weg, selbst wenn es konfiguriert ist.
        let mut cfg = SensorConfig::default();
        cfg.sensor.mode = SensorMode::Balanced;
        cfg.active.enabled = true;
        cfg.active.acknowledged = true;
        cfg.active.targets = vec!["127.0.0.1/32".into()];
        cfg.active.ports = vec![port];
        cfg.active.banner_grab = true;
        cfg.active.icmp = false;

        let mut scanner = Scanner::new(cfg.effective_policy())
            .expect("scanner")
            .with_probe_timeout(Duration::from_millis(500));

        let (tx, mut rx) = channel();
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);
        scanner.sweep(&tx, &mut shutdown_rx).await;
        drop(tx);

        // Der Port liegt nicht auf der Balanced-Allowlist, es passiert nichts.
        assert!(
            rx.recv().await.is_none(),
            "balanced mode probes only allowlisted ports"
        );
    }

    #[tokio::test]
    async fn shutdown_interrupts_a_running_sweep() {
        let policy = policy_for(&["192.168.51.0/24"], &[9, 7], SensorMode::Balanced);
        let mut scanner = Scanner::new(policy)
            .expect("scanner")
            .with_probe_timeout(Duration::from_millis(50));

        let (tx, _rx) = channel();
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        shutdown_tx.send(true).expect("shutdown");

        let stats = scanner.sweep(&tx, &mut shutdown_rx).await;
        assert_eq!(
            stats.hosts_probed, 0,
            "an already-cancelled sweep does nothing"
        );
    }

    #[tokio::test]
    async fn no_targets_means_no_probes() {
        let policy = policy_for(&["127.0.0.1/32"], &[], SensorMode::Balanced);
        // Ohne Ports und ohne ICMP bleibt nichts zu tun.
        let Some(mut scanner) = Scanner::new(policy) else {
            return; // tcp_connect wird ohne Ports abgeschaltet — auch in Ordnung
        };
        let (tx, mut rx) = channel();
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);
        scanner.sweep(&tx, &mut shutdown_rx).await;
        drop(tx);
        assert!(rx.recv().await.is_none());
    }
}
