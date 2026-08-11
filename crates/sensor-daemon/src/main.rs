//! `trapd-sensord` — der Daemon des TRAPD Network Sensor.

mod admin;
mod registry;
mod runtime;
mod state;

use std::path::PathBuf;

use clap::Parser;
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;
use trapd_sensor_core::config::{SensorConfig, DEFAULT_CONFIG_PATH};
use trapd_sensor_core::identity::SensorIdentity;

#[derive(Debug, Parser)]
#[command(
    name = "trapd-sensord",
    version,
    about = "TRAPD network sensor — passive asset discovery and network telemetry"
)]
struct Cli {
    /// Pfad zur Konfigurationsdatei.
    #[arg(short, long, env = "TRAPD_SENSOR_CONFIG", default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    /// Konfiguration prüfen und beenden, ohne etwas zu erfassen.
    #[arg(long)]
    check: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing();

    let config = SensorConfig::load(&cli.config)?;
    config.validate()?;

    if cli.check {
        validate_capture_providers(&config)?;
        report_configuration(&config);
        return Ok(());
    }

    let identity = match SensorIdentity::load(&config.sensor.state_dir) {
        Ok(identity) => identity,
        Err(e) => {
            // Der häufigste Erststart-Fall. Die Meldung nennt den nächsten
            // Schritt, statt nur einen Fehler zu zeigen.
            tracing::error!(
                error = %e,
                "sensor is not enrolled — run: trapd-sensorctl enroll --token <ENROLLMENT_TOKEN>"
            );
            return Err(e.into());
        }
    };

    tracing::info!(
        sensor_id = %identity.sensor_id,
        version = trapd_sensor_core::VERSION,
        mode = config.sensor.mode.as_str(),
        "starting TRAPD network sensor"
    );

    // Die Runtime wird hier von Hand gebaut, weil `main` selbst synchron bleibt:
    // Konfiguration und Identität sollen geprüft sein, bevor überhaupt ein
    // Thread-Pool entsteht.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let daemon = runtime::Daemon::new(config.clone(), identity);
        let state = daemon.state();

        let listen = config.admin.listen.clone();
        let admin_state = state.clone();
        let admin_shutdown = shutdown_rx.clone();
        let mut admin =
            tokio::spawn(async move { admin::serve(&listen, admin_state, admin_shutdown).await });

        let signal_shutdown = shutdown_tx.clone();
        let signals = tokio::spawn(async move {
            wait_for_shutdown().await;
            let _ = signal_shutdown.send(true);
        });
        let mut daemon = tokio::spawn(daemon.run(shutdown_rx));
        let result = tokio::select! {
            result = &mut daemon => result.map_err(anyhow::Error::from)?,
            result = &mut admin => {
                let error = match result { Ok(Ok(())) => anyhow::anyhow!("admin server stopped unexpectedly"), Ok(Err(error)) => error, Err(error) => error.into() };
                state.mark_unhealthy(error.to_string());
                Err(error)
            }
        };
        let _ = shutdown_tx.send(true);
        if !daemon.is_finished() { let _ = tokio::time::timeout(std::time::Duration::from_secs(20), &mut daemon).await; }
        if !admin.is_finished() { let _ = tokio::time::timeout(std::time::Duration::from_secs(5), &mut admin).await; }
        signals.abort();
        result
    })
}

fn validate_capture_providers(config: &SensorConfig) -> anyhow::Result<()> {
    let fb = &config.capture.fritzbox;
    if fb.enabled {
        trapd_sensor_capture::fritzbox::FritzBoxClient::new(
            &fb.address,
            std::time::Duration::from_secs(fb.connect_timeout_secs),
            std::time::Duration::from_secs(fb.read_timeout_secs),
        )?;
        trapd_sensor_capture::fritzbox::SecretStore::new(&fb.credentials_file).load()?;
    }
    Ok(())
}

/// Gibt aus, was der Sensor mit dieser Konfiguration tatsächlich täte.
///
/// `--check` beantwortet die Frage, die sonst erst der Betrieb beantwortet:
/// Warum scannt er nicht? Welche Interfaces nimmt er? Was ist abgeschaltet?
fn report_configuration(config: &SensorConfig) {
    let policy = config.effective_policy();
    let interfaces = trapd_sensor_capture::select_interfaces(&config.capture.interfaces);

    println!("configuration is valid\n");
    println!("  edition:           {}", config.deployment.edition);
    println!("  network:           {}", config.deployment.profile.label());
    println!("  vantage:           {}", config.deployment.vantage.label());
    println!("  mode:              {}", config.sensor.mode.as_str());
    println!("  state directory:   {}", config.sensor.state_dir.display());
    println!("  queue directory:   {}", config.buffer.dir.display());
    println!(
        "  queue limit:       {} MiB",
        config.buffer.max_disk_bytes / (1024 * 1024)
    );
    println!("  api url:           {}", config.backend.api_url);
    println!("  ingest url:        {}", config.backend.ingest_url);
    println!(
        "  interfaces:        {}",
        if interfaces.is_empty() {
            "(none found)".to_string()
        } else {
            interfaces.join(", ")
        }
    );
    println!(
        "  FRITZ!Box capture: {}",
        if config.capture.fritzbox.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );

    println!("\n  passive modules:");
    for (name, enabled) in [
        ("arp", policy.passive.arp),
        ("dhcp", policy.passive.dhcp),
        ("mdns", policy.passive.mdns),
        ("ssdp", policy.passive.ssdp),
        ("dns", policy.passive.dns),
        ("flows", policy.passive.flows),
    ] {
        println!("    {name:<8} {}", if enabled { "on" } else { "off" });
    }

    match &policy.active {
        Some(active) => {
            println!("\n  active discovery:  ENABLED");
            println!("    rate limit:      {}/s", active.rate_limit_per_sec);
            println!("    icmp:            {}", active.icmp);
            println!("    tcp connect:     {}", active.tcp_connect);
            println!("    banner grab:     {}", active.banner_grab);
            println!(
                "    ports:           {}",
                active
                    .ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!(
                "    targets:         {}",
                active
                    .targets
                    .iter()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            if !active.exclude.is_empty() {
                println!(
                    "    excluded:        {}",
                    active
                        .exclude
                        .iter()
                        .map(|c| c.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
        None => {
            println!("\n  active discovery:  DISABLED");
            if let Some(reason) = policy.active_disabled_reason {
                println!("    reason:          {reason}");
            }
        }
    }

    // Was der Sensor an diesem Anschluss überhaupt sehen kann. Steht bewusst
    // neben der Policy: die eine Hälfte ist "was er darf", die andere "was
    // ankommt".
    let visibility = config.visibility();
    println!("\n  visibility:");
    for capability in &visibility.capabilities {
        println!(
            "    {} {:<30} {}",
            capability.level.symbol(),
            capability.label,
            capability.reason
        );
    }

    println!("\n  privacy:");
    println!("    dns observation: {}", policy.privacy.dns_observation);
    println!("    hash dns names:  {}", policy.privacy.hash_dns_names);
    println!("    store answers:   {}", policy.privacy.store_dns_answers);
    if !policy.privacy.exclude_clients.is_empty() {
        println!(
            "    excluded hosts:  {}",
            policy.privacy.exclude_clients.join(", ")
        );
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let json = std::env::var("TRAPD_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    if json {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

async fn wait_for_shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "could not install the SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    tokio::select! {
        _ = ctrl_c => tracing::info!("received Ctrl-C"),
        _ = terminate => tracing::info!("received SIGTERM"),
    }
}
