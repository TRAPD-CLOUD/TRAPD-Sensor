//! `trapd-sensorctl` — Enrollment und Betriebsauskunft für den Sensor.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use trapd_sensor_core::config::{SensorConfig, DEFAULT_CONFIG_PATH};
use trapd_sensor_core::identity::{derive_device_id, SensorIdentity};
use trapd_sensor_transport::{BackendClient, EnrollRequest};

mod diagnose;

#[derive(Debug, Parser)]
#[command(
    name = "trapd-sensorctl",
    version,
    about = "Enroll and inspect a TRAPD network sensor"
)]
struct Cli {
    #[arg(short, long, env = "TRAPD_SENSOR_CONFIG", default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Meldet den Sensor mit einem Einmal-Token beim Backend an.
    Enroll {
        /// Enrollment-Token aus dem TRAPD-Dashboard.
        #[arg(short, long, env = "TRAPD_ENROLLMENT_TOKEN")]
        token: String,

        /// Anzeigename im Dashboard (Vorgabe: aus der Konfiguration).
        #[arg(long)]
        name: Option<String>,

        /// Standort-Bezeichnung.
        #[arg(long)]
        site: Option<String>,

        /// Vorhandene Identität überschreiben.
        #[arg(long)]
        force: bool,
    },

    /// Zeigt den Zustand des laufenden Daemons.
    Status {
        /// Rohes JSON statt der Übersicht ausgeben.
        #[arg(long)]
        json: bool,
    },

    /// Prüft die Konfiguration und die Voraussetzungen auf diesem Host.
    Diagnose {
        /// Machine-readable, versioned JSON output.
        #[arg(long)]
        json: bool,
    },

    /// Entfernt die lokale Identität. Der Sensor gilt danach als nicht angemeldet.
    Reset {
        #[arg(long)]
        yes: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();
    let config = match SensorConfig::load(&cli.config) {
        Ok(config) => config,
        Err(error) => {
            if let Command::Diagnose { json } = &cli.command {
                let report = diagnose::config_failure(&cli.config);
                if *json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    print!("{}", report.render_text());
                }
                std::process::exit(report.exit_code().into());
            }
            return Err(error).with_context(|| format!("could not load {}", cli.config.display()));
        }
    };

    match cli.command {
        Command::Enroll {
            token,
            name,
            site,
            force,
        } => enroll(&config, &token, name, site, force).await,
        Command::Status { json } => status(&config, json).await,
        Command::Diagnose { json } => {
            let report = diagnose::run(&cli.config, &config).await;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", report.render_text());
            }
            std::process::exit(report.exit_code().into());
        }
        Command::Reset { yes } => reset(&config, yes),
    }
}

async fn enroll(
    config: &SensorConfig,
    token: &str,
    name: Option<String>,
    site: Option<String>,
    force: bool,
) -> anyhow::Result<()> {
    if SensorIdentity::exists(&config.sensor.state_dir) && !force {
        bail!(
            "this sensor is already enrolled ({}). Use --force to replace the identity.",
            SensorIdentity::path(&config.sensor.state_dir).display()
        );
    }

    let client = BackendClient::new(
        &config.backend.api_url,
        &config.backend.ingest_url,
        Duration::from_secs(config.backend.request_timeout_secs),
    )?;

    let request = EnrollRequest {
        enrollment_token: token.to_string(),
        device_id: derive_device_id(),
        hostname: hostname(),
        name: name.unwrap_or_else(|| config.sensor.name.clone()),
        site: site.or_else(|| config.sensor.site.clone()),
        os_version: os_release(),
        arch: std::env::consts::ARCH.to_string(),
        sensor_version: trapd_sensor_core::VERSION.to_string(),
        mode: config.sensor.mode.as_str().to_string(),
        interfaces: trapd_sensor_capture::select_interfaces(&config.capture.interfaces),
    };

    println!("enrolling with {} …", config.backend.api_url);
    let response = client.enroll(&request).await?;
    let sensor_id = response.sensor_id.clone();
    let identity = response.into_identity(request.device_id.clone());

    identity.save(&config.sensor.state_dir).with_context(|| {
        format!(
            "could not write the identity to {}",
            config.sensor.state_dir.display()
        )
    })?;

    println!("\nenrolled successfully");
    println!("  sensor id:  {sensor_id}");
    println!("  project:    {}", identity.project_id);
    println!(
        "  identity:   {} (mode 0600)",
        SensorIdentity::path(&config.sensor.state_dir).display()
    );
    println!("\nstart the sensor with: systemctl start trapd-sensor");

    // Der Betreiber soll nicht erst im Betrieb merken, dass aktive Erkennung
    // eine Handlung auf diesem Host braucht.
    if config.active.enabled && !config.active.acknowledged {
        println!(
            "\nnote: active discovery is configured but not acknowledged.\n\
             Set `acknowledged = true` under [active] in {} to allow this host\n\
             to send probes. The dashboard cannot set this for you — by design.",
            DEFAULT_CONFIG_PATH
        );
    }

    Ok(())
}

async fn status(config: &SensorConfig, json: bool) -> anyhow::Result<()> {
    let url = format!("http://{}/admin/status", config.admin.listen);
    let response = reqwest::Client::new()
        .get(&url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .with_context(|| format!("could not reach the daemon at {url} — is it running?"))?;

    let body = response.text().await?;
    if json {
        println!("{body}");
        return Ok(());
    }

    let status: serde_json::Value =
        serde_json::from_str(&body).context("the daemon returned malformed status output")?;

    println!("sensor    {}", status["sensor_id"].as_str().unwrap_or("?"));
    println!("version   {}", status["version"].as_str().unwrap_or("?"));
    println!("mode      {}", status["mode"].as_str().unwrap_or("?"));
    println!(
        "state     {}",
        if status["ready"].as_bool().unwrap_or(false) {
            "ready".to_string()
        } else {
            format!(
                "NOT READY — {}",
                status["readiness_reason"].as_str().unwrap_or("unknown")
            )
        }
    );
    println!(
        "uptime    {}s",
        status["uptime_secs"].as_u64().unwrap_or_default()
    );
    println!(
        "capture   {} of {} interfaces, {} packets ({} dropped)",
        status["interfaces"]["up"].as_u64().unwrap_or_default(),
        status["interfaces"]["configured"]
            .as_u64()
            .unwrap_or_default(),
        status["packets"]["captured"].as_u64().unwrap_or_default(),
        status["packets"]["dropped"].as_u64().unwrap_or_default(),
    );
    println!(
        "devices   {}",
        status["devices_tracked"].as_u64().unwrap_or_default()
    );
    println!(
        "queue     {} pending, {} KiB on disk, {} dropped",
        status["queue"]["pending"].as_u64().unwrap_or_default(),
        status["queue"]["disk_bytes"].as_u64().unwrap_or_default() / 1024,
        status["queue"]["dropped"].as_u64().unwrap_or_default(),
    );
    println!(
        "uploads   {} events in {} batches, {} failures",
        status["uploads"]["events"].as_u64().unwrap_or_default(),
        status["uploads"]["batches"].as_u64().unwrap_or_default(),
        status["uploads"]["failures"].as_u64().unwrap_or_default(),
    );

    if let Some(reason) = status["active_discovery_disabled_reason"].as_str() {
        println!("\nactive discovery is off: {reason}");
    }
    if let Some(error) = status["last_error"].as_str() {
        println!("last error: {error}");
    }

    Ok(())
}

fn reset(config: &SensorConfig, confirmed: bool) -> anyhow::Result<()> {
    if !confirmed {
        bail!(
            "this removes {} and unenrolls the sensor. Re-run with --yes to confirm.",
            SensorIdentity::path(&config.sensor.state_dir).display()
        );
    }
    SensorIdentity::remove(&config.sensor.state_dir)?;
    println!("identity removed — this sensor is no longer enrolled");
    println!("note: the backend still lists it. Delete it there as well.");
    Ok(())
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// `PRETTY_NAME` aus `/etc/os-release`, sonst ein generischer Wert.
fn os_release() -> String {
    let Ok(content) = std::fs::read_to_string("/etc/os-release") else {
        return "Linux".to_string();
    };
    content
        .lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_else(|| "Linux".to_string())
}
