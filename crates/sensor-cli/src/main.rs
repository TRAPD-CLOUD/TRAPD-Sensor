//! `trapd-sensorctl` — Enrollment und Betriebsauskunft für den Sensor.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use trapd_sensor_core::config::{SensorConfig, DEFAULT_CONFIG_PATH};
use trapd_sensor_core::deployment::{Edition, NetworkProfile, Vantage};
use trapd_sensor_core::identity::{derive_device_id, SensorIdentity};
use trapd_sensor_transport::{BackendClient, EnrollRequest};

mod diagnose;
mod probe;
mod setup;

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

    /// Richtet ein, wie dieser Sensor am Netz hängt — geführt oder per Flags.
    ///
    /// Beliebig oft wiederholbar: derselbe Befehl wechselt später die
    /// Netzwerkquelle (FRITZ!Box → SPAN), das Interface oder die Edition,
    /// ohne Neuinstallation.
    Setup {
        /// Installationsvariante: homelab (geführt) oder enterprise.
        #[arg(long, value_parser = parse_edition)]
        edition: Option<Edition>,

        /// Netzwerkumgebung: fritzbox, unifi, opnsense, pfsense, openwrt,
        /// span, generic oder manual.
        #[arg(long, value_parser = parse_profile)]
        profile: Option<NetworkProfile>,

        /// Beobachtungspunkt: lan_host, mirror_port, network_tap oder gateway.
        #[arg(long, value_parser = parse_vantage)]
        vantage: Option<Vantage>,

        /// Capture-Interface. Mehrfach angebbar; ohne Angabe bleibt die
        /// automatische Auswahl.
        #[arg(long = "interface", value_name = "NAME")]
        interfaces: Vec<String>,

        /// Standard-Gateway, falls die Erkennung es nicht findet.
        #[arg(long)]
        gateway: Option<std::net::IpAddr>,

        /// Lokales Netz in CIDR-Notation.
        #[arg(long, value_name = "CIDR")]
        lan: Option<String>,

        /// Das Gateway ohne Rückfrage einmal unauthentifiziert abfragen, um
        /// die Plattform zu bestimmen.
        #[arg(long)]
        probe_gateway: bool,

        /// Keine Rückfragen stellen (für Automatisierung).
        #[arg(long)]
        non_interactive: bool,

        /// Nur zeigen, was herauskäme; nichts schreiben.
        #[arg(long)]
        dry_run: bool,
    },

    /// Zeigt, welche Netzwerk-Sichtbarkeit dieser Sensor hat — und warum.
    Visibility {
        /// Versionierte JSON-Ausgabe statt der Tabelle.
        #[arg(long)]
        json: bool,
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
            // `setup` exists to fix a broken configuration (that is what the
            // new backend-host prompt below is for), so it must not refuse to
            // start just because the file it is about to fix does not
            // currently validate. It starts from defaults instead — prompts
            // that normally pre-fill the previous value (FRITZ!Box address,
            // interfaces, ...) show the default instead, since the broken
            // file couldn't be parsed to read them back. The write path
            // (`update_document`) edits the real file's TOML in place, so
            // everything setup does not ask about (comments, other keys)
            // still survives regardless of this fallback.
            if matches!(cli.command, Command::Setup { .. }) {
                eprintln!(
                    "warning: {} is present but invalid ({error}) — starting setup from \
                     defaults so you can fix it. Previous answers this can't read back \
                     (e.g. the FRITZ!Box address) will show as their defaults; re-enter them \
                     if they need to stay the same.",
                    cli.config.display()
                );
                SensorConfig::default()
            } else {
                return Err(error)
                    .with_context(|| format!("could not load {}", cli.config.display()));
            }
        }
    };

    match cli.command {
        Command::Enroll {
            token,
            name,
            site,
            force,
        } => enroll(&config, &token, name, site, force).await,
        Command::Setup {
            edition,
            profile,
            vantage,
            interfaces,
            gateway,
            lan,
            probe_gateway,
            non_interactive,
            dry_run,
        } => {
            setup::run(
                &cli.config,
                &config,
                setup::SetupArgs {
                    edition,
                    profile,
                    vantage,
                    interfaces,
                    gateway,
                    lan,
                    probe_gateway,
                    non_interactive,
                    dry_run,
                },
            )
            .await
        }
        Command::Visibility { json } => visibility(&config, json).await,
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

// clap braucht für die eigenen Aufzählungstypen einen Parser; `FromStr` liefert
// bereits die Fehlermeldung samt Liste der erlaubten Werte.
fn parse_edition(raw: &str) -> Result<Edition, String> {
    raw.parse()
}
fn parse_profile(raw: &str) -> Result<NetworkProfile, String> {
    raw.parse()
}
fn parse_vantage(raw: &str) -> Result<Vantage, String> {
    raw.parse()
}

/// Was der Sensor an diesem Anschluss sehen kann — hergeleitet aus der
/// Konfiguration, ergänzt um den tatsächlichen Capture-Zustand des laufenden
/// Daemons. Beides gehört zusammen: die beste Position im Netz nützt nichts,
/// wenn kein Interface offen ist.
async fn visibility(config: &SensorConfig, json: bool) -> anyhow::Result<()> {
    let report = config.visibility();
    let live = daemon_status(config).await;

    if json {
        let mut value = serde_json::to_value(&report)?;
        value["live"] = match &live {
            Some(status) => serde_json::json!({
                "daemon_reachable": true,
                "ready": status["ready"].as_bool().unwrap_or(false),
                "interfaces_up": status["interfaces"]["up"].as_u64().unwrap_or(0),
                "interfaces_configured": status["interfaces"]["configured"].as_u64().unwrap_or(0),
                "packets_captured": status["packets"]["captured"].as_u64().unwrap_or(0),
            }),
            None => serde_json::json!({ "daemon_reachable": false }),
        };
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }

    print!("{}", report.render_text());
    println!("\n  {}:", report.profile.label());
    for line in report.profile.guidance() {
        println!("  - {line}");
    }

    match live {
        Some(status) => println!(
            "\n  live: {} of {} capture interfaces up, {} packets captured{}",
            status["interfaces"]["up"].as_u64().unwrap_or(0),
            status["interfaces"]["configured"].as_u64().unwrap_or(0),
            status["packets"]["captured"].as_u64().unwrap_or(0),
            match status["readiness_reason"].as_str() {
                Some(reason) if !status["ready"].as_bool().unwrap_or(false) =>
                    format!(" — NOT READY: {reason}"),
                _ => String::new(),
            }
        ),
        None => println!(
            "\n  live: the daemon is not reachable on {} — the report above is what this \
             configuration would allow, not what is currently being captured.",
            config.admin.listen
        ),
    }
    println!("\n  Change any of this with: trapd-sensorctl setup");
    Ok(())
}

/// Der Status des laufenden Daemons, oder `None`, wenn er nicht läuft.
async fn daemon_status(config: &SensorConfig) -> Option<serde_json::Value> {
    let response = reqwest::Client::new()
        .get(format!("http://{}/admin/status", config.admin.listen))
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .ok()?;
    response.json::<serde_json::Value>().await.ok()
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
    if let (Some(profile), Some(vantage)) = (
        status["deployment"]["profile"]
            .as_str()
            .and_then(|s| s.parse::<NetworkProfile>().ok()),
        status["deployment"]["vantage"]
            .as_str()
            .and_then(|s| s.parse::<Vantage>().ok()),
    ) {
        println!("network   {} via {}", profile.label(), vantage.label());
    }
    println!(
        "capture   {} of {} interfaces, {} packets ({} dropped)",
        status["interfaces"]["up"].as_u64().unwrap_or_default(),
        status["interfaces"]["configured"]
            .as_u64()
            .unwrap_or_default(),
        status["packets"]["captured"].as_u64().unwrap_or_default(),
        status["packets"]["dropped"].as_u64().unwrap_or_default(),
    );
    if let Some(fritzbox) = status["capture_providers"]["fritzbox"].as_object() {
        println!("\nFRITZ!Box capture");
        println!(
            "  status:     {}",
            fritzbox["state"].as_str().unwrap_or("unknown")
        );
        println!(
            "  address:    {}",
            fritzbox["address"].as_str().unwrap_or("?")
        );
        let interfaces = fritzbox["configured_interfaces"]
            .as_array()
            .map(|v| {
                v.iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        println!("  interfaces: {interfaces}");
        println!(
            "  packets:    {}",
            fritzbox["packets_received"].as_u64().unwrap_or(0)
        );
        if let Some(reason) = fritzbox["last_error_code"].as_str() {
            println!("  reason:     {reason}");
        }
        if let Some(retry) = fritzbox["current_backoff_secs"].as_u64().filter(|n| *n > 0) {
            println!("  retry:      {retry}s");
        }
    }
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
