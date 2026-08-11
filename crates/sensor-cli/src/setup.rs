//! `trapd-sensorctl setup` — record how this sensor is attached to the network.
//!
//! One code path serves both editions. The edition only changes the defaults
//! and how much is asked:
//!
//! * **Homelab** — guided. Detects interface, gateway and LAN, asks how the
//!   network is managed, and asks about the vantage point only where the
//!   answer is genuinely ambiguous. It never requires a managed switch.
//! * **Enterprise** — the same questions, but every answer can come from a
//!   flag, so `--non-interactive` finishes without a terminal.
//!
//! What setup writes is deliberately small: the `[deployment]` block and, if
//! chosen, `capture.interfaces`/`capture.promiscuous`. It does **not** touch
//! `sensor.mode`, `active.enabled`, `active.acknowledged` or `active.targets`
//! — the three-key rule for active discovery stays a decision made by hand in
//! the config file on the host, exactly as before. Setup can therefore never
//! turn a sensor into something that sends packets it did not send before.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{bail, Context};
use toml_edit::{value, Array, DocumentMut, Item, Table};
use trapd_sensor_core::config::{Cidr, SensorConfig};
use trapd_sensor_core::deployment::{Edition, NetworkProfile, Vantage};
use trapd_sensor_core::visibility::VisibilityReport;

use crate::probe;

/// Everything the command line can contribute. All optional: what is not
/// given is either detected, asked, or left as it is.
#[derive(Debug, Default)]
pub struct SetupArgs {
    pub edition: Option<Edition>,
    pub profile: Option<NetworkProfile>,
    pub vantage: Option<Vantage>,
    pub interfaces: Vec<String>,
    pub gateway: Option<IpAddr>,
    pub lan: Option<String>,
    pub probe_gateway: bool,
    pub non_interactive: bool,
    pub dry_run: bool,
}

/// The answers, before they are written.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Plan {
    edition: Edition,
    profile: NetworkProfile,
    vantage: Vantage,
    interfaces: Vec<String>,
    gateway: Option<IpAddr>,
    lan: Option<String>,
    promiscuous: bool,
    fritzbox_enabled: bool,
    fritzbox_address: String,
    fritzbox_interfaces: Vec<String>,
    /// `None` = leave `[backend]` in the file untouched. Only set when the
    /// operator actively enters a host this run — see `backend_urls_for_host`.
    backend_api_url: Option<String>,
    backend_ingest_url: Option<String>,
    backend_allow_insecure_private_http: Option<bool>,
}

impl Plan {
    fn from_config(config: &SensorConfig) -> Self {
        Self {
            edition: config.deployment.edition,
            profile: config.deployment.profile,
            vantage: config.deployment.vantage,
            interfaces: config.capture.interfaces.clone(),
            gateway: config.deployment.gateway_ip,
            lan: config.deployment.lan_cidr.clone(),
            promiscuous: config.capture.promiscuous,
            fritzbox_enabled: config.capture.fritzbox.enabled,
            fritzbox_address: config.capture.fritzbox.address.clone(),
            fritzbox_interfaces: config.capture.fritzbox.interfaces.clone(),
            backend_api_url: None,
            backend_ingest_url: None,
            backend_allow_insecure_private_http: None,
        }
    }

    /// Projects the plan onto a config so the visibility report can be
    /// computed before anything is written — the operator sees the outcome,
    /// then decides.
    fn preview(&self, base: &SensorConfig) -> SensorConfig {
        let mut preview = base.clone();
        preview.deployment.edition = self.edition;
        preview.deployment.profile = self.profile;
        preview.deployment.vantage = self.vantage;
        preview.deployment.gateway_ip = self.gateway;
        preview.deployment.lan_cidr = self.lan.clone();
        preview.capture.interfaces = self.interfaces.clone();
        preview.capture.promiscuous = self.promiscuous;
        preview.capture.fritzbox.enabled = self.fritzbox_enabled;
        preview.capture.fritzbox.address = self.fritzbox_address.clone();
        preview.capture.fritzbox.interfaces = self.fritzbox_interfaces.clone();
        if let Some(api_url) = &self.backend_api_url {
            preview.backend.api_url = api_url.clone();
        }
        if let Some(ingest_url) = &self.backend_ingest_url {
            preview.backend.ingest_url = ingest_url.clone();
        }
        if let Some(allow) = self.backend_allow_insecure_private_http {
            preview.backend.allow_insecure_private_http = allow;
        }
        preview
    }
}

/// Turns a bare host/IP entered during setup into the two backend URLs
/// TRAPD-Sensor needs, using the documented default ports (dashboard 3001,
/// ingest-gateway 8082) — matching the local Homelab Docker Compose layout
/// in `docker-compose.yml` of the main TRAPD repo. Returns
/// `(api_url, ingest_url, allow_insecure_private_http)`.
///
/// Only a bare host/IP (no scheme, e.g. `10.0.0.22`) is handled — a value
/// containing "://" is left alone (returns `None`) for the operator to set
/// by hand in `config.toml`, matching the deliberately small scope of what
/// `setup` writes. A private (RFC1918) or loopback host gets `http://` with
/// the third value set accordingly (`allow_insecure_private_http` is only
/// ever `true` for a private, non-loopback host — loopback is always
/// allowed regardless of that flag); anything else gets `https://` and
/// `false`, since only RFC1918/loopback plaintext is ever permitted.
fn backend_urls_for_host(host: &str) -> Option<(String, String, bool)> {
    let host = host.trim();
    if host.is_empty() || host.contains("://") {
        return None;
    }
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    let private = !loopback
        && matches!(
            host.parse::<std::net::IpAddr>(),
            Ok(std::net::IpAddr::V4(v4)) if v4.is_private()
        );
    let scheme = if loopback || private { "http" } else { "https" };
    Some((
        format!("{scheme}://{host}:3001"),
        format!("{scheme}://{host}:8082"),
        private,
    ))
}

pub async fn run(config_path: &Path, config: &SensorConfig, args: SetupArgs) -> anyhow::Result<()> {
    let detected = trapd_sensor_capture::detect_vantage_point();
    let available = capturable_interfaces();

    let mut plan = Plan::from_config(config);
    if let Some(edition) = args.edition {
        plan.edition = edition;
    }
    // Detection only fills gaps; a recorded value is never silently replaced.
    if plan.gateway.is_none() {
        plan.gateway = detected.gateway.map(IpAddr::V4);
    }
    if plan.lan.is_none() {
        plan.lan = detected.lan_cidr.clone();
    }

    let mut prompt = if args.non_interactive {
        None
    } else {
        match Prompt::open() {
            Ok(prompt) => Some(prompt),
            Err(error) => {
                // A piped installer (`curl | bash`) has no usable stdin, which
                // is why the prompt goes to /dev/tty. If even that is missing
                // there is nobody to ask — carry on with what we know rather
                // than failing an otherwise complete installation.
                eprintln!(
                    "note: no terminal available ({error}) — continuing without questions. \
                     Re-run `trapd-sensorctl setup` from a terminal to change anything."
                );
                None
            }
        }
    };

    if let Some(prompt) = prompt.as_mut() {
        prompt.say(&format!(
            "\nTRAPD Network Sensor\n{} Setup\n",
            plan.edition.label()
        ));
        prompt.say(&render_detection(&detected, &available));
    }

    // --- Optional gateway identification -----------------------------------
    let mut suggested = None;
    if let Some(gateway) = plan.gateway {
        let consented = if args.probe_gateway {
            true
        } else if let Some(prompt) = prompt.as_mut() {
            prompt.ask_yes_no(
                &format!(
                    "May TRAPD contact your gateway at {gateway} to identify it?\n  \
                     One unauthenticated HTTP request to ports 80 and {} plus a TCP connect to \
                     443/8443. No credentials are sent or stored",
                    49000
                ),
                false,
            )?
        } else {
            false
        };
        if consented {
            let report = probe::probe_gateway(gateway).await;
            let rendered = report.render();
            match prompt.as_mut() {
                Some(prompt) => prompt.say(&format!("\n{rendered}")),
                None => print!("{rendered}"),
            }
            suggested = report.suggested_profile();
        }
    }

    // --- Profile ------------------------------------------------------------
    if let Some(profile) = args.profile {
        plan.profile = profile;
    } else if let Some(prompt) = prompt.as_mut() {
        let default = match (suggested, plan.profile) {
            (Some(found), _) => found,
            // A never-configured sensor gets an edition-appropriate default:
            // homelab installations are usually behind a plain router,
            // enterprise ones on a mirror port.
            (None, NetworkProfile::Manual) if plan.edition == Edition::Homelab => {
                NetworkProfile::Generic
            }
            (None, NetworkProfile::Manual) => NetworkProfile::Span,
            (None, current) => current,
        };
        let labels: Vec<&str> = NetworkProfile::ALL.iter().map(|p| p.label()).collect();
        let index = prompt.ask_choice(
            "How is your network managed?",
            &labels,
            NetworkProfile::ALL
                .iter()
                .position(|p| *p == default)
                .unwrap_or(0),
        )?;
        plan.profile = NetworkProfile::ALL[index];
    } else if plan.profile == NetworkProfile::Manual {
        if let Some(found) = suggested {
            plan.profile = found;
        }
    }

    let mut new_credentials = None;
    if plan.profile == NetworkProfile::Fritzbox {
        if let Some(prompt) = prompt.as_mut() {
            new_credentials = configure_fritzbox(prompt, &mut plan, config).await?;
        }
    } else {
        plan.fritzbox_enabled = false;
    }

    // --- Vantage point -------------------------------------------------------
    if let Some(prompt) = prompt.as_mut() {
        plan.vantage = match args.vantage {
            Some(vantage) => vantage,
            None => ask_vantage(prompt, plan.profile, plan.vantage)?,
        };
    } else {
        plan.vantage =
            unattended_vantage(args.vantage, plan.profile, &config.deployment, plan.vantage);
    }

    // --- Capture interface ----------------------------------------------------
    if !args.interfaces.is_empty() {
        plan.interfaces = args.interfaces.clone();
    } else if let Some(prompt) = prompt.as_mut() {
        plan.interfaces = ask_interfaces(prompt, &available, &plan, &detected)?;
    }

    // --- Gateway / LAN overrides ----------------------------------------------
    if let Some(gateway) = args.gateway {
        plan.gateway = Some(gateway);
    }
    if let Some(lan) = &args.lan {
        Cidr::parse(lan).map_err(|e| anyhow::anyhow!("invalid --lan value '{lan}': {e}"))?;
        plan.lan = Some(lan.clone());
    }

    // --- Promiscuous mode ------------------------------------------------------
    if plan.vantage.requires_promiscuous() && !plan.promiscuous {
        let question = format!(
            "A {} needs promiscuous mode, but capture.promiscuous is false.\n  \
             Enable it? (needs CAP_NET_ADMIN, which the packaged systemd unit already grants)",
            plan.vantage.label()
        );
        match prompt.as_mut() {
            Some(prompt) => plan.promiscuous = prompt.ask_yes_no(&question, true)?,
            None => eprintln!(
                "warning: vantage {} needs promiscuous mode, but capture.promiscuous is false — \
                 the sensor will see nothing beyond a plain LAN host. Set it in {} or re-run \
                 setup interactively.",
                plan.vantage,
                config_path.display()
            ),
        }
    }

    // --- Backend address (optional; for a local/self-hosted test backend) -----
    // Deliberately minimal: a bare host generates both URLs with the
    // documented default ports, skipped entirely for non-interactive runs
    // and left alone (no [backend] keys written) if the operator just
    // presses enter — config.toml keeps whatever it already had.
    if let Some(prompt) = prompt.as_mut() {
        prompt.say(&format!(
            "\nBackend host or IP, for a local/self-hosted test backend \
             (leave blank to keep {}): ",
            config.backend.api_url
        ));
        let input = prompt.read_line()?;
        if let Some((api_url, ingest_url, allow_insecure)) = backend_urls_for_host(&input) {
            plan.backend_api_url = Some(api_url);
            plan.backend_ingest_url = Some(ingest_url);
            plan.backend_allow_insecure_private_http = Some(allow_insecure);
        }
    }

    // --- Result -----------------------------------------------------------------
    let preview = plan.preview(config);
    preview
        .validate()
        .context("the answers do not produce a valid configuration")?;
    let report = preview.visibility();

    let summary = render_result(&plan, &report);
    match prompt.as_mut() {
        Some(prompt) => prompt.say(&summary),
        None => print!("{summary}"),
    }

    if args.dry_run {
        println!("dry run — nothing was written to {}", config_path.display());
        return Ok(());
    }

    if let Some(prompt) = prompt.as_mut() {
        if !prompt.ask_yes_no(&format!("Write this to {}?", config_path.display()), true)? {
            println!("nothing was written");
            return Ok(());
        }
    }

    let credentials_changed = new_credentials.is_some();
    if let Some(credentials) = &new_credentials {
        let store = trapd_sensor_capture::fritzbox::SecretStore::new(
            &config.capture.fritzbox.credentials_file,
        );
        store
            .save(credentials)
            .context("could not save FRITZ!Box credentials")?;
        adopt_secret_ownership(store.path());
    }

    let unchanged = plan == Plan::from_config(config);
    if unchanged && config.deployment.is_configured() {
        println!(
            "configuration already matches — {} unchanged",
            config_path.display()
        );
        if credentials_changed {
            println!("updated FRITZ!Box credentials");
            println!("apply them with: systemctl restart trapd-sensor");
        }
    } else {
        write_config(config_path, &plan)?;
        println!("wrote {}", config_path.display());
        println!("apply it with: systemctl restart trapd-sensor");
    }

    Ok(())
}

async fn configure_fritzbox(
    prompt: &mut Prompt,
    plan: &mut Plan,
    config: &SensorConfig,
) -> anyhow::Result<Option<trapd_sensor_capture::fritzbox::Credentials>> {
    prompt.say(&format!(
        "\nFRITZ!Box live capture: {}\nAddress: {}\nInterfaces: {}\nCredentials: {}\n",
        if plan.fritzbox_enabled {
            "enabled"
        } else {
            "disabled"
        },
        plan.fritzbox_address,
        if plan.fritzbox_interfaces.is_empty() {
            "(none)".into()
        } else {
            plan.fritzbox_interfaces.join(", ")
        },
        if config.capture.fritzbox.credentials_file.exists() {
            "configured"
        } else {
            "not configured"
        }
    ));
    if !prompt.ask_yes_no("Enable FRITZ!Box live capture?", plan.fritzbox_enabled)? {
        plan.fritzbox_enabled = false;
        plan.fritzbox_interfaces.clear();
        return Ok(None);
    }
    prompt.say(&format!(
        "\nFRITZ!Box address [{}]: ",
        plan.fritzbox_address
    ));
    let address = prompt.read_line()?;
    if !address.is_empty() {
        plan.fritzbox_address = address;
    }
    loop {
        prompt.say("\nFRITZ!Box username: ");
        let username = prompt.read_line()?;
        let password = prompt.read_secret("FRITZ!Box password: ")?;
        let credentials = trapd_sensor_capture::fritzbox::Credentials { username, password };
        prompt.say("\nTesting authentication...\n");
        let client = trapd_sensor_capture::fritzbox::FritzBoxClient::new(
            &plan.fritzbox_address,
            std::time::Duration::from_secs(10),
            std::time::Duration::from_secs(15),
        );
        let result: Result<(), String> = match client {
            Ok(client) => match client.authenticate(&credentials).await {
                Ok(session) => match session.capture_interfaces().await {
                    Ok(found) if !found.is_empty() => {
                        prompt
                            .say("✓ Authentication successful\n\nAvailable capture interfaces:\n");
                        for (index, item) in found.iter().enumerate() {
                            prompt.say(&format!(
                                "  [{}] {}{}\n",
                                index + 1,
                                item.display_name,
                                if item.available { "" } else { " (unavailable)" }
                            ));
                        }
                        prompt.say("\nSelect one or more (comma separated): ");
                        let selected = parse_selections(&prompt.read_line()?, found.len());
                        if selected.is_empty() {
                            Err("no interface selected".to_string())
                        } else {
                            let selected: Vec<_> = selected
                                .into_iter()
                                .filter_map(|n| found.get(n))
                                .filter(|i| i.available)
                                .cloned()
                                .collect();
                            if selected.is_empty() {
                                Err("selected interfaces are unavailable".into())
                            } else {
                                prompt.say("Starting test capture...\n");
                                if let Err(error) = validate_capture(
                                    &session,
                                    &selected[0],
                                    config.capture.fritzbox.max_packet_bytes,
                                )
                                .await
                                {
                                    Err(error)
                                } else {
                                    plan.fritzbox_enabled = true;
                                    plan.fritzbox_interfaces =
                                        selected.into_iter().map(|i| i.id).collect();
                                    prompt.say("✓ valid Ethernet PCAP and packets received\n");
                                    return Ok(Some(credentials));
                                }
                            }
                        }
                    }
                    Ok(_) => Err(
                        "router advertised no capture interfaces (no diagnostic response was returned)"
                            .into(),
                    ),
                    Err(error) => Err(format!("interface discovery failed: {error}")),
                },
                Err(_) => Err("authentication failed".into()),
            },
            Err(_) => Err("invalid FRITZ!Box address".into()),
        };
        prompt.say(&format!("\n{result:?}\n"));
        if !prompt.ask_yes_no(
            "Retry FRITZ!Box setup? (No continues without live capture)",
            true,
        )? {
            plan.fritzbox_enabled = false;
            plan.fritzbox_interfaces.clear();
            return Ok(None);
        }
    }
}

async fn validate_capture(
    session: &trapd_sensor_capture::fritzbox::FritzBoxSession<'_>,
    interface: &trapd_sensor_capture::fritzbox::CaptureInterface,
    max_packet: usize,
) -> Result<(), String> {
    let mut response = session
        .start_capture(interface, max_packet)
        .await
        .map_err(|error| format!("capture endpoint unavailable: {error}"))?;
    // Metadata only (status/content-type/content-length/redacted URL) — safe
    // to keep around and include directly in the error shown to the operator.
    let response_diagnostic = trapd_sensor_capture::fritzbox::describe_capture_response(&response);
    // `target` pinned to the capture crate so `RUST_LOG=trapd_sensor_capture=debug`
    // (the documented way to see capture diagnostics) enables this line too,
    // even though it is logged from the CLI crate.
    tracing::debug!(target: "trapd_sensor_capture", response = %response_diagnostic, "FRITZ!Box capture response received");

    let mut decoder = trapd_sensor_capture::fritzbox::PcapStreamDecoder::new(max_packet);
    // Only the first bytes of the stream, and only until the decoder proves the
    // stream is real PCAP — captured traffic payloads must never be logged.
    let mut preview: Vec<u8> = Vec::with_capacity(64);
    let mut header_logged = false;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        let chunk = tokio::time::timeout_at(deadline, response.chunk())
            .await
            .map_err(|_| "capture test timed out".to_string())?
            .map_err(|error| format!("capture stream failed: {error}"))?
            .ok_or_else(|| "capture stream closed".to_string())?;
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
        match push_result {
            Ok(packets) if !packets.is_empty() => {
                return if decoder.link_type()
                    == Some(trapd_sensor_capture::fritzbox::LINKTYPE_ETHERNET)
                {
                    Ok(())
                } else {
                    Err("capture is not Ethernet PCAP".into())
                };
            }
            Ok(_) => {}
            Err(error) => {
                tracing::debug!(
                    target: "trapd_sensor_capture",
                    preview = %trapd_sensor_capture::fritzbox::preview_stream_bytes(&preview),
                    "FRITZ!Box capture stream did not decode as PCAP"
                );
                let reason = trapd_sensor_capture::fritzbox::classify_non_pcap(
                    &response_diagnostic.content_type,
                    &preview,
                );
                return Err(format!(
                    "invalid PCAP stream: {error} — {reason} ({response_diagnostic})"
                ));
            }
        }
    }
    Err("no packet received during capture test".into())
}

fn parse_selections(text: &str, count: usize) -> Vec<usize> {
    let mut out = Vec::new();
    for part in text.split(',') {
        if let Ok(n) = part.trim().parse::<usize>() {
            if (1..=count).contains(&n) && !out.contains(&(n - 1)) {
                out.push(n - 1);
            }
        }
    }
    out
}

fn adopt_secret_ownership(path: &Path) {
    if let (Some(uid), Some(gid)) = (sensor_user_id(), sensor_group_id()) {
        adopt_ownership(path, path, uid, gid);
        if let Some(parent) = path.parent() {
            adopt_ownership(parent, parent, uid, gid);
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn render_detection(
    detected: &trapd_sensor_capture::NetworkVantagePoint,
    available: &[String],
) -> String {
    let mut out = String::from("Network environment detected.\n\n");
    out.push_str(&format!(
        "  interface: {}\n",
        detected.interface.as_deref().unwrap_or("(none)")
    ));
    out.push_str(&format!(
        "  gateway:   {}\n",
        detected
            .gateway
            .map(|g| g.to_string())
            .unwrap_or_else(|| "(none)".into())
    ));
    out.push_str(&format!(
        "  network:   {}\n",
        detected.lan_cidr.as_deref().unwrap_or("(unknown)")
    ));
    out.push_str(&format!(
        "  capture:   {}\n",
        if available.is_empty() {
            "(no usable interface)".to_string()
        } else {
            available.join(", ")
        }
    ));
    out
}

fn render_result(plan: &Plan, report: &VisibilityReport) -> String {
    let mut out = String::from("\n");
    out.push_str(&report.render_summary());
    out.push('\n');
    for line in plan.profile.guidance() {
        out.push_str(&format!("  - {line}\n"));
    }
    if plan.interfaces.is_empty() {
        out.push_str("\n  Capture interfaces: automatic (all usable interfaces)\n");
    } else {
        out.push_str(&format!(
            "\n  Capture interfaces: {}\n",
            plan.interfaces.join(", ")
        ));
    }
    out.push_str("\n  `trapd-sensorctl visibility` explains every line above.\n");
    out
}

// ---------------------------------------------------------------------------
// Questions
// ---------------------------------------------------------------------------

/// The vantage point when there is nobody to ask.
///
/// The interesting case is `setup --profile span` on a sensor that was set up
/// as a FRITZ!Box LAN host: keeping `lan_host` would leave the sensor claiming
/// far less than a mirror port gives it, and the operator gets no prompt to
/// correct it. So a *changed* profile brings its own default along, while an
/// unchanged one never has its recorded vantage overwritten.
fn unattended_vantage(
    explicit: Option<Vantage>,
    chosen: NetworkProfile,
    recorded: &trapd_sensor_core::deployment::DeploymentConfig,
    current: Vantage,
) -> Vantage {
    match explicit {
        Some(vantage) => vantage,
        None if !recorded.is_configured() || chosen != recorded.profile => chosen.default_vantage(),
        None => current,
    }
}

/// Only asks where the answer genuinely differs between installations. On a
/// FRITZ!Box or a plain router there is exactly one truthful answer, and
/// asking it would only teach the operator a word they do not need.
fn ask_vantage(
    prompt: &mut Prompt,
    profile: NetworkProfile,
    current: Vantage,
) -> anyhow::Result<Vantage> {
    let default = if current == Vantage::default() {
        profile.default_vantage()
    } else {
        current
    };

    let options: Vec<Vantage> = match profile {
        NetworkProfile::Span => vec![Vantage::MirrorPort, Vantage::NetworkTap],
        NetworkProfile::Opnsense | NetworkProfile::Pfsense | NetworkProfile::Openwrt => {
            vec![Vantage::LanHost, Vantage::Gateway, Vantage::MirrorPort]
        }
        NetworkProfile::Manual => Vantage::ALL.to_vec(),
        NetworkProfile::Fritzbox | NetworkProfile::Unifi | NetworkProfile::Generic => {
            prompt.say(&format!(
                "\n  Vantage point: {} (a {} does not mirror traffic to the sensor by itself)\n",
                default.label(),
                profile.label()
            ));
            return Ok(default);
        }
    };

    let labels: Vec<&str> = options.iter().map(|v| v.label()).collect();
    let index = prompt.ask_choice(
        "Where is the sensor attached?",
        &labels,
        options.iter().position(|v| *v == default).unwrap_or(0),
    )?;
    Ok(options[index])
}

fn ask_interfaces(
    prompt: &mut Prompt,
    available: &[String],
    plan: &Plan,
    detected: &trapd_sensor_capture::NetworkVantagePoint,
) -> anyhow::Result<Vec<String>> {
    if available.is_empty() {
        prompt.say(
            "\n  No usable capture interface was found — leaving the selection on automatic.\n",
        );
        return Ok(plan.interfaces.clone());
    }

    // "automatic" stays the first option: it is what the sensor shipped with,
    // and it is the right answer whenever there is exactly one NIC.
    let mut labels = vec!["automatic (all usable interfaces)".to_string()];
    labels.extend(available.iter().map(|name| {
        // The interface carrying the default route is the LAN-facing one; a
        // mirror port usually has no route at all, so this hint is exactly
        // the distinction the operator needs.
        if Some(name.as_str()) == detected.interface.as_deref() {
            format!("{name} (default route)")
        } else {
            format!("{name} (no default route — typical for a mirror port)")
        }
    }));

    let default = match plan.interfaces.first() {
        Some(current) => available
            .iter()
            .position(|name| name == current)
            .map(|i| i + 1)
            .unwrap_or(0),
        None => 0,
    };

    let borrowed: Vec<&str> = labels.iter().map(String::as_str).collect();
    let index = prompt.ask_choice(
        "Which interface should TRAPD listen on?",
        &borrowed,
        default,
    )?;
    Ok(if index == 0 {
        Vec::new()
    } else {
        vec![available[index - 1].clone()]
    })
}

fn capturable_interfaces() -> Vec<String> {
    trapd_sensor_capture::list_interfaces()
        .into_iter()
        .filter(trapd_sensor_capture::Interface::is_capturable)
        .map(|interface| interface.name)
        .collect()
}

// ---------------------------------------------------------------------------
// Writing the configuration
// ---------------------------------------------------------------------------

const DEPLOYMENT_HEADER: &str = "\n\
# Wie und wo dieser Sensor im Netz haengt. Von `trapd-sensorctl setup`\n\
# geschrieben; von Hand aenderbar. Beeinflusst die Sichtbarkeits-Auskunft und\n\
# die Einrichtung, nicht die Rechte des Sensors — die Obergrenze bleibt\n\
# `sensor.mode`.\n";

fn write_config(path: &Path, plan: &Plan) -> anyhow::Result<()> {
    let existing = match std::fs::read_to_string(path) {
        Ok(contents) => Some(contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| format!("could not read {}", path.display()))
        }
    };

    let mut document: DocumentMut = existing
        .as_deref()
        .unwrap_or_default()
        .parse()
        .with_context(|| format!("{} is not valid TOML", path.display()))?;
    update_document(&mut document, plan)?;

    write_atomically(path, &document.to_string())
        .with_context(|| format!("could not write {}", path.display()))
}

/// Edits in place with `toml_edit` rather than re-serialising the parsed
/// config: the shipped `config.toml` is mostly comments explaining the
/// security model, and rewriting it from a struct would delete all of them.
fn update_document(document: &mut DocumentMut, plan: &Plan) -> anyhow::Result<()> {
    let deployment = ensure_table(document, "deployment", DEPLOYMENT_HEADER)?;
    deployment["edition"] = value(plan.edition.as_str());
    deployment["profile"] = value(plan.profile.as_str());
    deployment["vantage"] = value(plan.vantage.as_str());
    set_optional(
        deployment,
        "gateway_ip",
        plan.gateway.map(|ip| ip.to_string()),
    );
    set_optional(deployment, "lan_cidr", plan.lan.clone());

    let capture = ensure_table(document, "capture", "")?;
    let mut interfaces = Array::new();
    for name in &plan.interfaces {
        interfaces.push(name.as_str());
    }
    capture["interfaces"] = value(interfaces);
    capture["promiscuous"] = value(plan.promiscuous);
    let fritzbox = capture
        .entry("fritzbox")
        .or_insert(Item::Table(Table::new()))
        .as_table_mut()
        .context("[capture.fritzbox] is not a table")?;
    fritzbox["enabled"] = value(plan.fritzbox_enabled);
    fritzbox["address"] = value(plan.fritzbox_address.as_str());
    let mut remote_interfaces = Array::new();
    for id in &plan.fritzbox_interfaces {
        remote_interfaces.push(id.as_str());
    }
    fritzbox["interfaces"] = value(remote_interfaces);

    if plan.backend_api_url.is_some()
        || plan.backend_ingest_url.is_some()
        || plan.backend_allow_insecure_private_http.is_some()
    {
        let backend = ensure_table(document, "backend", "")?;
        if let Some(api_url) = &plan.backend_api_url {
            backend["api_url"] = value(api_url.as_str());
        }
        if let Some(ingest_url) = &plan.backend_ingest_url {
            backend["ingest_url"] = value(ingest_url.as_str());
        }
        if let Some(allow) = plan.backend_allow_insecure_private_http {
            backend["allow_insecure_private_http"] = value(allow);
        }
    }
    Ok(())
}

fn ensure_table<'a>(
    document: &'a mut DocumentMut,
    name: &str,
    header: &str,
) -> anyhow::Result<&'a mut Table> {
    let mut fresh = Table::new();
    if !header.is_empty() {
        fresh.decor_mut().set_prefix(header);
    }
    document
        .as_table_mut()
        .entry(name)
        .or_insert(Item::Table(fresh))
        .as_table_mut()
        .with_context(|| format!("[{name}] in the configuration file is not a table"))
}

fn set_optional(table: &mut Table, key: &str, new: Option<String>) {
    match new {
        Some(text) => table[key] = value(text),
        None => {
            table.remove(key);
        }
    }
}

/// Replaces the file through a temporary file in the same directory, so a
/// crash mid-write cannot leave a half-written config behind — and copies the
/// original's mode and ownership across, because `config.toml` is `0640
/// root:trapd-sensor` and a sensor that can no longer read its own
/// configuration is a worse outcome than a failed setup.
fn write_atomically(path: &Path, contents: &str) -> anyhow::Result<()> {
    let directory = path.parent().unwrap_or(Path::new("."));
    let (mode, uid, gid) = match std::fs::metadata(path) {
        Ok(metadata) => {
            use std::os::unix::fs::MetadataExt;
            (
                metadata.permissions().mode() & 0o7777,
                metadata.uid(),
                metadata.gid(),
            )
        }
        // A config that does not exist yet gets the same permissions the
        // packages use: readable by the service user, writable by root only.
        Err(_) => (0o640, 0, sensor_group_id().unwrap_or(0)),
    };

    let temporary = directory.join(format!(".{}.trapd-setup", file_name(path)));
    let _ = std::fs::remove_file(&temporary);
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .with_context(|| {
                format!(
                    "could not create {} — setup needs root to change the sensor configuration",
                    temporary.display()
                )
            })?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
    }

    let result = (|| -> anyhow::Result<()> {
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(mode))?;
        adopt_ownership(&temporary, path, uid, gid);
        std::fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// Gives the replacement file the ownership the original had.
///
/// Only when it differs: writing a config the caller already owns — a
/// non-packaged path, a test, a `--config` somewhere else — needs no `chown`,
/// and an unprivileged caller is not allowed to make one. Failing there would
/// refuse a write that is perfectly legitimate.
///
/// A failure that *does* matter is the packaged path: `0640 root:trapd-sensor`
/// losing its group means `trapd-sensord` can no longer read its own
/// configuration. That is worth saying out loud, but it is still not a reason
/// to throw away the operator's edit — the file is written either way, and the
/// warning names the fix.
fn adopt_ownership(temporary: &Path, target: &Path, uid: u32, gid: u32) {
    use std::os::unix::fs::MetadataExt;

    let already_correct = std::fs::metadata(temporary)
        .map(|metadata| metadata.uid() == uid && metadata.gid() == gid)
        .unwrap_or(false);
    if already_correct {
        return;
    }
    if let Err(error) = chown(temporary, uid, gid) {
        eprintln!(
            "warning: {error}. Re-run setup as root if trapd-sensord cannot read {} afterwards.",
            target.display()
        );
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config.toml".to_string())
}

fn chown(path: &Path, uid: u32, gid: u32) -> anyhow::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: `c_path` is a valid NUL-terminated string that outlives the call.
    if unsafe { libc::chown(c_path.as_ptr(), uid, gid) } != 0 {
        bail!(
            "could not set owner {uid}:{gid} on {} — {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

/// The gid of the `trapd-sensor` group, read from `/etc/group` — the same
/// "parse the file the system already has" approach `diagnose` uses for
/// `/etc/passwd`, and one less dependency than a libc user database binding.
fn sensor_group_id() -> Option<u32> {
    std::fs::read_to_string("/etc/group")
        .ok()?
        .lines()
        .find_map(|line| parse_group_line(line, "trapd-sensor"))
}

fn sensor_user_id() -> Option<u32> {
    std::fs::read_to_string("/etc/passwd")
        .ok()?
        .lines()
        .find_map(|line| {
            let mut fields = line.split(':');
            if fields.next()? != "trapd-sensor" {
                return None;
            }
            fields.next()?;
            fields.next()?.parse().ok()
        })
}

fn parse_group_line(line: &str, name: &str) -> Option<u32> {
    let mut fields = line.split(':');
    if fields.next()? != name {
        return None;
    }
    fields.next()?; // password placeholder
    fields.next()?.parse().ok()
}

// ---------------------------------------------------------------------------
// Terminal
// ---------------------------------------------------------------------------

/// Questions go to `/dev/tty`, not to stdin/stdout.
///
/// The installer arrives through a pipe (`curl … | sudo bash`), so this
/// process's stdin is the script itself — reading answers from there would
/// consume the installer. `install.sh` already solves the same problem the
/// same way for the enrollment token.
struct Prompt {
    input: BufReader<std::fs::File>,
    output: std::fs::File,
}

impl Prompt {
    fn open() -> std::io::Result<Self> {
        let output = OpenOptions::new().write(true).open("/dev/tty")?;
        let input = OpenOptions::new().read(true).open("/dev/tty")?;
        Ok(Self {
            input: BufReader::new(input),
            output,
        })
    }

    fn say(&mut self, text: &str) {
        let _ = self.output.write_all(text.as_bytes());
        let _ = self.output.flush();
    }

    fn read_line(&mut self) -> anyhow::Result<String> {
        let mut line = String::new();
        if self.input.read_line(&mut line)? == 0 {
            bail!("the terminal closed while setup was waiting for an answer");
        }
        Ok(line.trim().to_string())
    }

    fn read_secret(&mut self, question: &str) -> anyhow::Result<String> {
        use std::os::fd::AsRawFd;
        self.say(question);
        let fd = self.input.get_ref().as_raw_fd();
        let mut old = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(fd, &mut old) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut hidden = old;
        hidden.c_lflag &= !libc::ECHO;
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let result = self.read_line();
        let restored = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &old) };
        self.say("\n");
        if restored != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        result
    }

    fn ask_yes_no(&mut self, question: &str, default: bool) -> anyhow::Result<bool> {
        loop {
            self.say(&format!(
                "\n{question} [{}] ",
                if default { "Y/n" } else { "y/N" }
            ));
            match self.read_line()?.to_ascii_lowercase().as_str() {
                "" => return Ok(default),
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                _ => self.say("  please answer y or n\n"),
            }
        }
    }

    fn ask_choice(
        &mut self,
        question: &str,
        options: &[&str],
        default: usize,
    ) -> anyhow::Result<usize> {
        let default = default.min(options.len().saturating_sub(1));
        loop {
            self.say(&format!("\n{question}\n\n"));
            for (index, option) in options.iter().enumerate() {
                self.say(&format!(
                    "  [{}] {option}{}\n",
                    index + 1,
                    if index == default { "  (default)" } else { "" }
                ));
            }
            self.say(&format!("\n> [{}] ", default + 1));

            let answer = self.read_line()?;
            if answer.is_empty() {
                return Ok(default);
            }
            match answer.parse::<usize>() {
                Ok(choice) if choice >= 1 && choice <= options.len() => return Ok(choice - 1),
                _ => self.say(&format!(
                    "  please enter a number from 1 to {}\n",
                    options.len()
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> Plan {
        Plan {
            edition: Edition::Homelab,
            profile: NetworkProfile::Fritzbox,
            vantage: Vantage::LanHost,
            interfaces: vec!["eth0".into()],
            gateway: Some("192.168.178.1".parse().expect("ip")),
            lan: Some("192.168.178.0/24".into()),
            promiscuous: true,
            fritzbox_enabled: false,
            fritzbox_address: "fritz.box".into(),
            fritzbox_interfaces: Vec::new(),
            backend_api_url: None,
            backend_ingest_url: None,
            backend_allow_insecure_private_http: None,
        }
    }

    fn document(text: &str) -> DocumentMut {
        text.parse().expect("valid toml")
    }

    #[test]
    fn setup_writes_a_deployment_block_and_the_interface() {
        let mut doc = document("[sensor]\nname = \"kellersensor\"\n");
        update_document(&mut doc, &plan()).expect("update");
        let rendered = doc.to_string();

        let parsed: SensorConfig = toml::from_str(&rendered).expect("still parses");
        assert_eq!(parsed.deployment.edition, Edition::Homelab);
        assert_eq!(parsed.deployment.profile, NetworkProfile::Fritzbox);
        assert_eq!(parsed.deployment.vantage, Vantage::LanHost);
        assert_eq!(
            parsed.deployment.lan_cidr.as_deref(),
            Some("192.168.178.0/24")
        );
        assert_eq!(parsed.capture.interfaces, vec!["eth0".to_string()]);
        assert_eq!(parsed.sensor.name, "kellersensor");
    }

    /// The shipped config is mostly comments explaining the security model.
    /// Losing them to a setup run would be a real regression.
    #[test]
    fn comments_and_unrelated_settings_survive() {
        let mut doc = document(
            "# top comment\n\
             [sensor]\n\
             # the display name in the dashboard\n\
             name = \"sensor-01\"\n\
             mode = \"passive_only\"\n\n\
             [active]\n\
             # three keys are needed\n\
             acknowledged = false\n\
             targets = [\"10.0.0.0/24\"]\n",
        );
        update_document(&mut doc, &plan()).expect("update");
        let rendered = doc.to_string();

        assert!(rendered.contains("# top comment"));
        assert!(rendered.contains("# the display name in the dashboard"));
        assert!(rendered.contains("# three keys are needed"));
        assert!(rendered.contains("mode = \"passive_only\""));
        assert!(rendered.contains("targets = [\"10.0.0.0/24\"]"));
    }

    /// Setup must not be able to widen what the sensor may send. Everything
    /// behind the three-key rule stays untouched.
    #[test]
    fn setup_never_touches_the_active_discovery_keys() {
        let before = "[sensor]\nmode = \"passive_only\"\n\n[active]\nenabled = false\nacknowledged = false\ntargets = []\n";
        let mut doc = document(before);
        update_document(
            &mut doc,
            &Plan {
                profile: NetworkProfile::Span,
                vantage: Vantage::MirrorPort,
                ..plan()
            },
        )
        .expect("update");

        let parsed: SensorConfig = toml::from_str(&doc.to_string()).expect("parses");
        assert_eq!(
            parsed.sensor.mode,
            trapd_sensor_core::config::SensorMode::PassiveOnly
        );
        assert!(!parsed.active.enabled);
        assert!(!parsed.active.acknowledged);
        assert!(parsed.active.targets.is_empty());
        assert!(parsed.effective_policy().active.is_none());
    }

    #[test]
    fn re_running_setup_is_idempotent() {
        let mut first = document("[sensor]\nname = \"a\"\n");
        update_document(&mut first, &plan()).expect("update");
        let once = first.to_string();

        let mut second = document(&once);
        update_document(&mut second, &plan()).expect("update");
        assert_eq!(once, second.to_string());
    }

    #[test]
    fn switching_from_fritzbox_to_span_replaces_the_previous_answers() {
        let mut doc = document("[sensor]\nname = \"a\"\n");
        update_document(&mut doc, &plan()).expect("first run");
        update_document(
            &mut doc,
            &Plan {
                profile: NetworkProfile::Span,
                vantage: Vantage::MirrorPort,
                interfaces: vec!["eth1".into()],
                gateway: None,
                lan: None,
                ..plan()
            },
        )
        .expect("second run");

        let parsed: SensorConfig = toml::from_str(&doc.to_string()).expect("parses");
        assert_eq!(parsed.deployment.profile, NetworkProfile::Span);
        assert_eq!(parsed.deployment.vantage, Vantage::MirrorPort);
        assert_eq!(parsed.capture.interfaces, vec!["eth1".to_string()]);
        assert_eq!(
            parsed.deployment.gateway_ip, None,
            "a mirror port has no gateway of its own — the stale value must go"
        );
        assert_eq!(parsed.deployment.lan_cidr, None);
    }

    #[test]
    fn the_shipped_example_config_survives_a_setup_run() {
        let example = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/config.example.toml"),
        )
        .expect("example config");
        let mut doc = document(&example);
        update_document(&mut doc, &plan()).expect("update");

        let parsed: SensorConfig = toml::from_str(&doc.to_string()).expect("still parses");
        assert_eq!(parsed.deployment.profile, NetworkProfile::Fritzbox);
        assert!(parsed.validate().is_ok());
        assert!(
            doc.to_string().contains("LEER BEDEUTET: NICHTS SCANNEN"),
            "the security comments must survive"
        );
    }

    #[test]
    fn the_file_is_replaced_atomically_and_keeps_its_permissions() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("config.toml");
        std::fs::write(&path, "[sensor]\nname = \"a\"\n").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("chmod");

        write_config(&path, &plan()).expect("write config");

        let metadata = std::fs::metadata(&path).expect("metadata");
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o640);
        let parsed: SensorConfig =
            toml::from_str(&std::fs::read_to_string(&path).expect("read")).expect("parses");
        assert_eq!(parsed.deployment.profile, NetworkProfile::Fritzbox);
        assert!(
            std::fs::read_dir(directory.path())
                .expect("read_dir")
                .flatten()
                .all(|entry| entry.file_name() == "config.toml"),
            "no temporary file may be left behind"
        );
    }

    /// A config that does not exist yet is created with the packaged
    /// permissions. The ownership it aims for is `root:trapd-sensor`, which an
    /// unprivileged caller cannot set — that must warn, not abort, or setup
    /// would refuse to write any config path outside `/etc` (and this test
    /// would only pass as root).
    #[test]
    fn a_missing_config_file_is_created_even_without_the_right_to_chown() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("config.toml");

        write_config(&path, &plan()).expect("write config");

        let parsed = SensorConfig::load(&path).expect("loads");
        assert_eq!(parsed.deployment.edition, Edition::Homelab);
        assert_eq!(
            std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o640
        );
    }

    /// The caller already owns the file, so there is nothing to chown and
    /// nothing that may fail — the common case for every non-packaged path.
    #[test]
    fn rewriting_a_file_the_caller_owns_needs_no_ownership_change() {
        use std::os::unix::fs::MetadataExt;

        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("config.toml");
        std::fs::write(&path, "[sensor]\nname = \"a\"\n").expect("write");
        let before = std::fs::metadata(&path).expect("metadata");

        write_config(&path, &plan()).expect("write config");

        let after = std::fs::metadata(&path).expect("metadata");
        assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
        assert_eq!(
            after.permissions().mode() & 0o7777,
            before.permissions().mode() & 0o7777,
            "an existing file keeps the mode it had"
        );
    }

    #[test]
    fn a_broken_config_file_is_not_overwritten() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("config.toml");
        std::fs::write(&path, "this is not = = toml").expect("write");

        assert!(write_config(&path, &plan()).is_err());
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "this is not = = toml",
            "a parse failure must leave the operator's file alone"
        );
    }

    #[test]
    fn an_unattended_profile_change_brings_its_vantage_along() {
        use trapd_sensor_core::deployment::DeploymentConfig;

        let fritzbox = DeploymentConfig {
            profile: NetworkProfile::Fritzbox,
            vantage: Vantage::LanHost,
            ..Default::default()
        };

        // `setup --profile span` must not leave the sensor claiming lan_host.
        assert_eq!(
            unattended_vantage(None, NetworkProfile::Span, &fritzbox, Vantage::LanHost),
            Vantage::MirrorPort
        );
        // An explicit flag always wins.
        assert_eq!(
            unattended_vantage(
                Some(Vantage::Gateway),
                NetworkProfile::Span,
                &fritzbox,
                Vantage::LanHost
            ),
            Vantage::Gateway
        );
        // Re-running with the same profile must not overwrite a vantage the
        // operator chose by hand.
        let tapped = DeploymentConfig {
            profile: NetworkProfile::Span,
            vantage: Vantage::NetworkTap,
            ..Default::default()
        };
        assert_eq!(
            unattended_vantage(None, NetworkProfile::Span, &tapped, Vantage::NetworkTap),
            Vantage::NetworkTap
        );
        // A never-configured sensor takes the chosen profile's default.
        assert_eq!(
            unattended_vantage(
                None,
                NetworkProfile::Fritzbox,
                &DeploymentConfig::default(),
                Vantage::LanHost
            ),
            Vantage::LanHost
        );
    }

    #[test]
    fn group_lines_are_parsed() {
        assert_eq!(
            parse_group_line("trapd-sensor:x:990:", "trapd-sensor"),
            Some(990)
        );
        assert_eq!(parse_group_line("root:x:0:", "trapd-sensor"), None);
        assert_eq!(parse_group_line("", "trapd-sensor"), None);
    }

    #[test]
    fn the_plan_preview_drives_the_visibility_report() {
        let base = SensorConfig::default();
        let span = Plan {
            profile: NetworkProfile::Span,
            vantage: Vantage::MirrorPort,
            ..plan()
        };
        let report = span.preview(&base).visibility();
        assert_eq!(
            report.level("full_packet_visibility"),
            Some(trapd_sensor_core::visibility::VisibilityLevel::Full)
        );
        assert!(report.render_summary().contains("Managed Switch / SPAN"));
    }

    #[test]
    fn bare_private_ip_generates_http_urls_with_the_insecure_flag() {
        assert_eq!(
            backend_urls_for_host("10.0.0.22"),
            Some((
                "http://10.0.0.22:3001".to_string(),
                "http://10.0.0.22:8082".to_string(),
                true,
            ))
        );
    }

    #[test]
    fn bare_loopback_host_generates_http_urls_without_the_insecure_flag() {
        // Loopback is always allowed by validate() regardless of the flag,
        // so setup should not need to set it just to reach 127.0.0.1.
        assert_eq!(
            backend_urls_for_host("127.0.0.1"),
            Some((
                "http://127.0.0.1:3001".to_string(),
                "http://127.0.0.1:8082".to_string(),
                false,
            ))
        );
        assert_eq!(
            backend_urls_for_host("localhost"),
            Some((
                "http://localhost:3001".to_string(),
                "http://localhost:8082".to_string(),
                false,
            ))
        );
    }

    #[test]
    fn bare_public_host_generates_https_urls() {
        assert_eq!(
            backend_urls_for_host("sensors.example.com"),
            Some((
                "https://sensors.example.com:3001".to_string(),
                "https://sensors.example.com:8082".to_string(),
                false,
            ))
        );
    }

    #[test]
    fn blank_or_full_url_input_leaves_backend_untouched() {
        assert_eq!(backend_urls_for_host(""), None);
        assert_eq!(backend_urls_for_host("   "), None);
        assert_eq!(backend_urls_for_host("https://api.trapd.io"), None);
    }

    #[test]
    fn setup_input_10_0_0_22_produces_the_expected_config() {
        let mut doc = document("[sensor]\nname = \"a\"\n");
        let (api_url, ingest_url, allow) = backend_urls_for_host("10.0.0.22").expect("private ip");
        let plan = Plan {
            backend_api_url: Some(api_url),
            backend_ingest_url: Some(ingest_url),
            backend_allow_insecure_private_http: Some(allow),
            ..plan()
        };
        update_document(&mut doc, &plan).expect("update");

        let parsed: SensorConfig = toml::from_str(&doc.to_string()).expect("parses");
        assert_eq!(parsed.backend.api_url, "http://10.0.0.22:3001");
        assert_eq!(parsed.backend.ingest_url, "http://10.0.0.22:8082");
        assert!(parsed.backend.allow_insecure_private_http);
        assert!(parsed.validate().is_ok());
    }

    #[test]
    fn skipping_the_backend_prompt_leaves_existing_backend_config_untouched() {
        let mut doc = document(
            "[sensor]\nname = \"a\"\n\n[backend]\napi_url = \"https://api.trapd.io\"\ningest_url = \"https://ingest.trapd.io\"\n",
        );
        update_document(&mut doc, &plan()).expect("update");
        let parsed: SensorConfig = toml::from_str(&doc.to_string()).expect("parses");
        assert_eq!(parsed.backend.api_url, "https://api.trapd.io");
        assert_eq!(parsed.backend.ingest_url, "https://ingest.trapd.io");
        assert!(!parsed.backend.allow_insecure_private_http);
    }
}
