//! Optional gateway identification for `trapd-sensorctl setup`.
//!
//! The wizard asks what manages the network. This probe checks what of that
//! answer can actually be confirmed — and, more importantly, what the platform
//! offers that TRAPD could use. It is deliberately tiny:
//!
//! * it runs only against **one** address, the host's own default gateway,
//! * only after the operator explicitly agreed to it (or passed
//!   `--probe-gateway`),
//! * only unauthenticated requests: no credentials are sent, asked for, or
//!   stored, and no response body is logged or printed,
//! * never from the daemon. `trapd-sensord` remains bound by its operating
//!   mode and the three-key rule for active discovery; nothing here changes
//!   what the running sensor may send.
//!
//! What it is not: a scanner. There is no port sweep, no version detection and
//! no credential guessing — the same line the rest of the product draws.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use trapd_sensor_core::deployment::NetworkProfile;

/// Kept short: this runs while an operator waits at a prompt, and a gateway
/// that does not answer within this window is simply "not identified".
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

/// Only ever read this much of a response — enough for the markers below,
/// small enough that a misbehaving device cannot make the wizard hang on a
/// multi-megabyte body.
const MAX_BODY_BYTES: usize = 16 * 1024;

/// TR-064 lives here on AVM devices; the descriptor is served without
/// authentication and is the one genuinely useful unauthenticated fact a
/// FRITZ!Box offers.
const TR064_PORT: u16 = 49000;

/// HTTPS management ports checked with a plain TCP connect (no TLS handshake,
/// no request) — enough to report "the management interface is reachable"
/// without touching the certificate story. Both are in the sensor's built-in
/// balanced-mode port allowlist.
const HTTPS_MANAGEMENT_PORTS: [u16; 2] = [443, 8443];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Stable identifier, e.g. `tr064`, `http`, `https`.
    pub id: &'static str,
    /// One line for the operator. Never contains response bodies.
    pub detail: String,
    /// The profile this finding points at, if any.
    pub suggests: Option<NetworkProfile>,
}

#[derive(Debug, Clone)]
pub struct GatewayReport {
    pub gateway: IpAddr,
    pub findings: Vec<Finding>,
}

impl GatewayReport {
    /// The profile the findings agree on, if they agree at all.
    pub fn suggested_profile(&self) -> Option<NetworkProfile> {
        let mut suggested = self.findings.iter().filter_map(|f| f.suggests);
        let first = suggested.next()?;
        suggested.all(|p| p == first).then_some(first)
    }

    pub fn render(&self) -> String {
        if self.findings.is_empty() {
            return format!(
                "  no identifying response from {} — that is normal for a router whose \
                 management interface is HTTPS-only or switched off.\n",
                self.gateway
            );
        }
        self.findings
            .iter()
            .map(|f| format!("  {}\n", f.detail))
            .collect()
    }
}

pub async fn probe_gateway(gateway: IpAddr) -> GatewayReport {
    let client = reqwest::Client::builder()
        .timeout(PROBE_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(trapd_sensor_core::user_agent())
        .build();

    let mut findings = Vec::new();

    if let Ok(client) = client {
        if let Some(body) = fetch(&client, &url(gateway, TR064_PORT, "/tr64desc.xml")).await {
            if let Some(model) = tr064_model(&body) {
                findings.push(Finding {
                    id: "tr064",
                    detail: format!(
                        "TR-064 device description on port {TR064_PORT}: {model} \
                         (read without credentials)"
                    ),
                    suggests: Some(NetworkProfile::Fritzbox),
                });
            } else {
                findings.push(Finding {
                    id: "tr064",
                    detail: format!(
                        "TR-064 responds on port {TR064_PORT} but the description carries no \
                         model name"
                    ),
                    suggests: None,
                });
            }
        }

        if let Some(body) = fetch(&client, &url(gateway, 80, "/")).await {
            let (label, profile) = identify_http(&body);
            findings.push(Finding {
                id: "http",
                detail: format!("HTTP management interface on port 80: {label}"),
                suggests: profile,
            });
        }
    }

    for port in HTTPS_MANAGEMENT_PORTS {
        if tcp_reachable(SocketAddr::new(gateway, port)).await {
            findings.push(Finding {
                id: "https",
                detail: format!(
                    "port {port}/tcp accepts connections — an HTTPS management interface is \
                     reachable (TRAPD does not log in)"
                ),
                suggests: None,
            });
        }
    }

    GatewayReport { gateway, findings }
}

fn url(gateway: IpAddr, port: u16, path: &str) -> String {
    // IPv6 literals need brackets; SocketAddr's Display already does that.
    format!("http://{}{path}", SocketAddr::new(gateway, port))
}

async fn fetch(client: &reqwest::Client, url: &str) -> Option<String> {
    let response = client.get(url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let bytes = response.bytes().await.ok()?;
    let end = bytes.len().min(MAX_BODY_BYTES);
    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

async fn tcp_reachable(address: SocketAddr) -> bool {
    matches!(
        tokio::time::timeout(PROBE_TIMEOUT, tokio::net::TcpStream::connect(address)).await,
        Ok(Ok(_))
    )
}

/// Pulls the model out of a TR-064 device description. A three-line substring
/// scan rather than an XML parser: the interesting element is a fixed,
/// well-known tag, and this keeps an untrusted document off a parser's stack.
pub(crate) fn tr064_model(body: &str) -> Option<String> {
    for tag in ["modelName", "friendlyName", "modelDescription"] {
        if let Some(value) = between(body, &format!("<{tag}>"), &format!("</{tag}>")) {
            let cleaned = sanitize(value);
            if !cleaned.is_empty() {
                return Some(cleaned);
            }
        }
    }
    None
}

/// Identifies a management interface from marker strings. Deliberately
/// conservative: an unrecognised page is reported as "not identified", never
/// guessed at.
pub(crate) fn identify_http(body: &str) -> (String, Option<NetworkProfile>) {
    const MARKERS: &[(&str, &str, NetworkProfile)] = &[
        ("FRITZ!Box", "FRITZ!Box", NetworkProfile::Fritzbox),
        ("fritz.box", "FRITZ!Box", NetworkProfile::Fritzbox),
        ("OPNsense", "OPNsense", NetworkProfile::Opnsense),
        ("pfSense", "pfSense", NetworkProfile::Pfsense),
        ("OpenWrt", "OpenWrt", NetworkProfile::Openwrt),
        ("LuCI", "OpenWrt (LuCI)", NetworkProfile::Openwrt),
        ("UniFi", "UniFi", NetworkProfile::Unifi),
    ];
    let haystack = body.to_ascii_lowercase();
    for (marker, label, profile) in MARKERS {
        if haystack.contains(&marker.to_ascii_lowercase()) {
            return ((*label).to_string(), Some(*profile));
        }
    }
    ("reachable, not identified".to_string(), None)
}

fn between<'a>(haystack: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = haystack.find(open)? + open.len();
    let rest = &haystack[start..];
    let end = rest.find(close)?;
    Some(&rest[..end])
}

/// Device-supplied text ends up on the operator's terminal, so it gets the
/// same treatment as a service banner: printable ASCII, hard length cap.
fn sanitize(raw: &str) -> String {
    trapd_sensor_core::sanitize_banner(raw.as_bytes()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tr064_description_yields_the_model() {
        let body = r#"<?xml version="1.0"?><root><device>
            <deviceType>urn:dslforum-org:device:InternetGatewayDevice:1</deviceType>
            <friendlyName>FRITZ!Box 7590</friendlyName>
            <modelName>FRITZ!Box 7590</modelName>
        </device></root>"#;
        assert_eq!(tr064_model(body).as_deref(), Some("FRITZ!Box 7590"));
    }

    #[test]
    fn a_description_without_a_model_is_not_invented() {
        assert_eq!(tr064_model("<root><device/></root>"), None);
        assert_eq!(tr064_model("<modelName></modelName>"), None);
    }

    /// Whatever the device sends lands on a terminal — control characters and
    /// unbounded strings do not.
    #[test]
    fn device_supplied_text_is_sanitised() {
        let body = "<modelName>evil\u{1b}[2Jbox\u{0}</modelName>";
        let model = tr064_model(body).expect("model");
        assert!(!model.contains('\u{1b}'), "{model}");
        assert!(model.starts_with("evil"), "{model}");

        let long = format!("<modelName>{}</modelName>", "A".repeat(4096));
        assert_eq!(tr064_model(&long).expect("model").len(), 256);
    }

    #[test]
    fn known_platforms_are_recognised_case_insensitively() {
        assert_eq!(
            identify_http("<title>fritz!box 7590</title>").1,
            Some(NetworkProfile::Fritzbox)
        );
        assert_eq!(
            identify_http("<h1>OPNsense</h1>").1,
            Some(NetworkProfile::Opnsense)
        );
        assert_eq!(
            identify_http("powered by LuCI").1,
            Some(NetworkProfile::Openwrt)
        );
    }

    #[test]
    fn an_unknown_page_is_reported_as_unidentified() {
        let (label, profile) = identify_http("<html><body>hello</body></html>");
        assert_eq!(profile, None);
        assert!(label.contains("not identified"));
    }

    #[test]
    fn agreeing_findings_suggest_a_profile_and_conflicting_ones_do_not() {
        let gateway: IpAddr = "192.168.178.1".parse().expect("ip");
        let fritz = Finding {
            id: "tr064",
            detail: "x".into(),
            suggests: Some(NetworkProfile::Fritzbox),
        };
        let openwrt = Finding {
            id: "http",
            detail: "y".into(),
            suggests: Some(NetworkProfile::Openwrt),
        };
        let neutral = Finding {
            id: "https",
            detail: "z".into(),
            suggests: None,
        };

        let agreeing = GatewayReport {
            gateway,
            findings: vec![fritz.clone(), neutral.clone()],
        };
        assert_eq!(
            agreeing.suggested_profile(),
            Some(NetworkProfile::Fritzbox),
            "a neutral finding must not veto an identification"
        );

        let conflicting = GatewayReport {
            gateway,
            findings: vec![fritz, openwrt],
        };
        assert_eq!(
            conflicting.suggested_profile(),
            None,
            "the wizard must not pick a side when the gateway contradicts itself"
        );

        let quiet = GatewayReport {
            gateway,
            findings: vec![neutral],
        };
        assert_eq!(quiet.suggested_profile(), None);
    }

    #[test]
    fn an_empty_report_explains_itself() {
        let report = GatewayReport {
            gateway: "10.0.0.1".parse().expect("ip"),
            findings: Vec::new(),
        };
        assert!(report.render().contains("no identifying response"));
    }

    #[test]
    fn ipv6_gateways_produce_a_bracketed_url() {
        let gateway: IpAddr = "fe80::1".parse().expect("ip");
        assert_eq!(url(gateway, 80, "/"), "http://[fe80::1]:80/");
    }
}
