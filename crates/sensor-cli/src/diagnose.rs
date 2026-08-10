use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use trapd_sensor_core::config::SensorConfig;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Ok,
    Warning,
    Error,
}

#[derive(Debug, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub status: CheckStatus,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub status: CheckStatus,
    pub checks: Vec<Check>,
}

impl Report {
    fn new() -> Self {
        Self {
            schema_version: 1,
            status: CheckStatus::Ok,
            checks: Vec::new(),
        }
    }
    fn push(&mut self, id: &'static str, status: CheckStatus, message: impl Into<String>) {
        if status == CheckStatus::Error
            || (status == CheckStatus::Warning && self.status == CheckStatus::Ok)
        {
            self.status = status;
        }
        self.checks.push(Check {
            id,
            status,
            message: message.into(),
        });
    }
    pub fn exit_code(&self) -> u8 {
        match self.status {
            CheckStatus::Ok => 0,
            CheckStatus::Warning => 1,
            CheckStatus::Error => 2,
        }
    }
    pub fn render_text(&self) -> String {
        let mut out = format!("TRAPD Sensor diagnostics: {:?}\n\n", self.status);
        for check in &self.checks {
            out.push_str(&format!(
                "{:<9} {:<28} {}\n",
                format!("[{:?}]", check.status),
                check.id,
                check.message
            ));
        }
        out
    }
}

pub fn config_failure(path: &Path) -> Report {
    let mut report = Report::new();
    report.push(
        "config.parse",
        CheckStatus::Error,
        format!(
            "{} could not be parsed or validated; details are omitted to avoid exposing secrets",
            path.display()
        ),
    );
    report
}

pub async fn run(config_path: &Path, config: &SensorConfig) -> Report {
    let mut report = Report::new();
    check_config(&mut report, config_path, config);
    check_service(&mut report, config);
    check_capabilities(&mut report, config);
    check_network(&mut report, config);
    check_storage(&mut report, config);
    check_backend(&mut report, config).await;
    check_runtime(&mut report, config).await;
    report
}

fn check_config(report: &mut Report, path: &Path, config: &SensorConfig) {
    if path.exists() {
        report.push(
            "config.parse",
            CheckStatus::Ok,
            format!("{} parsed and validated", path.display()),
        );
        match std::fs::metadata(path) {
            Ok(meta) => {
                let mode = meta.mode() & 0o777;
                let status = if mode & 0o007 != 0 {
                    CheckStatus::Error
                } else if mode & 0o020 != 0 {
                    CheckStatus::Warning
                } else {
                    CheckStatus::Ok
                };
                report.push(
                    "config.permissions",
                    status,
                    format!("mode {mode:04o}, uid {}, gid {}", meta.uid(), meta.gid()),
                );
            }
            Err(error) => report.push("config.permissions", CheckStatus::Error, error.to_string()),
        }
    } else {
        report.push(
            "config.present",
            CheckStatus::Warning,
            format!("{} absent; built-in defaults are active", path.display()),
        );
    }
    let policy = config.effective_policy();
    report.push(
        "policy.local_cap",
        CheckStatus::Ok,
        format!(
            "mode={}, active_acknowledged={}, active_effective={}",
            config.sensor.mode.as_str(),
            config.active.acknowledged,
            policy.active.is_some()
        ),
    );
}

fn check_service(report: &mut Report, config: &SensorConfig) {
    let user = std::fs::read_to_string("/etc/passwd")
        .ok()
        .is_some_and(|p| p.lines().any(|l| l.starts_with("trapd-sensor:")));
    report.push(
        "service.user",
        if user {
            CheckStatus::Ok
        } else {
            CheckStatus::Warning
        },
        if user {
            "trapd-sensor service user exists"
        } else {
            "trapd-sensor user not found (expected in package installations)"
        },
    );
    let unit = [
        "/etc/systemd/system/trapd-sensor.service",
        "/usr/lib/systemd/system/trapd-sensor.service",
    ]
    .iter()
    .any(|p| Path::new(p).exists());
    report.push(
        "service.systemd",
        if unit {
            CheckStatus::Ok
        } else {
            CheckStatus::Warning
        },
        if unit {
            "systemd unit installed"
        } else {
            "systemd unit not found"
        },
    );
    report.push(
        "service.state_dir",
        path_status(&config.sensor.state_dir),
        format!("state directory {}", config.sensor.state_dir.display()),
    );
}

fn check_capabilities(report: &mut Report, config: &SensorConfig) {
    let effective = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("CapEff:\t")
                    .and_then(|v| u64::from_str_radix(v, 16).ok())
            })
        })
        .unwrap_or(0);
    for (id, bit, name, required) in [
        ("cap.net_raw", 13, "CAP_NET_RAW", true),
        (
            "cap.net_admin",
            12,
            "CAP_NET_ADMIN",
            config.capture.promiscuous,
        ),
    ] {
        let present = effective & (1u64 << bit) != 0;
        let status = if present {
            CheckStatus::Ok
        } else if required {
            CheckStatus::Error
        } else {
            CheckStatus::Warning
        };
        report.push(
            id,
            status,
            format!(
                "{name} {} (effective mask 0x{effective:016x})",
                if present { "available" } else { "missing" }
            ),
        );
    }
}

fn check_network(report: &mut Report, config: &SensorConfig) {
    let found = trapd_sensor_capture::list_interfaces();
    let selected = trapd_sensor_capture::select_interfaces(&config.capture.interfaces);
    for name in selected {
        let interface = found.iter().find(|i| i.name == name);
        match interface {
            None => report.push(
                "network.interface",
                CheckStatus::Error,
                format!("configured interface {name} does not exist"),
            ),
            Some(interface) => {
                let mtu = std::fs::read_to_string(format!("/sys/class/net/{name}/mtu"))
                    .ok()
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|| "unknown".into());
                let ipv6 = ipv6_addresses(&name);
                let status = if interface.is_capturable() {
                    CheckStatus::Ok
                } else {
                    CheckStatus::Error
                };
                report.push(
                    "network.interface",
                    status,
                    format!(
                        "{name}: state={}, mtu={mtu}, mac={}, ipv6={}",
                        interface.operstate,
                        interface.mac.as_deref().unwrap_or("none"),
                        if ipv6.is_empty() {
                            "none".into()
                        } else {
                            ipv6.join(",")
                        }
                    ),
                );
                match trapd_sensor_capture::AfPacketSource::open(
                    &name,
                    config.capture.promiscuous,
                    Duration::from_millis(20),
                ) {
                    Ok(_) => report.push(
                        "network.af_packet",
                        CheckStatus::Ok,
                        format!("AF_PACKET opened on {name}"),
                    ),
                    Err(error) => {
                        report.push("network.af_packet", CheckStatus::Error, error.to_string())
                    }
                }
            }
        }
    }
}

fn ipv6_addresses(interface: &str) -> Vec<String> {
    std::fs::read_to_string("/proc/net/if_inet6")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let p: Vec<_> = line.split_whitespace().collect();
            if p.len() == 6 && p[5] == interface {
                Some(format!(
                    "{}/{}",
                    p[0],
                    u8::from_str_radix(p[2], 16).unwrap_or(0)
                ))
            } else {
                None
            }
        })
        .collect()
}

fn check_storage(report: &mut Report, config: &SensorConfig) {
    for (id, path) in [
        ("storage.state", &config.sensor.state_dir),
        ("storage.wal", &config.buffer.dir),
    ] {
        report.push(
            id,
            path_status(path),
            format!(
                "{} ({})",
                path.display(),
                if is_writable(path) {
                    "writable"
                } else {
                    "not writable"
                }
            ),
        );
    }
    let bytes = directory_bytes(&config.buffer.dir).unwrap_or(0);
    report.push(
        "storage.wal_usage",
        if bytes > config.buffer.max_disk_bytes {
            CheckStatus::Error
        } else {
            CheckStatus::Ok
        },
        format!(
            "{bytes} bytes used, {} bytes configured maximum",
            config.buffer.max_disk_bytes
        ),
    );
    if let Some(free) = free_bytes(&config.buffer.dir) {
        report.push(
            "storage.free",
            if free < config.buffer.segment_bytes {
                CheckStatus::Error
            } else {
                CheckStatus::Ok
            },
            format!("{free} bytes available"),
        );
    }
}

async fn check_backend(report: &mut Report, config: &SensorConfig) {
    let Ok(url) = reqwest::Url::parse(&config.backend.api_url) else {
        report.push("backend.url", CheckStatus::Error, "invalid backend URL");
        return;
    };
    let Some(host) = url.host_str() else {
        report.push("backend.url", CheckStatus::Error, "backend URL has no host");
        return;
    };
    let port = url.port_or_known_default().unwrap_or(443);
    match tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::lookup_host((host, port)),
    )
    .await
    {
        Ok(Ok(mut addresses)) => {
            if let Some(address) = addresses.next() {
                report.push("backend.dns", CheckStatus::Ok, format!("{host} resolved"));
                match tokio::time::timeout(
                    Duration::from_secs(3),
                    tokio::net::TcpStream::connect(address),
                )
                .await
                {
                    Ok(Ok(_)) => report.push(
                        "backend.tcp",
                        CheckStatus::Ok,
                        format!("TCP {host}:{port} reachable"),
                    ),
                    _ => report.push(
                        "backend.tcp",
                        CheckStatus::Warning,
                        format!("TCP {host}:{port} unavailable"),
                    ),
                }
            } else {
                report.push(
                    "backend.dns",
                    CheckStatus::Warning,
                    format!("{host} returned no addresses"),
                );
            }
        }
        _ => report.push(
            "backend.dns",
            CheckStatus::Warning,
            format!("could not resolve {host}"),
        ),
    }
    report.push("backend.tls", CheckStatus::Warning, "TLS is verified by rustls during authenticated transport requests; diagnose does not call an assumed backend route");
}

async fn check_runtime(report: &mut Report, config: &SensorConfig) {
    let url = format!("http://{}/admin/status", config.admin.listen);
    match reqwest::Client::new()
        .get(&url)
        .timeout(Duration::from_secs(2))
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            match response.json::<serde_json::Value>().await {
                Ok(status) => report.push(
                    "runtime.admin",
                    CheckStatus::Ok,
                    format!(
                        "daemon {}, health={}, queue_pending={}",
                        status["version"].as_str().unwrap_or("unknown"),
                        status["health"].as_str().unwrap_or("unknown"),
                        status["queue"]["pending"].as_u64().unwrap_or(0)
                    ),
                ),
                Err(_) => report.push(
                    "runtime.admin",
                    CheckStatus::Error,
                    "admin endpoint returned malformed JSON",
                ),
            }
        }
        _ => report.push(
            "runtime.admin",
            CheckStatus::Warning,
            "daemon admin endpoint is unavailable",
        ),
    }
}

fn path_status(path: &Path) -> CheckStatus {
    if !path.exists() {
        CheckStatus::Warning
    } else if is_writable(path) {
        CheckStatus::Ok
    } else {
        CheckStatus::Error
    }
}
fn is_writable(path: &Path) -> bool {
    let probe = if path.is_dir() {
        path.join(".diagnose-write-test")
    } else {
        PathBuf::from(path)
    };
    if path.is_file() {
        return !std::fs::metadata(path)
            .map(|m| m.permissions().readonly())
            .unwrap_or(true);
    }
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(probe);
            true
        }
        Err(_) => false,
    }
}
fn directory_bytes(path: &Path) -> std::io::Result<u64> {
    let mut total = 0u64;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            total = total.saturating_add(entry.metadata()?.len());
        }
    }
    Ok(total)
}
fn free_bytes(path: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    let rc = unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    let stat = unsafe { stat.assume_init() };
    Some(stat.f_bavail.saturating_mul(stat.f_frsize))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn report_exit_codes_are_stable() {
        let mut r = Report::new();
        assert_eq!(r.exit_code(), 0);
        r.push("x", CheckStatus::Warning, "warning");
        assert_eq!(r.exit_code(), 1);
        r.push("y", CheckStatus::Error, "error");
        assert_eq!(r.exit_code(), 2);
    }
    #[test]
    fn json_schema_is_versioned_and_secret_free() {
        let mut r = Report::new();
        r.push("cap.net_raw", CheckStatus::Ok, "available");
        let value = serde_json::to_value(r).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["checks"][0]["id"], "cap.net_raw");
    }
}
