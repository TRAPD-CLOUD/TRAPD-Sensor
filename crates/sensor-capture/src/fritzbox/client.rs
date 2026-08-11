use super::{challenge_response, AuthError, CaptureInterface, Credentials, PcapStreamDecoder};
use reqwest::{header::CONTENT_TYPE, redirect::Policy, StatusCode, Url};
use scraper::{ElementRef, Html, Selector};
use std::time::Duration;
use thiserror::Error;

const MAX_DISCOVERY_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum FritzBoxError {
    #[error("invalid FRITZ!Box address: only http(s), a host, and an optional port are allowed")]
    InvalidAddress,
    #[error(transparent)]
    Auth(#[from] AuthError),
    // reqwest errors can contain the complete request URL even in a Debug/source
    // chain. Login and capture URLs carry password-derived material or a SID,
    // so the public error deliberately does not retain that URL.
    #[error("FRITZ!Box HTTP request failed")]
    Http,
    #[error("FRITZ!Box returned an unexpected response")]
    UnexpectedResponse,
    #[error("configured capture interface is not advertised by this FRITZ!Box")]
    UnknownInterface,
    #[error("FRITZ!Box interface discovery failed: {diagnostic}")]
    InterfaceDiscovery { diagnostic: String },
}

impl From<reqwest::Error> for FritzBoxError {
    fn from(_source: reqwest::Error) -> Self {
        Self::Http
    }
}

/// Provider-specific client. Redirects and automatic decompression are disabled
/// to keep credentials on the configured origin and avoid decompression bombs.
pub struct FritzBoxClient {
    base: Url,
    http: reqwest::Client,
}
pub struct FritzBoxSession<'a> {
    client: &'a FritzBoxClient,
    sid: String,
}

impl FritzBoxClient {
    pub fn new(
        address: &str,
        connect_timeout: Duration,
        read_timeout: Duration,
    ) -> Result<Self, FritzBoxError> {
        let candidate = if address.contains("://") {
            address.to_owned()
        } else {
            format!("http://{address}")
        };
        let base = Url::parse(&candidate).map_err(|_| FritzBoxError::InvalidAddress)?;
        if !matches!(base.scheme(), "http" | "https")
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.path() != "/"
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err(FritzBoxError::InvalidAddress);
        }
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(connect_timeout)
            .read_timeout(read_timeout)
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .build()?;
        Ok(Self { base, http })
    }

    pub async fn authenticate(
        &self,
        credentials: &Credentials,
    ) -> Result<FritzBoxSession<'_>, FritzBoxError> {
        let url = self
            .base
            .join("login_sid.lua")
            .map_err(|_| FritzBoxError::InvalidAddress)?;
        let first = self
            .http
            .get(url.clone())
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let challenge = tag(&first, "Challenge").ok_or(AuthError::MalformedResponse)?;
        let (_, response) = challenge_response(challenge, &credentials.password)?;
        let body = self
            .http
            .get(url)
            .query(&[
                ("username", credentials.username.as_str()),
                ("response", response.as_str()),
            ])
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let sid = tag(&body, "SID").ok_or(AuthError::MalformedResponse)?;
        if sid == "0000000000000000" {
            return Err(AuthError::Rejected.into());
        }
        if sid.len() != 16 || !sid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(AuthError::MalformedResponse.into());
        }
        Ok(FritzBoxSession {
            client: self,
            sid: sid.to_owned(),
        })
    }
}

impl FritzBoxSession<'_> {
    /// Discover the router-defined capture IDs. FRITZ!OS has used both the
    /// `data.lua?page=cap` response and standalone capture pages. We prefer the
    /// semantic XHR endpoint, but retain page fallbacks for older/newer models.
    pub async fn capture_interfaces(&self) -> Result<Vec<CaptureInterface>, FritzBoxError> {
        let mut diagnostics = Vec::new();
        let requests = [
            ("POST data.lua?page=cap", "data.lua", true),
            ("GET capture.lua", "capture.lua", false),
            ("GET html/capture.lua", "html/capture.lua", false),
            ("GET html/capture.html", "html/capture.html", false),
        ];

        for (label, path, post) in requests {
            let url = self
                .client
                .base
                .join(path)
                .map_err(|_| FritzBoxError::InvalidAddress)?;
            let request = if post {
                // SID is hexadecimal, so this fixed form body needs no dynamic
                // percent encoding. Keep it out of URLs and diagnostics.
                self.client
                    .http
                    .post(url)
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(format!(
                        "xhr=1&sid={}&lang=en&page=cap&no_sidrenew=",
                        self.sid
                    ))
            } else {
                self.client
                    .http
                    .get(url)
                    .query(&[("sid", self.sid.as_str())])
            };

            let response = match request.send().await {
                Ok(response) => response,
                Err(error) => {
                    diagnostics.push(format!(
                        "{label}: request error: {}",
                        sanitized_error(&error)
                    ));
                    continue;
                }
            };
            let status = response.status();
            let content_type = response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("(missing)")
                .to_owned();
            let bytes = match read_bounded(response, MAX_DISCOVERY_RESPONSE_BYTES).await {
                Ok(bytes) => bytes,
                Err(error) => {
                    diagnostics.push(format!("{label}: HTTP {status}, {content_type}, {error}"));
                    continue;
                }
            };
            let body = String::from_utf8_lossy(&bytes);
            let found = parse_interfaces(&body);
            let summary = response_summary(label, status, &content_type, &body, found.len());
            tracing::debug!(discovery = %summary, "FRITZ!Box capture discovery response");
            if !found.is_empty() {
                tracing::info!(
                    endpoint = label,
                    interfaces = found.len(),
                    "discovered FRITZ!Box capture interfaces"
                );
                return Ok(found);
            }
            diagnostics.push(summary);
        }

        Err(FritzBoxError::InterfaceDiscovery {
            diagnostic: diagnostics.join("; "),
        })
    }

    pub async fn start_capture(
        &self,
        interface: &CaptureInterface,
        max_packet_bytes: usize,
    ) -> Result<reqwest::Response, FritzBoxError> {
        if !interface.available || interface.id.is_empty() {
            return Err(FritzBoxError::UnknownInterface);
        }
        let url = self
            .client
            .base
            .join("cgi-bin/capture_notimeout")
            .map_err(|_| FritzBoxError::InvalidAddress)?;
        let snaplen = max_packet_bytes.to_string();
        let response = self
            .client
            .http
            .get(url)
            .query(&[
                ("sid", self.sid.as_str()),
                ("ifaceorminor", interface.id.as_str()),
                ("capture", "Start"),
                ("snaplen", snaplen.as_str()),
            ])
            .send()
            .await?;
        if response.status().is_redirection() {
            return Err(FritzBoxError::UnexpectedResponse);
        }
        Ok(response.error_for_status()?)
    }
}

/// Bounded, credential-safe summary of a capture response, used to diagnose a
/// stream that failed to parse as PCAP. Never carries the SID, cookies, or
/// authorization headers — only status, content-type, content-length, and the
/// (SID-redacted) request URL.
#[derive(Debug)]
pub struct CaptureResponseDiagnostic {
    pub status: StatusCode,
    pub content_type: String,
    pub content_length: Option<u64>,
    pub url: String,
}

impl std::fmt::Display for CaptureResponseDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HTTP {}, content-type={}, content-length={}, url={}",
            self.status,
            self.content_type,
            self.content_length
                .map(|len| len.to_string())
                .unwrap_or_else(|| "(unknown)".to_owned()),
            self.url,
        )
    }
}

/// Captures response metadata before the body is streamed. Safe to log at any
/// level: the URL has its `sid` query parameter redacted, and no headers other
/// than `Content-Type` are read.
pub fn describe_capture_response(response: &reqwest::Response) -> CaptureResponseDiagnostic {
    CaptureResponseDiagnostic {
        status: response.status(),
        content_type: response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("(missing)")
            .to_owned(),
        content_length: response.content_length(),
        url: redact_parameter(response.url().as_str(), "sid"),
    }
}

/// Bounded hex + ASCII preview of the first bytes of a capture stream. Only
/// feed this bytes captured *before* the decoder has produced a first packet:
/// once real Ethernet frames are flowing, their payloads must never be
/// logged. Verbose by design — callers should gate this behind debug logging.
pub fn preview_stream_bytes(bytes: &[u8]) -> String {
    let take = bytes.len().min(64);
    let hex = bytes[..take]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    let ascii: String = bytes[..take]
        .iter()
        .map(|&byte| {
            if byte.is_ascii_graphic() || byte == b' ' {
                byte as char
            } else {
                '.'
            }
        })
        .collect();
    format!("{take} bytes: hex=[{hex}] ascii=\"{ascii}\"")
}

/// Best-effort, credential-safe reason a capture stream is not PCAP: checks
/// the declared content-type first, then the shape of the leading bytes.
pub fn classify_non_pcap(content_type: &str, bytes: &[u8]) -> String {
    let lower = content_type.to_ascii_lowercase();
    if lower.contains("html") {
        return format!(
            "content-type is {content_type} — likely an HTML login or error page, not a PCAP stream"
        );
    }
    if lower.contains("json") {
        return format!(
            "content-type is {content_type} — likely a JSON error response, not a PCAP stream"
        );
    }
    if bytes
        .iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| *byte == b'<')
    {
        return "response body starts with '<' — likely HTML/XML, not a PCAP stream".to_owned();
    }
    match bytes.get(0..4) {
        // d4c3b2a1 / a1b2c3d4: standard pcap. 4d3cb2a1 / a1b23c4d: nanosecond
        // pcap. 34cdb2a1 / a1b2cd34: the Kuznetsov-modified/"extended"
        // variant FRITZ!OS itself emits (see `PcapVariant::Extended`) — a
        // real, supported format, not evidence of HTTP or stream corruption.
        Some(magic) => format!(
            "unexpected magic bytes {:02x} {:02x} {:02x} {:02x} (expected d4c3b2a1 / a1b2c3d4, 4d3cb2a1 / a1b23c4d, or 34cdb2a1 / a1b2cd34)",
            magic[0], magic[1], magic[2], magic[3]
        ),
        None => "stream ended before a PCAP global header could be read".to_owned(),
    }
}

/// Logs a one-time debug summary of the parsed PCAP format, once the global
/// header is known. Returns whether it logged, so a caller in a streaming
/// loop can stop calling this once `true`. Only header-level metadata is
/// logged (variant/endian/timestamp precision/link type/snaplen) — never
/// captured traffic bytes, preserving the same privacy invariant as the rest
/// of this module.
pub fn log_pcap_format_if_known(decoder: &PcapStreamDecoder) -> bool {
    let (Some(variant), Some(endian), Some(precision), Some(link_type), Some(snaplen)) = (
        decoder.variant(),
        decoder.endian(),
        decoder.timestamp_precision(),
        decoder.link_type(),
        decoder.snaplen(),
    ) else {
        return false;
    };
    tracing::debug!(
        target: "trapd_sensor_capture",
        variant = %variant,
        endian = %endian,
        timestamp = %precision,
        linktype = link_type,
        snaplen = snaplen,
        "PCAP format detected"
    );
    true
}

async fn read_bounded(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(format!("response exceeds {limit} byte limit"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("response body failed: {error}"))?
    {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(format!("response exceeds {limit} byte limit"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn tag<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let start = format!("<{name}>");
    let end = format!("</{name}>");
    let from = xml.find(&start)? + start.len();
    let to = xml[from..].find(&end)? + from;
    Some(xml[from..to].trim())
}

fn parse_interfaces(response: &str) -> Vec<CaptureInterface> {
    let mut out = Vec::new();
    parse_markup_interfaces(response, &mut out);

    // data.lua normally returns HTML for `page=cap`, but some FRITZ!OS UI
    // generations wrap fragments or structured interface data in JSON.
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(response) {
        parse_json_interfaces(&json, &mut out);
    }
    out
}

fn parse_markup_interfaces(markup: &str, out: &mut Vec<CaptureInterface>) {
    // FRITZ!OS emits incomplete fragments on data.lua and full documents on
    // the page endpoints. An HTML5 parser handles both, including arbitrary
    // attribute ordering, quoting and entity encoding.
    let document = Html::parse_fragment(markup);
    let all = Selector::parse("*").expect("static selector");
    let row_labels = Selector::parse("th, label").expect("static selector");
    let mut category = "router".to_owned();

    for element in document.select(&all) {
        let tag_name = element.value().name();
        if matches!(tag_name, "h2" | "h3" | "legend") {
            let heading = element_text(element);
            if !heading.is_empty() {
                category = heading;
            }
            continue;
        }

        let control_name = element.value().attr("name").unwrap_or_default();
        let mut candidates = Vec::new();

        if control_name.eq_ignore_ascii_case("start")
            || control_name.eq_ignore_ascii_case("ifaceorminor")
        {
            if let Some(id) = element.value().attr("value") {
                candidates.push(id.to_owned());
            }
        } else if control_name.eq_ignore_ascii_case("capture") {
            // Retained for a short-lived/legacy form variant. Never mistake
            // the action values Start/Stop for interface IDs.
            if let Some(id) = element.value().attr("value") {
                if !matches!(id.to_ascii_lowercase().as_str(), "start" | "stop") {
                    candidates.push(id.to_owned());
                }
            }
        }

        // A few form variants put the semantic name on <select> and IDs on
        // child <option> elements.
        if tag_name == "option"
            && element
                .ancestors()
                .filter_map(ElementRef::wrap)
                .any(|parent| {
                    parent
                        .value()
                        .attr("name")
                        .is_some_and(|name| name.eq_ignore_ascii_case("ifaceorminor"))
                })
        {
            if let Some(id) = element.value().attr("value") {
                candidates.push(id.to_owned());
            }
        }

        // Links and JavaScript handlers are parsed by parameter semantics, not
        // by tag name or a fixed FRITZ!OS DOM layout.
        for (_, value) in element.value().attrs() {
            if let Some(id) = query_parameter(value, "ifaceorminor") {
                candidates.push(id);
            }
        }

        let self_disabled = element.value().attr("disabled").is_some()
            || element.value().attr("class").is_some_and(|class| {
                class
                    .split_ascii_whitespace()
                    .any(|item| item.eq_ignore_ascii_case("disabled"))
            });
        let available = !self_disabled
            && !element
                .ancestors()
                .filter_map(ElementRef::wrap)
                .any(|node| {
                    node.value().attr("disabled").is_some()
                        || node.value().attr("class").is_some_and(|class| {
                            class
                                .split_ascii_whitespace()
                                .any(|item| item.eq_ignore_ascii_case("disabled"))
                        })
                });
        for id in candidates {
            let display = element
                .value()
                .attr("aria-label")
                .or_else(|| element.value().attr("title"))
                .map(decode_html)
                .filter(|label| !label.trim().is_empty())
                .or_else(|| {
                    (tag_name == "a" || tag_name == "option").then(|| element_text(element))
                })
                .filter(|label| !label.trim().is_empty())
                .or_else(|| row_label(element, &row_labels))
                .unwrap_or_else(|| id.clone());
            push_interface(out, id, display, category.clone(), available);
        }
    }
}

fn element_text(element: ElementRef<'_>) -> String {
    clean_text(&element.text().collect::<Vec<_>>().join(" "), 128)
}

fn row_label(element: ElementRef<'_>, labels: &Selector) -> Option<String> {
    element
        .ancestors()
        .filter_map(ElementRef::wrap)
        .find(|ancestor| ancestor.value().name() == "tr")
        .and_then(|row| row.select(labels).next())
        .map(element_text)
        .filter(|label| !label.is_empty())
}

fn parse_json_interfaces(value: &serde_json::Value, out: &mut Vec<CaptureInterface>) {
    match value {
        serde_json::Value::String(text) => parse_markup_interfaces(text, out),
        serde_json::Value::Array(items) => {
            for item in items {
                parse_json_interfaces(item, out);
            }
        }
        serde_json::Value::Object(object) => {
            let id = object
                .iter()
                .find(|(key, value)| {
                    matches!(
                        key.to_ascii_lowercase().as_str(),
                        "ifaceorminor" | "interfaceid" | "interface_id"
                    ) && value.is_string()
                })
                .and_then(|(_, value)| value.as_str());
            if let Some(id) = id {
                let display = json_string(
                    object,
                    &[
                        "display_name",
                        "displayName",
                        "label",
                        "title",
                        "name",
                        "text",
                    ],
                )
                .unwrap_or(id);
                let category =
                    json_string(object, &["category", "group", "section"]).unwrap_or("router");
                let available = object
                    .get("available")
                    .and_then(serde_json::Value::as_bool)
                    .or_else(|| {
                        object
                            .get("disabled")
                            .and_then(serde_json::Value::as_bool)
                            .map(|v| !v)
                    })
                    .unwrap_or(true);
                push_interface(
                    out,
                    id.to_owned(),
                    display.to_owned(),
                    category.to_owned(),
                    available,
                );
            }
            for child in object.values() {
                parse_json_interfaces(child, out);
            }
        }
        _ => {}
    }
}

fn json_string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(serde_json::Value::as_str))
}

fn push_interface(
    out: &mut Vec<CaptureInterface>,
    id: String,
    display_name: String,
    category: String,
    available: bool,
) {
    let id = decode_html(&id).trim().to_owned();
    if id.is_empty()
        || id.len() > 128
        || id.chars().any(char::is_control)
        || matches!(id.to_ascii_lowercase().as_str(), "start" | "stop")
    {
        return;
    }
    if let Some(existing) = out.iter_mut().find(|item| item.id == id) {
        existing.available |= available;
        return;
    }
    let display_name = clean_text(&display_name, 128);
    let category = clean_text(&category, 64);
    out.push(CaptureInterface {
        display_name: if display_name.is_empty() {
            id.clone()
        } else {
            display_name
        },
        category: if category.is_empty() {
            "router".into()
        } else {
            category
        },
        id,
        available,
    });
}

fn query_parameter(value: &str, wanted: &str) -> Option<String> {
    let decoded = decode_html(value);
    let lowercase = decoded.to_ascii_lowercase();
    let needle = format!("{}=", wanted.to_ascii_lowercase());
    let start = lowercase.find(&needle)? + needle.len();
    let rest = &decoded[start..];
    let end = rest
        .find(|ch: char| matches!(ch, '&' | '"' | '\'' | '<' | '>' | ';') || ch.is_whitespace())
        .unwrap_or(rest.len());
    let id = &rest[..end];
    (!id.is_empty()).then(|| percent_decode(id))
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2])) {
                output.push(high * 16 + low);
                index += 3;
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn response_summary(
    endpoint: &str,
    status: StatusCode,
    content_type: &str,
    body: &str,
    interfaces: usize,
) -> String {
    let preview = sanitized_preview(body, 512);
    format!(
        "{endpoint}: HTTP {status}, content-type={content_type}, bytes={}, parsed_interfaces={interfaces}, preview={preview:?}",
        body.len()
    )
}

fn sanitized_preview(body: &str, limit: usize) -> String {
    let mut preview = clean_text(body, limit.saturating_mul(2));
    preview = redact_parameter(&preview, "sid");
    preview = redact_xml_tag(&preview, "SID");
    preview = redact_hex_session_tokens(&preview);
    preview.chars().take(limit).collect()
}

fn sanitized_error(error: &reqwest::Error) -> String {
    redact_hex_session_tokens(&redact_parameter(&error.to_string(), "sid"))
}

fn redact_hex_session_tokens(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < chars.len() {
        let mut end = index;
        while end < chars.len() && chars[end].is_ascii_hexdigit() {
            end += 1;
        }
        if end - index == 16 {
            output.push_str("[REDACTED]");
        } else {
            output.extend(chars[index..end].iter());
        }
        if end == index {
            output.push(chars[index]);
            index += 1;
        } else {
            index = end;
        }
    }
    output
}

fn redact_parameter(text: &str, name: &str) -> String {
    let mut output = text.to_owned();
    let needle = format!("{}=", name.to_ascii_lowercase());
    let mut search_from = 0;
    loop {
        let lowercase = output.to_ascii_lowercase();
        let Some(relative) = lowercase[search_from..].find(&needle) else {
            break;
        };
        let start = search_from + relative + needle.len();
        let end = output[start..]
            .find(['&', '"', '\'', '<', '>', ' '])
            .map(|length| start + length)
            .unwrap_or(output.len());
        output.replace_range(start..end, "[REDACTED]");
        search_from = start + "[REDACTED]".len();
        if search_from >= output.len() {
            break;
        }
    }
    output
}

fn redact_xml_tag(text: &str, tag: &str) -> String {
    let Some(start) = text.find(&format!("<{tag}>")) else {
        return text.to_owned();
    };
    let content = start + tag.len() + 2;
    let Some(relative_end) = text[content..].find(&format!("</{tag}>")) else {
        return text.to_owned();
    };
    let mut output = text.to_owned();
    output.replace_range(content..content + relative_end, "[REDACTED]");
    output
}

fn clean_text(text: &str, limit: usize) -> String {
    decode_html(text)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(limit)
        .collect()
}

fn decode_html(text: &str) -> String {
    text.replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&nbsp;", " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn fixture_server(
        responses: Vec<&'static str>,
    ) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4096];
                loop {
                    let count = stream.read(&mut buffer).await.unwrap();
                    if count == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..count]);
                    let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n")
                    else {
                        continue;
                    };
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(str::trim)
                                .map(str::to_owned)
                        })
                        .and_then(|value| value.parse::<usize>().ok())
                        .unwrap_or(0);
                    if request.len() >= header_end + 4 + content_length {
                        break;
                    }
                }
                requests.push(String::from_utf8_lossy(&request).into_owned());
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
            requests
        });
        (format!("http://{address}"), task)
    }

    #[test]
    fn address_rejects_credentials_and_paths() {
        assert!(FritzBoxClient::new(
            "http://u:p@fritz.box/evil",
            Duration::from_secs(1),
            Duration::from_secs(1)
        )
        .is_err())
    }

    #[test]
    fn parses_data_lua_start_buttons_and_categories() {
        let found = parse_interfaces(
            r#"<h3>WLAN</h3><table><tr><th>AP (5 GHz, ath1) - Interface 1</th>
               <td><button type='submit' name='start' id='uiStart_138' value='4-138'>Start</button></td></tr>
               <tr><th>Management traffic</th><td><button disabled value='4-128' name='start'>Start</button></td></tr></table>"#,
        );
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].id, "4-138");
        assert_eq!(found[0].display_name, "AP (5 GHz, ath1) - Interface 1");
        assert_eq!(found[0].category, "WLAN");
        assert!(found[0].available);
        assert!(!found[1].available);
    }

    #[test]
    fn parses_capture_links_without_fixed_interface_names() {
        let found = parse_interfaces(
            r#"<a href='/cgi-bin/capture_notimeout?capture=Start&amp;snaplen=1600&amp;ifaceorminor=7%2Dopaque'>Capture uplink</a>"#,
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "7-opaque");
    }

    #[test]
    fn parses_json_wrapped_markup_and_structured_variant() {
        let found = parse_interfaces(
            r#"{"data":{"html":"<tr><th>LAN bridge</th><td><button name=\"start\" value=\"1-lan\">Start</button></td></tr>","interfaces":[{"interfaceId":"2-0","displayName":"Internet","group":"WAN","disabled":false}]}}"#,
        );
        assert_eq!(found.len(), 2);
        assert!(found.iter().any(|item| item.id == "1-lan"));
        assert!(found
            .iter()
            .any(|item| item.id == "2-0" && item.category == "WAN"));
    }

    #[test]
    fn retains_legacy_capture_input_variant() {
        let found = parse_interfaces(
            r#"<input value=lan name=capture> LAN <input name='capture' disabled value='wifi'> Wi-Fi"#,
        );
        assert_eq!(found.len(), 2);
        assert!(found[0].available);
        assert!(!found[1].available);
    }

    #[test]
    fn diagnostics_redact_session_ids() {
        let preview = sanitized_preview(
            r#"<a href='capture.lua?sid=0123456789abcdef'>x</a><SID>fedcba9876543210</SID>"#,
            512,
        );
        assert!(!preview.contains("0123456789abcdef"));
        assert!(!preview.contains("fedcba9876543210"));
        assert!(preview.contains("[REDACTED]"));
    }

    #[test]
    fn malformed_session_xml() {
        assert_eq!(tag("<SID>x", "SID"), None)
    }

    #[test]
    fn classify_flags_html_content_type_before_inspecting_bytes() {
        let reason = classify_non_pcap("text/html; charset=utf-8", b"whatever");
        assert!(reason.contains("HTML"), "{reason}");
    }

    #[test]
    fn classify_flags_html_like_bodies_with_generic_content_type() {
        let reason = classify_non_pcap(
            "application/octet-stream",
            b"<!DOCTYPE html><html><body>login</body></html>",
        );
        assert!(reason.contains("HTML/XML"), "{reason}");
    }

    #[test]
    fn classify_reports_unexpected_magic_bytes() {
        let reason = classify_non_pcap("application/octet-stream", &[0, 1, 2, 3]);
        assert!(reason.contains("unexpected magic bytes"), "{reason}");
    }

    #[test]
    fn preview_bounds_to_64_bytes_and_masks_non_printable() {
        let bytes: Vec<u8> = (0u8..100).collect();
        let preview = preview_stream_bytes(&bytes);
        assert!(preview.starts_with("64 bytes:"));
        assert!(preview.contains(".")); // control bytes rendered as '.'
    }

    #[tokio::test]
    async fn describe_capture_response_redacts_sid_and_reports_content_type() {
        let body = "<html><body>login required</body></html>";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let response: &'static str = Box::leak(response.into_boxed_str());
        let (address, server) = fixture_server(vec![response]).await;
        let client =
            FritzBoxClient::new(&address, Duration::from_secs(1), Duration::from_secs(1)).unwrap();
        let session = FritzBoxSession {
            client: &client,
            sid: "0123456789abcdef".into(),
        };
        let interface = CaptureInterface {
            id: "4-138".into(),
            display_name: "opaque".into(),
            category: "router".into(),
            available: true,
        };

        let response = session.start_capture(&interface, 1600).await.unwrap();
        let diagnostic = describe_capture_response(&response);
        assert_eq!(diagnostic.status, StatusCode::OK);
        assert_eq!(diagnostic.content_type, "text/html");
        assert!(!diagnostic.url.contains("0123456789abcdef"));
        assert!(diagnostic.url.contains("[REDACTED]"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn discovery_uses_data_lua_cap_response() {
        let body = r#"<h3>LAN</h3><tr><th>LAN bridge</th><td><button name="start" value="1-lan">Start</button></td></tr>"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let response: &'static str = Box::leak(response.into_boxed_str());
        let (address, server) = fixture_server(vec![response]).await;
        let client =
            FritzBoxClient::new(&address, Duration::from_secs(1), Duration::from_secs(1)).unwrap();
        let session = FritzBoxSession {
            client: &client,
            sid: "0123456789abcdef".into(),
        };

        let found = session.capture_interfaces().await.unwrap();
        assert_eq!(found[0].id, "1-lan");
        let requests = server.await.unwrap();
        assert!(requests[0].starts_with("POST /data.lua HTTP/1.1"));
        assert!(requests[0].contains("page=cap"));
        assert!(requests[0].contains("sid=0123456789abcdef"));
    }

    #[tokio::test]
    async fn discovery_falls_back_to_standalone_capture_page() {
        let body =
            r#"<tr><th>WAN</th><td><button name="start" value="2-0">Start</button></td></tr>"#;
        let second = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let second: &'static str = Box::leak(second.into_boxed_str());
        let (address, server) = fixture_server(vec![
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"data\":{}}",
            second,
        ])
        .await;
        let client =
            FritzBoxClient::new(&address, Duration::from_secs(1), Duration::from_secs(1)).unwrap();
        let session = FritzBoxSession {
            client: &client,
            sid: "0123456789abcdef".into(),
        };

        let found = session.capture_interfaces().await.unwrap();
        assert_eq!(found[0].id, "2-0");
        let requests = server.await.unwrap();
        assert!(requests[0].starts_with("POST /data.lua HTTP/1.1"));
        assert!(requests[1].starts_with("GET /capture.lua?sid="));
    }

    #[tokio::test]
    async fn capture_cgi_uses_ifaceorminor_and_start_action() {
        let (address, server) = fixture_server(vec![
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ])
        .await;
        let client =
            FritzBoxClient::new(&address, Duration::from_secs(1), Duration::from_secs(1)).unwrap();
        let session = FritzBoxSession {
            client: &client,
            sid: "0123456789abcdef".into(),
        };
        let interface = CaptureInterface {
            id: "4-138".into(),
            display_name: "opaque".into(),
            category: "router".into(),
            available: true,
        };

        session.start_capture(&interface, 1600).await.unwrap();
        let requests = server.await.unwrap();
        assert!(requests[0].starts_with("GET /cgi-bin/capture_notimeout?"));
        assert!(requests[0].contains("ifaceorminor=4-138"));
        assert!(requests[0].contains("capture=Start"));
        assert!(!requests[0].contains("capture=4-138"));
    }
}
