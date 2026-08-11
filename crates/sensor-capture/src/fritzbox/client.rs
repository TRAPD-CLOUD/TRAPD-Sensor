use super::{challenge_response, AuthError, CaptureInterface, Credentials};
use reqwest::{redirect::Policy, Url};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FritzBoxError {
    #[error("invalid FRITZ!Box address: only http(s), a host, and an optional port are allowed")]
    InvalidAddress,
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error("FRITZ!Box request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("FRITZ!Box returned an unexpected response")]
    UnexpectedResponse,
    #[error("configured capture interface is not advertised by this FRITZ!Box")]
    UnknownInterface,
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
            .redirect(Policy::none())
            .connect_timeout(connect_timeout)
            .timeout(read_timeout)
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
    /// Discovers IDs from the router capture page. Unknown markup produces an
    /// empty list, allowing setup to offer an explicit manual-ID escape hatch.
    pub async fn capture_interfaces(&self) -> Result<Vec<CaptureInterface>, FritzBoxError> {
        let url = self
            .client
            .base
            .join("html/capture.html")
            .map_err(|_| FritzBoxError::InvalidAddress)?;
        let text = self
            .client
            .http
            .get(url)
            .query(&[("sid", self.sid.as_str())])
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        Ok(parse_interfaces(&text))
    }
    pub async fn start_capture(
        &self,
        interface: &CaptureInterface,
    ) -> Result<reqwest::Response, FritzBoxError> {
        if !interface.available || interface.id.is_empty() {
            return Err(FritzBoxError::UnknownInterface);
        }
        let url = self
            .client
            .base
            .join("cgi-bin/capture_notimeout")
            .map_err(|_| FritzBoxError::InvalidAddress)?;
        let response = self
            .client
            .http
            .get(url)
            .query(&[
                ("sid", self.sid.as_str()),
                ("capture", interface.id.as_str()),
                ("snaplen", "1600"),
            ])
            .send()
            .await?;
        if response.status().is_redirection() {
            return Err(FritzBoxError::UnexpectedResponse);
        }
        Ok(response.error_for_status()?)
    }
}
fn tag<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let start = format!("<{name}>");
    let end = format!("</{name}>");
    let from = xml.find(&start)? + start.len();
    let to = xml[from..].find(&end)? + from;
    Some(xml[from..to].trim())
}
fn parse_interfaces(html: &str) -> Vec<CaptureInterface> {
    let mut out = Vec::new();
    for part in html.split("name=\"capture\"").skip(1) {
        let Some(v) = part.find("value=\"") else {
            continue;
        };
        let rest = &part[v + 7..];
        let Some(end) = rest.find('"') else { continue };
        let id = &rest[..end];
        if id.is_empty() || id.len() > 128 || out.iter().any(|x: &CaptureInterface| x.id == id) {
            continue;
        }
        let nearby = &rest[end..rest.len().min(end + 256)];
        let display = strip_tags(nearby)
            .trim()
            .trim_matches(|c: char| !c.is_alphanumeric())
            .chars()
            .take(128)
            .collect::<String>();
        out.push(CaptureInterface {
            id: id.into(),
            display_name: if display.is_empty() {
                id.into()
            } else {
                display
            },
            category: "router".into(),
            available: !nearby.contains("disabled"),
        })
    }
    out
}
fn strip_tags(s: &str) -> String {
    let mut inside = false;
    s.chars()
        .filter(|c| {
            if *c == '<' {
                inside = true;
                false
            } else if *c == '>' {
                inside = false;
                false
            } else {
                !inside
            }
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
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
    fn discovers_only_advertised_ids() {
        let x = parse_interfaces(
            r#"<input name="capture" value="lan"> LAN <input name="capture" value="wifi" disabled> Wi-Fi"#,
        );
        assert_eq!(x.len(), 2);
        assert!(x[0].available);
        assert!(!x[1].available)
    }
    #[test]
    fn malformed_session_xml() {
        assert_eq!(tag("<SID>x", "SID"), None)
    }
}
