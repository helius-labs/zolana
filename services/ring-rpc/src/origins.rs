use std::net::IpAddr;

use hyper::header::HeaderValue;
use thiserror::Error;

/// ASCII serialized origins, the form a browser sends.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Origins {
    allowed: Vec<String>,
    relying_party_id: Option<String>,
    any: bool,
}

#[must_use]
pub struct OriginPolicy {
    origins: Vec<String>,
    relying_party_id: Option<String>,
    transport: OriginTransport,
}

/// Plain HTTP outside loopback exposes the decrypted audit data, test deployments only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginTransport {
    SecureOnly,
    InsecureHttp,
}

#[derive(Debug, Error)]
pub enum OriginError {
    #[error("browser origin is invalid")]
    InvalidOrigin,
    #[error("browser origin needs HTTPS outside loopback")]
    InsecureOrigin,
    #[error("WebAuthn RP ID is required for browser origins")]
    MissingRelyingParty,
    #[error("WebAuthn RP ID does not cover every browser origin")]
    RelyingPartyMismatch,
    #[error("browser origin cannot become an HTTP header")]
    Header,
}

impl OriginPolicy {
    pub fn new(origins: Vec<String>) -> Self {
        Self {
            origins,
            relying_party_id: None,
            transport: OriginTransport::SecureOnly,
        }
    }

    #[must_use = "use the updated policy"]
    pub fn with_relying_party_id(mut self, relying_party_id: String) -> Self {
        self.relying_party_id = Some(relying_party_id);
        self
    }

    #[must_use = "use the updated policy"]
    pub fn with_transport(mut self, transport: OriginTransport) -> Self {
        self.transport = transport;
        self
    }

    pub fn build(self) -> Result<Origins, OriginError> {
        let transport = self.transport;
        // `*` opens CORS to every page, only the insecure test transport may ask for it.
        if self.origins.iter().any(|origin| origin == "*") {
            if transport != OriginTransport::InsecureHttp || self.origins.len() != 1 {
                return Err(OriginError::InvalidOrigin);
            }
            return Ok(Origins {
                any: true,
                ..Origins::default()
            });
        }
        let parsed = self
            .origins
            .iter()
            .map(|origin| parse_origin(origin, transport))
            .collect::<Result<Vec<_>, _>>()?;
        if parsed.is_empty() {
            return Ok(Origins::default());
        }
        let relying_party_id = self
            .relying_party_id
            .filter(|value| valid_relying_party_id(value))
            .ok_or(OriginError::MissingRelyingParty)?;
        let covered = |host: &str| {
            host == relying_party_id
                || (!exact_host(&relying_party_id)
                    && host.ends_with(&format!(".{relying_party_id}")))
        };
        if !parsed.iter().all(|origin| covered(&origin.host)) {
            return Err(OriginError::RelyingPartyMismatch);
        }
        Ok(Origins {
            allowed: parsed.into_iter().map(|origin| origin.serialized).collect(),
            relying_party_id: Some(relying_party_id),
            any: false,
        })
    }
}

impl Origins {
    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty() && !self.any
    }

    pub fn allows_any(&self) -> bool {
        self.any
    }

    pub fn allows(&self, origin: &str) -> bool {
        self.allowed.iter().any(|allowed| allowed == origin)
    }

    pub fn relying_party_id(&self) -> Option<&str> {
        self.relying_party_id.as_deref()
    }

    pub fn header_values(&self) -> Result<Vec<HeaderValue>, OriginError> {
        self.allowed
            .iter()
            .map(|origin| origin.parse().map_err(|_| OriginError::Header))
            .collect()
    }
}

struct AllowedOrigin {
    serialized: String,
    host: String,
}

fn parse_origin(value: &str, transport: OriginTransport) -> Result<AllowedOrigin, OriginError> {
    let url = reqwest::Url::parse(value).map_err(|_| OriginError::InvalidOrigin)?;
    if url.cannot_be_a_base()
        || url.username() != ""
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(OriginError::InvalidOrigin);
    }
    let host = url
        .host_str()
        .ok_or(OriginError::InvalidOrigin)?
        .trim_matches(['[', ']'])
        .to_owned();
    let loopback = host == "localhost"
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    let plain_allowed = loopback || transport == OriginTransport::InsecureHttp;
    if url.scheme() != "https" && !(url.scheme() == "http" && plain_allowed) {
        return Err(OriginError::InsecureOrigin);
    }
    Ok(AllowedOrigin {
        serialized: url.origin().ascii_serialization(),
        host,
    })
}

/// Hosts a relying party ID covers only when equal, never through a subdomain.
fn exact_host(value: &str) -> bool {
    value == "localhost" || value.parse::<IpAddr>().is_ok()
}

fn valid_relying_party_id(value: &str) -> bool {
    exact_host(value)
        || (!value.is_empty()
            && !value.contains(['/', ':'])
            && psl::domain_str(value).is_some()
            && psl::suffix_str(value) != Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_accepts_parent_domains_ports_and_ipv6_loopback() {
        let origins = OriginPolicy::new(vec![
            "https://app.example.com:8443".to_owned(),
            "https://audit.example.com".to_owned(),
        ])
        .with_relying_party_id("example.com".to_owned())
        .build()
        .expect("parent domain");
        assert!(origins.allows("https://app.example.com:8443"));
        assert_eq!(origins.relying_party_id(), Some("example.com"));

        let loopback = OriginPolicy::new(vec!["http://[::1]:3000".to_owned()])
            .with_relying_party_id("::1".to_owned())
            .build();
        assert!(loopback.is_ok());
    }

    #[test]
    fn any_origin_needs_the_insecure_transport() {
        assert!(OriginPolicy::new(vec!["*".to_owned()]).build().is_err());
        let origins = OriginPolicy::new(vec!["*".to_owned()])
            .with_transport(OriginTransport::InsecureHttp)
            .build()
            .expect("any origin under the insecure transport");
        assert!(origins.allows_any() && !origins.is_empty());
        assert!(
            OriginPolicy::new(vec!["*".to_owned(), "https://a.example".to_owned()])
                .with_transport(OriginTransport::InsecureHttp)
                .build()
                .is_err()
        );
    }

    #[test]
    fn insecure_transport_accepts_plain_http_origins() {
        let origins = OriginPolicy::new(vec!["http://auditor.example.com".to_owned()])
            .with_relying_party_id("auditor.example.com".to_owned())
            .with_transport(OriginTransport::InsecureHttp)
            .build()
            .expect("plain origin under the insecure transport");
        assert!(origins.allows("http://auditor.example.com"));
    }

    #[test]
    fn policy_rejects_malformed_insecure_and_uncovered_origins() {
        for origin in [
            "not an origin",
            "http://example.com",
            "https://example.com/path",
            "https://user@example.com",
        ] {
            assert!(OriginPolicy::new(vec![origin.to_owned()])
                .with_relying_party_id("example.com".to_owned())
                .build()
                .is_err());
        }
        assert!(matches!(
            OriginPolicy::new(vec!["https://app.example.com".to_owned()])
                .with_relying_party_id("other.example".to_owned())
                .build(),
            Err(OriginError::RelyingPartyMismatch)
        ));
        assert!(matches!(
            OriginPolicy::new(vec!["https://app.example.com".to_owned()])
                .with_relying_party_id("com".to_owned())
                .build(),
            Err(OriginError::MissingRelyingParty)
        ));
    }
}
