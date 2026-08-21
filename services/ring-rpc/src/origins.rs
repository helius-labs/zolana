use hyper::header::HeaderValue;
use thiserror::Error;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Origins {
    allowed: Vec<AllowedOrigin>,
    relying_party_id: Option<String>,
}

#[must_use]
pub struct OriginPolicy {
    origins: Vec<String>,
    relying_party_id: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct AllowedOrigin {
    serialized: String,
    host: String,
}

impl OriginPolicy {
    pub fn new(origins: Vec<String>) -> Self {
        Self {
            origins,
            relying_party_id: None,
        }
    }

    #[must_use = "use the updated policy"]
    pub fn with_relying_party_id(mut self, relying_party_id: String) -> Self {
        self.relying_party_id = Some(relying_party_id);
        self
    }

    pub fn build(self) -> Result<Origins, OriginError> {
        let allowed = self
            .origins
            .into_iter()
            .map(parse_origin)
            .collect::<Result<Vec<_>, _>>()?;
        if allowed.is_empty() {
            return Ok(Origins::default());
        }
        let relying_party_id = self
            .relying_party_id
            .filter(|value| valid_relying_party_id(value))
            .ok_or(OriginError::MissingRelyingParty)?;
        if allowed
            .iter()
            .any(|origin| !rp_covers_host(&relying_party_id, &origin.host))
        {
            return Err(OriginError::RelyingPartyMismatch);
        }
        Ok(Origins {
            allowed,
            relying_party_id: Some(relying_party_id),
        })
    }
}

impl Origins {
    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }

    pub fn allows(&self, origin: &str) -> bool {
        self.allowed
            .iter()
            .any(|allowed| allowed.serialized == origin)
    }

    pub fn relying_party_id(&self) -> Option<&str> {
        self.relying_party_id.as_deref()
    }

    pub fn header_values(&self) -> Result<Vec<HeaderValue>, OriginError> {
        self.allowed
            .iter()
            .map(|origin| origin.serialized.parse().map_err(|_| OriginError::Header))
            .collect()
    }
}

fn parse_origin(value: String) -> Result<AllowedOrigin, OriginError> {
    let url = reqwest::Url::parse(&value).map_err(|_| OriginError::InvalidOrigin)?;
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
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(OriginError::InsecureOrigin);
    }
    Ok(AllowedOrigin {
        serialized: url.origin().ascii_serialization(),
        host,
    })
}

fn valid_relying_party_id(value: &str) -> bool {
    if value == "localhost" || value.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    !value.is_empty()
        && !value.contains(['/', ':'])
        && psl::domain_str(value).is_some()
        && psl::suffix_str(value) != Some(value)
}

fn rp_covers_host(relying_party_id: &str, host: &str) -> bool {
    if relying_party_id.parse::<std::net::IpAddr>().is_ok() || relying_party_id == "localhost" {
        host == relying_party_id
    } else {
        host == relying_party_id || host.ends_with(&format!(".{relying_party_id}"))
    }
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
