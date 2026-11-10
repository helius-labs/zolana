//! Prover URLs, and keeping a gateway `api-key` out of printed ones.

#[cfg(feature = "reqwest")]
use std::borrow::Cow;

use spr_api::redact_api_key;
use url::{Host, Url};

use crate::{
    error::ClientError,
    prover::{tee::ATTESTATION_PATH, ExpectedProvingKey},
};

/// A prover base URL. Request paths go before its query, so every query
/// parameter, a gateway `api-key` among them, rides on every request.
#[derive(Clone)]
pub(crate) struct ProverEndpoint {
    /// `None` for an unparseable URL, which fails on the first request rather
    /// than at construction: callers build placeholder clients they never use.
    base: Option<Url>,
}

impl ProverEndpoint {
    pub(crate) fn parse(url: &str) -> Self {
        Self {
            base: Url::parse(url).ok(),
        }
    }

    /// Whether the prover runs on this machine, where its requests never leave
    /// the host.
    pub(crate) fn is_loopback(&self) -> bool {
        self.base.as_ref().is_some_and(|url| match url.host() {
            Some(Host::Domain(host)) => {
                let host = host.trim_end_matches('.');
                host == "localhost" || host.ends_with(".localhost")
            }
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        })
    }

    /// `path` is slash-separated segments, such as `/prove/merge_24_1`.
    pub(crate) fn url(&self, path: &str) -> Result<Url, ClientError> {
        let invalid = || ClientError::Prover("invalid prover URL".into());
        let mut url = self.base.clone().ok_or_else(invalid)?;
        url.path_segments_mut()
            .map_err(|()| invalid())?
            .pop_if_empty()
            .extend(path.split('/').filter(|segment| !segment.is_empty()));
        Ok(url)
    }

    /// Where a queued proof of `key` is polled, so the poll reaches the pool
    /// that queued it.
    pub(crate) fn status_url(
        &self,
        key: &ExpectedProvingKey,
        job_id: &str,
    ) -> Result<Url, ClientError> {
        let path = key.prove_path();
        let mut url = self.url(&format!("{path}/status"))?;
        url.query_pairs_mut().append_pair("jobId", job_id);
        Ok(url)
    }

    /// Where the prover quotes `nonce`.
    pub(crate) fn attestation_url(&self, nonce: &[u8]) -> Result<Url, ClientError> {
        let mut url = self.url(ATTESTATION_PATH)?;
        url.query_pairs_mut()
            .append_pair("nonce", &hex::encode(nonce));
        Ok(url)
    }

    /// What an encrypted call to `url` binds: its path below this base, then
    /// its query, so a proxy can serve the prover under any path.
    pub(crate) fn route(&self, url: &Url) -> String {
        let base = self
            .base
            .as_ref()
            .map_or("", |base| base.path().trim_end_matches('/'));
        let path = url.path().strip_prefix(base).unwrap_or(url.path());
        match url.query() {
            Some(query) => format!("{path}?{query}"),
            None => path.to_owned(),
        }
    }

    pub(crate) fn redacted(&self) -> String {
        self.base.as_ref().map_or_else(
            || "invalid URL".to_owned(),
            |url| redact_api_key(url.as_str()).into_owned(),
        )
    }
}

/// Mask the `api-key` in the URL reqwest puts in its error text, which reaches
/// CLI output and service logs. The host and path stay, to say what failed.
#[cfg(feature = "reqwest")]
pub(crate) fn scrub(mut error: reqwest::Error) -> reqwest::Error {
    if let Some(url) = error.url_mut() {
        redact_in_place(url);
    }
    error
}

/// Masks the `api-key` value in place with [`redact_api_key`]. A URL that would
/// not parse once masked, which masking a query value cannot produce, loses its
/// whole query instead.
#[cfg(feature = "reqwest")]
fn redact_in_place(url: &mut Url) {
    if let Cow::Owned(redacted) = redact_api_key(url.as_str()) {
        match Url::parse(&redacted) {
            Ok(redacted) => *url = redacted,
            Err(_) => url.set_query(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::{PROVE_PATH, PROVING_KEYS_PATH};

    fn url(base: &str, path: &str) -> String {
        ProverEndpoint::parse(base).url(path).unwrap().into()
    }

    #[test]
    fn plaintext_proving_is_local_only() {
        for url in [
            "http://localhost:3001",
            "https://node.localhost:3001",
            "http://127.0.0.2:3001",
            "http://[::1]:3001",
        ] {
            assert!(ProverEndpoint::parse(url).is_loopback(), "{url}");
        }
        for url in [
            "https://prover.example",
            "https://localhost.example",
            "http://10.0.0.1:3001",
            "not a url",
        ] {
            assert!(!ProverEndpoint::parse(url).is_loopback(), "{url}");
        }
    }

    #[test]
    fn request_paths_go_before_the_query() {
        assert_eq!(
            url("http://127.0.0.1:3001", PROVE_PATH),
            "http://127.0.0.1:3001/prove"
        );
        assert_eq!(
            url("https://gateway.invalid/v1/spr?api-key=k", PROVE_PATH),
            "https://gateway.invalid/v1/spr/prove?api-key=k"
        );
        assert_eq!(
            url(
                "https://gateway.invalid/v1/spr/?api-key=k",
                PROVING_KEYS_PATH
            ),
            "https://gateway.invalid/v1/spr/proving-keys?api-key=k"
        );
        // Every parameter stays, not just the key.
        assert_eq!(
            url("https://gateway.invalid/v1/spr?a=1&api-key=k", PROVE_PATH),
            "https://gateway.invalid/v1/spr/prove?a=1&api-key=k"
        );
        assert_eq!(
            url("https://prover.invalid?token=x", PROVE_PATH),
            "https://prover.invalid/prove?token=x"
        );
    }

    #[test]
    fn the_job_id_is_encoded_and_the_key_kept() {
        let endpoint = ProverEndpoint::parse("https://gateway.invalid/zolana?api-key=k");
        let key = ExpectedProvingKey {
            name: "merge_52_1.key".to_string(),
            sha256: [0; 32],
        };
        assert_eq!(
            String::from(endpoint.status_url(&key, "job-1").unwrap()),
            "https://gateway.invalid/zolana/prove/merge_52_1/status?api-key=k&jobId=job-1"
        );
        // The gateway hostname does not change the key-specific poll route.
        let helius = ProverEndpoint::parse("https://beta-devnet.helius-rpc.com/v1/spr?api-key=k");
        assert_eq!(
            String::from(helius.status_url(&key, "job-1").unwrap()),
            "https://beta-devnet.helius-rpc.com/v1/spr/prove/merge_52_1/status?api-key=k&jobId=job-1"
        );
        let other = ProverEndpoint::parse("https://gateway.invalid/v1/spr?api-key=k");
        assert_eq!(
            String::from(other.status_url(&key, "job-1").unwrap()),
            "https://gateway.invalid/v1/spr/prove/merge_52_1/status?api-key=k&jobId=job-1"
        );
        // A `#` from the server must not push the key into a fragment.
        let url = endpoint.status_url(&key, "a#b&c").unwrap();
        assert_eq!(url.query(), Some("api-key=k&jobId=a%23b%26c"));
        assert_eq!(url.fragment(), None);
    }

    #[test]
    fn an_unparseable_url_fails_on_use() {
        for base in ["", "not a url", "mailto:prover@example.com"] {
            assert!(
                ProverEndpoint::parse(base).url(PROVE_PATH).is_err(),
                "{base}"
            );
        }
    }

    #[test]
    fn the_printed_endpoint_masks_only_the_key_value() {
        assert_eq!(
            ProverEndpoint::parse("https://gateway.invalid/v1/spr?a=%20x&api-key=secret&b=2")
                .redacted(),
            "https://gateway.invalid/v1/spr?a=%20x&api-key=redacted&b=2"
        );
        assert_eq!(
            ProverEndpoint::parse("http://127.0.0.1:3001").redacted(),
            "http://127.0.0.1:3001/"
        );
        assert_eq!(
            ProverEndpoint::parse("not a url ?api-key=secret").redacted(),
            "invalid URL"
        );
    }
}
