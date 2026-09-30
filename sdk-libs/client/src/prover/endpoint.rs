//! Prover URLs, and keeping a gateway `api-key` out of printed ones.

use reqwest::Url;

use crate::error::ClientError;

const API_KEY: &str = "api-key";
const REDACTED: &str = "redacted";

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

    /// `path` is slash-separated segments, as in [`super::PROVE_PATH`].
    pub(crate) fn url(&self, path: &str) -> Result<Url, ClientError> {
        let invalid = || ClientError::Prover("invalid prover URL".into());
        let mut url = self.base.clone().ok_or_else(invalid)?;
        url.path_segments_mut()
            .map_err(|()| invalid())?
            .pop_if_empty()
            .extend(path.split('/').filter(|segment| !segment.is_empty()));
        Ok(url)
    }

    pub(crate) fn status_url(&self, job_id: &str) -> Result<Url, ClientError> {
        let mut url = self.url(&format!("{}/status", super::PROVE_PATH))?;
        url.query_pairs_mut().append_pair("jobId", job_id);
        Ok(url)
    }

    pub(crate) fn redacted(&self) -> String {
        redact_api_key(self.base.as_ref().map_or("", Url::as_str))
    }
}

/// Mask the `api-key` in the URL reqwest puts in its error text, which reaches
/// CLI output and service logs. The host and path stay, to say what failed.
pub(crate) fn scrub(mut error: reqwest::Error) -> reqwest::Error {
    if let Some(url) = error.url_mut() {
        redact_in_place(url);
    }
    error
}

/// `url` with any `api-key` query value masked, for printing. A URL without a
/// key comes back as given.
pub fn redact_api_key(url: &str) -> String {
    match Url::parse(url) {
        Ok(mut parsed) if has_api_key(&parsed) => {
            redact_in_place(&mut parsed);
            parsed.into()
        }
        Ok(_) => url.to_string(),
        Err(_) => "invalid URL".to_string(),
    }
}

fn is_api_key(pair: &str) -> bool {
    pair.split_once('=')
        .is_some_and(|(name, _)| name == API_KEY)
}

fn has_api_key(url: &Url) -> bool {
    url.query()
        .is_some_and(|query| query.split('&').any(is_api_key))
}

/// Rewrites only the key's value, so the other parameters keep their encoding.
fn redact_in_place(url: &mut Url) {
    if !has_api_key(url) {
        return;
    }
    let masked = url
        .query()
        .unwrap_or_default()
        .split('&')
        .map(|pair| {
            if is_api_key(pair) {
                format!("{API_KEY}={REDACTED}")
            } else {
                pair.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("&");
    url.set_query(Some(&masked));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::{PROVE_PATH, PROVING_KEYS_PATH};

    fn url(base: &str, path: &str) -> String {
        ProverEndpoint::parse(base).url(path).unwrap().into()
    }

    #[test]
    fn request_paths_go_before_the_query() {
        assert_eq!(
            url("http://127.0.0.1:3001", PROVE_PATH),
            "http://127.0.0.1:3001/prove"
        );
        assert_eq!(
            url("https://gateway.invalid/v1/zolana?api-key=k", PROVE_PATH),
            "https://gateway.invalid/v1/zolana/prove?api-key=k"
        );
        assert_eq!(
            url(
                "https://gateway.invalid/v1/zolana/?api-key=k",
                PROVING_KEYS_PATH
            ),
            "https://gateway.invalid/v1/zolana/proving-keys?api-key=k"
        );
        // Every parameter stays, not just the key.
        assert_eq!(
            url(
                "https://gateway.invalid/v1/zolana?a=1&api-key=k",
                PROVE_PATH
            ),
            "https://gateway.invalid/v1/zolana/prove?a=1&api-key=k"
        );
        assert_eq!(
            url("https://prover.invalid?token=x", PROVE_PATH),
            "https://prover.invalid/prove?token=x"
        );
    }

    #[test]
    fn the_job_id_is_encoded_and_the_key_kept() {
        let endpoint = ProverEndpoint::parse("https://gateway.invalid/v1/zolana?api-key=k");
        assert_eq!(
            String::from(endpoint.status_url("job-1").unwrap()),
            "https://gateway.invalid/v1/zolana/prove/status?api-key=k&jobId=job-1"
        );
        // A `#` from the server must not push the key into a fragment.
        let url = endpoint.status_url("a#b&c").unwrap();
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
    fn only_the_key_value_is_masked() {
        assert_eq!(
            redact_api_key("https://gateway.invalid/v1/zolana?a=%20x&api-key=secret&b=2"),
            "https://gateway.invalid/v1/zolana?a=%20x&api-key=redacted&b=2"
        );
        assert_eq!(
            redact_api_key("http://127.0.0.1:3001"),
            "http://127.0.0.1:3001"
        );
        assert_eq!(
            redact_api_key("https://prover.invalid/?api-keys=not-the-key"),
            "https://prover.invalid/?api-keys=not-the-key"
        );
        assert_eq!(redact_api_key("not a url ?api-key=secret"), "invalid URL");
    }
}
