//! One prover HTTP exchange, shared by the blocking and async clients and
//! encrypted to the attested key when the client requires a TEE.

use std::{mem, time::Duration};

use http::{
    header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE},
    Method, StatusCode,
};
use spr_api::{ApiError, HttpRequest};
use url::Url;
use zeroize::Zeroizing;

#[cfg(feature = "reqwest")]
use crate::prover::endpoint::scrub;
use crate::{
    error::ClientError,
    prover::{
        client::Delivery,
        endpoint::ProverEndpoint,
        tee::{
            EncryptedRequest, TeeSession, HEADER_CIPHERTEXT, HEADER_ENC, HEADER_VERSION, VERSION,
        },
    },
};

pub(crate) struct Call<'a> {
    pub method: Method,
    pub url: &'a Url,
    pub body: Option<&'a str>,
    pub delivery: Option<Delivery>,
    pub timeout: Option<Duration>,
}

/// Where an exchange stopped, so each caller keeps its own retry rules.
pub(crate) enum CallError {
    /// No response arrived.
    Connect(ApiError),
    /// The status arrived and the body was lost: the prover may have acted
    /// on the request.
    Read(ApiError),
    Refused(ClientError),
}

#[derive(Clone, Copy)]
pub(crate) struct Recipient<'s> {
    pub session: &'s TeeSession,
    pub key: [u8; 32],
}

/// A call as sent, keeping the key that decrypts its answer.
pub(crate) struct Prepared<'s> {
    pub headers: HeaderMap,
    pub body: Option<Zeroizing<Vec<u8>>>,
    encrypted: Option<Encrypted<'s>>,
}

struct Encrypted<'s> {
    recipient: Recipient<'s>,
    request: EncryptedRequest,
}

pub(crate) enum Answer<'s> {
    Done(StatusCode, String),
    KeyLost {
        recipient: Recipient<'s>,
        status: StatusCode,
        body: String,
    },
}

impl<'a> Call<'a> {
    pub fn get(url: &'a Url, timeout: Duration) -> Self {
        Self {
            method: Method::GET,
            url,
            body: None,
            delivery: None,
            timeout: Some(timeout),
        }
    }

    pub fn post(url: &'a Url, body: &'a str, delivery: Delivery, timeout: Duration) -> Self {
        Self {
            method: Method::POST,
            url,
            body: Some(body),
            delivery: Some(delivery),
            timeout: Some(timeout),
        }
    }

    /// `recipient` is set exactly when the client requires a TEE, and
    /// `endpoint` is the base `url` was built on.
    pub fn prepare<'s>(
        &self,
        recipient: Option<Recipient<'s>>,
        endpoint: &ProverEndpoint,
    ) -> Result<Prepared<'s>, CallError> {
        let mut headers = HeaderMap::new();
        match self.delivery {
            Some(Delivery::InResponse) => insert(&mut headers, "X-Sync", "true")?,
            Some(Delivery::Queued) => insert(&mut headers, "X-Async", "true")?,
            None => {}
        }
        let Some(recipient) = recipient else {
            if self.body.is_some() {
                insert(&mut headers, CONTENT_TYPE.as_str(), "application/json")?;
            }
            return Ok(Prepared {
                headers,
                body: self
                    .body
                    .map(|body| Zeroizing::new(body.as_bytes().to_vec())),
                encrypted: None,
            });
        };
        recipient
            .session
            .check_policy_time()
            .map_err(CallError::Refused)?;
        let encrypted = TeeSession::encrypt(
            &recipient.key,
            self.method.as_str(),
            &endpoint.route(self.url),
            self.body.unwrap_or_default().as_bytes(),
        )
        .map_err(CallError::Refused)?;
        insert(&mut headers, HEADER_VERSION, VERSION)?;
        insert(&mut headers, HEADER_ENC, &encrypted.enc)?;
        let body = if self.method == Method::GET {
            insert(
                &mut headers,
                HEADER_CIPHERTEXT,
                hex::encode(&encrypted.body),
            )?;
            None
        } else {
            insert(
                &mut headers,
                CONTENT_TYPE.as_str(),
                "application/octet-stream",
            )?;
            Some(Zeroizing::new(encrypted.body.clone()))
        };
        Ok(Prepared {
            headers,
            body,
            encrypted: Some(Encrypted {
                recipient,
                request: encrypted,
            }),
        })
    }
}

impl<'s> Prepared<'s> {
    /// The request to send; it takes the prepared headers and body.
    pub fn request(&mut self, call: &Call<'_>) -> HttpRequest {
        let mut request = HttpRequest::new(call.method.clone(), call.url.as_str());
        request.headers = mem::take(&mut self.headers);
        request.body = self.body.take().unwrap_or_default();
        request.timeout = call.timeout;
        request
    }

    pub fn finish(
        &self,
        status: StatusCode,
        is_encrypted: bool,
        body: &[u8],
    ) -> Result<Answer<'s>, CallError> {
        let plain = || String::from_utf8_lossy(body).into_owned();
        let Some(Encrypted { recipient, request }) = &self.encrypted else {
            return Ok(Answer::Done(status, plain()));
        };
        if !is_encrypted && recipient.session.lost_key(&recipient.key, status, body) {
            return Ok(Answer::KeyLost {
                recipient: *recipient,
                status,
                body: plain(),
            });
        }
        TeeSession::decrypt(request, status, is_encrypted, body)
            .map(|(status, body)| Answer::Done(status, body))
            .map_err(CallError::Refused)
    }
}

fn insert(
    headers: &mut HeaderMap,
    name: &'static str,
    value: impl AsRef<str>,
) -> Result<(), CallError> {
    let name = HeaderName::from_bytes(name.as_bytes());
    let value = HeaderValue::from_str(value.as_ref());
    let (Ok(name), Ok(value)) = (name, value) else {
        return Err(CallError::Refused(ClientError::Prover(
            "invalid prover request header".into(),
        )));
    };
    headers.insert(name, value);
    Ok(())
}

impl Answer<'_> {
    pub fn into_parts(self) -> (StatusCode, String) {
        match self {
            Self::Done(status, body) | Self::KeyLost { status, body, .. } => (status, body),
        }
    }
}

impl Recipient<'_> {
    pub fn forget(&self) {
        self.session.forget(&self.key);
    }
}

impl CallError {
    pub fn transport(error: ApiError) -> Self {
        match error {
            ApiError::ResponseLost(_) => Self::Read(error),
            error => Self::Connect(error),
        }
    }

    /// `label` names the call in a transport failure.
    pub fn into_client_error(self, label: &str) -> ClientError {
        match self {
            Self::Connect(e) => {
                ClientError::ProverServer(format!("{label} failed: {}", transport_error(e)))
            }
            Self::Read(e) => ClientError::ProverServer(e.to_string()),
            Self::Refused(error) => error,
        }
    }
}

/// The failure's text, `api-key` masked: a `reqwest` error through `scrub`,
/// which keeps its own wording, and any other through `ApiError`'s display.
pub(crate) fn transport_error(error: ApiError) -> String {
    match error {
        #[cfg(feature = "reqwest")]
        ApiError::Request(error) => scrub(error).to_string(),
        error => error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spr_prover_tee::FixtureProver;

    use crate::prover::tee::{FixtureSession, NitroFixture, TeePolicy};

    fn session() -> TeeSession {
        TeeSession::new(
            TeePolicy::from_json(include_str!(
                "../../../../prover/tee/testdata/probe_policy.json"
            ))
            .unwrap(),
        )
    }

    fn encrypted<'s>(session: &'s TeeSession, call: &Call<'_>) -> Prepared<'s> {
        call.prepare(
            Some(Recipient {
                session,
                key: [9; 32],
            }),
            &ProverEndpoint::parse("https://prover.example"),
        )
        .ok()
        .unwrap()
    }

    fn rejected(code: &str) -> Vec<u8> {
        format!(r#"{{"code":"{code}","message":"encrypted request rejected"}}"#).into_bytes()
    }

    fn re_attests(session: &TeeSession, code: &str) -> bool {
        let url = Url::parse("https://prover.example/proving-keys").unwrap();
        let prepared = encrypted(session, &Call::get(&url, Duration::from_secs(1)));
        let answer = prepared
            .finish(StatusCode::BAD_REQUEST, false, &rejected(code))
            .ok()
            .unwrap();
        matches!(answer, Answer::KeyLost { .. })
    }

    #[test]
    fn only_a_rotating_platform_re_attests_on_decryption_failure() {
        let nitro = NitroFixture::default().session();
        assert!(re_attests(&nitro, "tee_decryption_failed"));
        assert!(!re_attests(&session(), "tee_decryption_failed"));
    }

    #[test]
    fn a_malformed_request_never_re_attests() {
        let nitro = NitroFixture::default().session();
        for code in ["tee_request_malformed", "tee_version_unsupported"] {
            assert!(!re_attests(&nitro, code), "{code}");
        }
    }

    #[test]
    fn an_encrypted_get_carries_its_bytes_in_a_header() {
        let url = Url::parse("https://prover.example/prove/merge/status?jobId=a").unwrap();
        let session = session();
        let prepared = encrypted(&session, &Call::get(&url, Duration::from_secs(1)));
        assert!(prepared.body.is_none());
        assert!(prepared.headers.contains_key(HEADER_CIPHERTEXT));
    }

    #[test]
    fn an_encrypted_post_keeps_its_bytes_in_the_body() {
        let url = Url::parse("https://prover.example/prove/merge").unwrap();
        let session = session();
        let prepared = encrypted(
            &session,
            &Call::post(&url, "{}", Delivery::Queued, Duration::from_secs(1)),
        );
        assert!(prepared.body.is_some());
        assert!(!prepared.headers.contains_key(HEADER_CIPHERTEXT));
    }

    /// A proxy that serves the prover under its own path forwards the route
    /// bare or under the gateway prefix; the call opens on either.
    #[test]
    fn an_encrypted_call_binds_the_route_below_its_prover_url() {
        let prover = FixtureProver::from_ikm(&[0x5a; 32]);
        let session = session();
        let endpoint =
            ProverEndpoint::parse("https://app.example/api/tvc/zolana/prover/?api-key=k");
        let url = endpoint.url("/prove/merge_8_1/status").unwrap();
        let prepared = Call::get(&url, Duration::from_secs(1))
            .prepare(
                Some(Recipient {
                    session: &session,
                    key: prover.hpke_public_key(),
                }),
                &endpoint,
            )
            .ok()
            .unwrap();
        let enc = hex::decode(&prepared.headers[HEADER_ENC]).unwrap();
        let body = hex::decode(&prepared.headers[HEADER_CIPHERTEXT]).unwrap();
        for target in [
            "/prove/merge_8_1/status",
            "/v1/zolana/prove/merge_8_1/status?api-key=other",
        ] {
            assert!(prover.open("GET", target, &enc, &body).is_ok(), "{target}");
        }
        assert!(prover
            .open("GET", "/v1/zolana/prove/transfer_2_2/status", &enc, &body)
            .is_err());
        assert!(prover
            .open(
                "GET",
                "/api/tvc/zolana/prover/prove/merge_8_1/status",
                &enc,
                &body
            )
            .is_err());
    }
}
