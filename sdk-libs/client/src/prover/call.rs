//! One prover HTTP exchange, shared by the blocking and async clients and
//! encrypted to the attested key when the client requires a TEE.

use std::time::Duration;

use reqwest::{Method, StatusCode, Url};

use crate::{
    error::ClientError,
    prover::{
        client::Delivery,
        endpoint::scrub,
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
    Connect(reqwest::Error),
    Read(reqwest::Error),
    Refused(ClientError),
}

#[derive(Clone, Copy)]
pub(crate) struct Recipient<'s> {
    pub session: &'s TeeSession,
    pub key: [u8; 32],
}

/// A call as sent, keeping the key that decrypts its answer.
pub(crate) struct Prepared<'s> {
    pub headers: Vec<(&'static str, String)>,
    pub body: Option<Vec<u8>>,
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

    pub fn post(url: &'a Url, body: &'a str, delivery: Delivery) -> Self {
        Self {
            method: Method::POST,
            url,
            body: Some(body),
            delivery: Some(delivery),
            timeout: None,
        }
    }

    /// `recipient` is set exactly when the client requires a TEE.
    pub fn prepare<'s>(&self, recipient: Option<Recipient<'s>>) -> Result<Prepared<'s>, CallError> {
        let mut headers = Vec::new();
        match self.delivery {
            Some(Delivery::InResponse) => headers.push(("X-Sync", "true".to_string())),
            Some(Delivery::Queued) => headers.push(("X-Async", "true".to_string())),
            None => {}
        }
        let Some(recipient) = recipient else {
            if self.body.is_some() {
                headers.push(("Content-Type", "application/json".to_string()));
            }
            return Ok(Prepared {
                headers,
                body: self.body.map(|body| body.as_bytes().to_vec()),
                encrypted: None,
            });
        };
        let encrypted = TeeSession::encrypt(
            &recipient.key,
            self.method.as_str(),
            self.url,
            self.body.unwrap_or_default().as_bytes(),
        )
        .map_err(CallError::Refused)?;
        headers.push((HEADER_VERSION, VERSION.to_string()));
        headers.push((HEADER_ENC, encrypted.enc.clone()));
        let body = if self.method == Method::GET {
            headers.push((HEADER_CIPHERTEXT, hex::encode(&encrypted.body)));
            None
        } else {
            headers.push(("Content-Type", "application/octet-stream".to_string()));
            Some(encrypted.body.clone())
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
        if !is_encrypted && recipient.session.lost_key(status, body) {
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
    /// `label` names the call in a transport failure.
    pub fn into_client_error(self, label: &str) -> ClientError {
        match self {
            Self::Connect(e) => ClientError::ProverServer(format!("{label} failed: {}", scrub(e))),
            Self::Read(e) => {
                ClientError::ProverServer(format!("failed to read response body: {}", scrub(e)))
            }
            Self::Refused(error) => error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::tee::{NitroFixture, TeePolicy};

    fn session() -> TeeSession {
        TeeSession::new(
            TeePolicy::from_json(include_str!(
                "../../../../prover/tee/testdata/probe_policy.json"
            ))
            .unwrap(),
        )
    }

    fn encrypted<'s>(session: &'s TeeSession, call: &Call<'_>) -> Prepared<'s> {
        call.prepare(Some(Recipient {
            session,
            key: [9; 32],
        }))
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
        assert!(prepared
            .headers
            .iter()
            .any(|(name, _)| *name == HEADER_CIPHERTEXT));
    }

    #[test]
    fn an_encrypted_post_keeps_its_bytes_in_the_body() {
        let url = Url::parse("https://prover.example/prove/merge").unwrap();
        let session = session();
        let prepared = encrypted(&session, &Call::post(&url, "{}", Delivery::Queued));
        assert!(prepared.body.is_some());
        assert!(!prepared
            .headers
            .iter()
            .any(|(name, _)| *name == HEADER_CIPHERTEXT));
    }
}
