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

/// A call as sent, keeping the key an encrypted answer opens with.
pub(crate) struct Prepared {
    pub headers: Vec<(&'static str, String)>,
    pub body: Option<Vec<u8>>,
    pub encrypted: Option<EncryptedRequest>,
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

    /// `attested_key` is set exactly when the client requires a TEE.
    pub fn prepare(&self, attested_key: Option<&[u8; 32]>) -> Result<Prepared, CallError> {
        let mut headers = Vec::new();
        match self.delivery {
            Some(Delivery::InResponse) => headers.push(("X-Sync", "true".to_string())),
            Some(Delivery::Queued) => headers.push(("X-Async", "true".to_string())),
            None => {}
        }
        let Some(key) = attested_key else {
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
            key,
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
            encrypted: Some(encrypted),
        })
    }
}

impl Prepared {
    pub fn finish(
        &self,
        status: StatusCode,
        is_encrypted: bool,
        body: &[u8],
    ) -> Result<(StatusCode, String), CallError> {
        match &self.encrypted {
            Some(encrypted) => TeeSession::decrypt(encrypted, status, is_encrypted, body)
                .map_err(CallError::Refused),
            None => Ok((status, String::from_utf8_lossy(body).into_owned())),
        }
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

    fn encrypted(call: &Call<'_>) -> Prepared {
        call.prepare(Some(&[9; 32])).ok().unwrap()
    }

    #[test]
    fn an_encrypted_get_carries_its_bytes_in_a_header() {
        let url = Url::parse("https://prover.example/prove/merge/status?jobId=a").unwrap();
        let prepared = encrypted(&Call::get(&url, Duration::from_secs(1)));
        assert!(prepared.body.is_none());
        assert!(prepared
            .headers
            .iter()
            .any(|(name, _)| *name == HEADER_CIPHERTEXT));
    }

    #[test]
    fn an_encrypted_post_keeps_its_bytes_in_the_body() {
        let url = Url::parse("https://prover.example/prove/merge").unwrap();
        let prepared = encrypted(&Call::post(&url, "{}", Delivery::Queued));
        assert!(prepared.body.is_some());
        assert!(!prepared
            .headers
            .iter()
            .any(|(name, _)| *name == HEADER_CIPHERTEXT));
    }
}
