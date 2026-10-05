use std::{
    sync::Mutex,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use rand_core::{OsRng, TryRngCore};
use reqwest::{StatusCode, Url};

use super::{
    verify, AttestedProver, Evidence, SealedRequest, TeeError, TeePolicy, HEADER_VERSION,
    NONCE_SIZE, VERSION,
};
use crate::error::ClientError;

/// Attestation state one prover client shares across its requests.
pub(crate) struct TeeSession {
    policy: TeePolicy,
    attested: Mutex<Option<(AttestedProver, Instant)>>,
}

impl TeeSession {
    pub fn new(policy: TeePolicy) -> Self {
        Self {
            policy,
            attested: Mutex::new(None),
        }
    }

    /// The key of the last attestation still inside the policy's max age.
    pub fn attested_key(&self) -> Option<[u8; 32]> {
        let attested = self.attested.lock().unwrap_or_else(|e| e.into_inner());
        attested
            .as_ref()
            .filter(|(_, at)| at.elapsed() < self.policy.max_age())
            .map(|(prover, _)| prover.hpke_public_key)
    }

    pub fn nonce() -> Result<[u8; NONCE_SIZE], ClientError> {
        let mut nonce = [0u8; NONCE_SIZE];
        OsRng.try_fill_bytes(&mut nonce).map_err(|_| {
            ClientError::Prover("no OS randomness for the attestation nonce".into())
        })?;
        Ok(nonce)
    }

    /// Verifies the attestation answer for `nonce` and caches the prover.
    pub fn accept(
        &self,
        nonce: &[u8; NONCE_SIZE],
        status: StatusCode,
        body: &str,
    ) -> Result<AttestedProver, ClientError> {
        if !status.is_success() {
            return Err(ClientError::ProverServer(format!(
                "attestation failed with status {status}: {body}"
            )));
        }
        let evidence: Evidence =
            serde_json::from_str(body).map_err(|e| TeeError::Evidence(e.to_string()))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ClientError::Prover("system clock is before 1970".into()))?
            .as_secs();
        let prover = verify(evidence, &self.policy, nonce, now)?;
        *self.attested.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((prover.clone(), Instant::now()));
        Ok(prover)
    }

    pub fn seal(
        key: &[u8; 32],
        method: &str,
        url: &Url,
        body: &[u8],
    ) -> Result<SealedRequest, ClientError> {
        let request_uri = match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_string(),
        };
        Ok(SealedRequest::seal(key, method, &request_uri, body)?)
    }

    /// Refuses an unsealed success and passes an unsealed failure through
    /// unauthenticated, so retries and shedding still work.
    pub fn open(
        sealed: &SealedRequest,
        status: StatusCode,
        is_sealed: bool,
        body: &[u8],
    ) -> Result<(StatusCode, String), ClientError> {
        if !is_sealed {
            if status.is_success() {
                return Err(TeeError::UnsealedResponse {
                    status: status.as_u16(),
                }
                .into());
            }
            return Ok((status, String::from_utf8_lossy(body).into_owned()));
        }
        let (inner, body) = sealed.open(body)?;
        let inner =
            StatusCode::from_u16(inner).map_err(|_| TeeError::Sealing("bad sealed status"))?;
        let text =
            String::from_utf8(body).map_err(|_| TeeError::Sealing("sealed body is not UTF-8"))?;
        Ok((inner, text))
    }

    pub fn is_sealed(headers: &reqwest::header::HeaderMap) -> bool {
        headers
            .get(HEADER_VERSION)
            .is_some_and(|value| value.as_bytes() == VERSION.as_bytes())
    }
}
