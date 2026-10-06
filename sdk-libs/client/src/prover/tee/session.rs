use std::{
    sync::Mutex,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use rand_core::{OsRng, TryRngCore};
use reqwest::{StatusCode, Url};

use super::{
    verify, Attestation, AttestedProver, EncryptedRequest, TeeError, TeePolicy, HEADER_VERSION,
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
        let attestation: Attestation = serde_json::from_str(body)
            .map_err(|e| TeeError::MalformedAttestation(e.to_string()))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ClientError::Prover("system clock is before 1970".into()))?
            .as_secs();
        let prover = verify(attestation, &self.policy, nonce, now)?;
        *self.attested.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((prover.clone(), Instant::now()));
        Ok(prover)
    }

    pub fn encrypt(
        key: &[u8; 32],
        method: &str,
        url: &Url,
        body: &[u8],
    ) -> Result<EncryptedRequest, ClientError> {
        let request_uri = match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_string(),
        };
        Ok(EncryptedRequest::encrypt(key, method, &request_uri, body)?)
    }

    /// Refuses an unencrypted success and passes an unencrypted failure through
    /// unauthenticated, so retries and shedding still work.
    pub fn decrypt(
        encrypted: &EncryptedRequest,
        status: StatusCode,
        is_encrypted: bool,
        body: &[u8],
    ) -> Result<(StatusCode, String), ClientError> {
        if !is_encrypted {
            if status.is_success() {
                return Err(TeeError::UnencryptedResponse {
                    status: status.as_u16(),
                }
                .into());
            }
            return Ok((status, String::from_utf8_lossy(body).into_owned()));
        }
        let (inner, body) = encrypted.decrypt(body)?;
        let inner = StatusCode::from_u16(inner)
            .map_err(|_| TeeError::Encryption("bad encrypted status"))?;
        let text = String::from_utf8(body)
            .map_err(|_| TeeError::Encryption("encrypted body is not UTF-8"))?;
        Ok((inner, text))
    }

    pub fn is_encrypted(headers: &reqwest::header::HeaderMap) -> bool {
        headers
            .get(HEADER_VERSION)
            .is_some_and(|value| value.as_bytes() == VERSION.as_bytes())
    }
}
