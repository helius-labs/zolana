use std::{
    future::Future,
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
    // One attestation at a time, the server answers only a few quotes at once.
    attesting: tokio::sync::Mutex<()>,
}

impl TeeSession {
    pub fn new(policy: TeePolicy) -> Self {
        Self {
            policy,
            attested: Mutex::new(None),
            attesting: tokio::sync::Mutex::new(()),
        }
    }

    /// Runs `attest` while no other attestation of this session runs.
    pub fn attest_exclusive<T>(&self, attest: impl FnOnce() -> T) -> T {
        let _attesting = self.attesting.blocking_lock();
        attest()
    }

    /// Async counterpart of [`Self::attest_exclusive`].
    pub async fn attest_exclusive_async<T, F: Future<Output = T>>(
        &self,
        attest: impl FnOnce() -> F,
    ) -> T {
        let _attesting = self.attesting.lock().await;
        attest().await
    }

    /// The cached key, else the key `attest` returns. A call that waited for
    /// another attestation takes its key instead of attesting again.
    pub fn key_or_attest(
        &self,
        attest: impl FnOnce() -> Result<AttestedProver, ClientError>,
    ) -> Result<[u8; 32], ClientError> {
        if let Some(key) = self.attested_key() {
            return Ok(key);
        }
        self.attest_exclusive(|| match self.attested_key() {
            Some(key) => Ok(key),
            None => attest().map(|prover| prover.hpke_public_key),
        })
    }

    /// Async counterpart of [`Self::key_or_attest`].
    pub async fn key_or_attest_async<F: Future<Output = Result<AttestedProver, ClientError>>>(
        &self,
        attest: impl FnOnce() -> F,
    ) -> Result<[u8; 32], ClientError> {
        if let Some(key) = self.attested_key() {
            return Ok(key);
        }
        self.attest_exclusive_async(|| async {
            match self.attested_key() {
                Some(key) => Ok(key),
                None => attest().await.map(|prover| prover.hpke_public_key),
            }
        })
        .await
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

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        thread,
        time::Duration,
    };

    use super::*;

    fn session() -> TeeSession {
        TeeSession::new(
            TeePolicy::from_json(include_str!(
                "../../../../../prover/tee/testdata/probe_policy.json"
            ))
            .unwrap(),
        )
    }

    /// Stands in for `accept`, caching the prover the way a verified attestation does.
    fn attest(
        session: &TeeSession,
        attestations: &AtomicUsize,
    ) -> Result<AttestedProver, ClientError> {
        attestations.fetch_add(1, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(50));
        let prover = AttestedProver {
            hpke_public_key: [7; 32],
            tcb_status: "UpToDate".into(),
            compose_hash: [0; 32],
            gpu_verified: false,
        };
        *session.attested.lock().unwrap() = Some((prover.clone(), Instant::now()));
        Ok(prover)
    }

    #[test]
    fn concurrent_calls_share_one_attestation() {
        let session = Arc::new(session());
        let attestations = Arc::new(AtomicUsize::new(0));
        let keys: Vec<_> = (0..4)
            .map(|_| {
                let (session, attestations) = (session.clone(), attestations.clone());
                thread::spawn(move || session.key_or_attest(|| attest(&session, &attestations)))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().unwrap().unwrap())
            .collect();
        assert_eq!(attestations.load(Ordering::SeqCst), 1);
        assert!(keys.iter().all(|key| *key == [7; 32]));
    }

    #[tokio::test]
    async fn concurrent_async_calls_share_one_attestation() {
        let session = session();
        let attestations = AtomicUsize::new(0);
        let call = || session.key_or_attest_async(|| async { attest(&session, &attestations) });
        let keys = futures::future::join_all((0..4).map(|_| call())).await;
        assert_eq!(attestations.load(Ordering::SeqCst), 1);
        assert!(keys.into_iter().all(|key| key.unwrap() == [7; 32]));
    }
}
