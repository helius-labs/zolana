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

type AttestResult = Result<AttestedProver, ClientError>;

/// Attestation state one prover client shares across its requests.
pub(crate) struct TeeSession {
    policy: TeePolicy,
    attested: Mutex<Option<(AttestedProver, Instant)>>,
    // One attestation at a time, the server answers only a few quotes at once.
    attesting: Mutex<()>,
    attesting_async: tokio::sync::Mutex<()>,
    // Bumped per finished attestation, a waiting call takes its failure instead of retrying.
    outcome: Mutex<(u64, Option<SharedFailure>)>,
}

#[derive(Clone)]
enum SharedFailure {
    Tee(TeeError),
    Other(String),
}

impl From<&ClientError> for SharedFailure {
    fn from(error: &ClientError) -> Self {
        match error {
            ClientError::Tee(error) => Self::Tee(error.clone()),
            error => Self::Other(error.to_string()),
        }
    }
}

impl From<SharedFailure> for ClientError {
    fn from(failure: SharedFailure) -> Self {
        match failure {
            SharedFailure::Tee(error) => ClientError::Tee(error),
            SharedFailure::Other(message) => ClientError::ProverServer(message),
        }
    }
}

impl TeeSession {
    pub fn new(policy: TeePolicy) -> Self {
        Self {
            policy,
            attested: Mutex::new(None),
            attesting: Mutex::new(()),
            attesting_async: tokio::sync::Mutex::new(()),
            outcome: Mutex::new((0, None)),
        }
    }

    /// Runs `attest` while no other attestation of this session runs.
    pub fn attest_exclusive(&self, attest: impl FnOnce() -> AttestResult) -> AttestResult {
        let _attesting = lock(&self.attesting);
        self.settle(attest())
    }

    /// Async counterpart of [`Self::attest_exclusive`].
    pub async fn attest_exclusive_async<F: Future<Output = AttestResult>>(
        &self,
        attest: impl FnOnce() -> F,
    ) -> AttestResult {
        let _attesting = self.attesting_async.lock().await;
        self.settle(attest().await)
    }

    /// The cached key, else the outcome of the attestation this call waited on, else `attest`.
    pub fn key_or_attest(
        &self,
        attest: impl FnOnce() -> AttestResult,
    ) -> Result<[u8; 32], ClientError> {
        if let Some(key) = self.attested_key() {
            return Ok(key);
        }
        let round = self.round();
        let _attesting = lock(&self.attesting);
        if let Some(joined) = self.joined(round) {
            return joined;
        }
        self.settle(attest()).map(|prover| prover.hpke_public_key)
    }

    /// Async counterpart of [`Self::key_or_attest`].
    pub async fn key_or_attest_async<F: Future<Output = AttestResult>>(
        &self,
        attest: impl FnOnce() -> F,
    ) -> Result<[u8; 32], ClientError> {
        if let Some(key) = self.attested_key() {
            return Ok(key);
        }
        let round = self.round();
        let _attesting = self.attesting_async.lock().await;
        if let Some(joined) = self.joined(round) {
            return joined;
        }
        self.settle(attest().await)
            .map(|prover| prover.hpke_public_key)
    }

    fn round(&self) -> u64 {
        lock(&self.outcome).0
    }

    /// What a call that waited since `round` takes, `None` when it must attest itself.
    fn joined(&self, round: u64) -> Option<Result<[u8; 32], ClientError>> {
        if let Some(key) = self.attested_key() {
            return Some(Ok(key));
        }
        let outcome = lock(&self.outcome);
        if outcome.0 == round {
            return None;
        }
        outcome.1.clone().map(|failure| Err(failure.into()))
    }

    fn settle(&self, result: AttestResult) -> AttestResult {
        let mut outcome = lock(&self.outcome);
        outcome.0 += 1;
        outcome.1 = result.as_ref().err().map(SharedFailure::from);
        result
    }

    /// The key of the last attestation still inside the policy's max age.
    pub fn attested_key(&self) -> Option<[u8; 32]> {
        let attested = lock(&self.attested);
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
        *lock(&self.attested) = Some((prover.clone(), Instant::now()));
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

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
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
        let call = || {
            session.key_or_attest_async(|| async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                attest(&session, &attestations)
            })
        };
        let keys = futures::future::join_all((0..4).map(|_| call())).await;
        assert_eq!(attestations.load(Ordering::SeqCst), 1);
        assert!(keys.into_iter().all(|key| key.unwrap() == [7; 32]));
    }

    #[test]
    fn calls_waiting_on_a_failed_attestation_share_its_failure() {
        let session = Arc::new(session());
        let attestations = Arc::new(AtomicUsize::new(0));
        let results: Vec<_> = (0..4)
            .map(|_| {
                let (session, attestations) = (session.clone(), attestations.clone());
                thread::spawn(move || {
                    session.key_or_attest(|| {
                        attestations.fetch_add(1, Ordering::SeqCst);
                        thread::sleep(Duration::from_millis(50));
                        Err(TeeError::ReportDataMismatch.into())
                    })
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(attestations.load(Ordering::SeqCst), 1);
        assert!(results
            .iter()
            .all(|result| matches!(result, Err(ClientError::Tee(TeeError::ReportDataMismatch)))));
    }
}
