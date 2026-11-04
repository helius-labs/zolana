use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use http::StatusCode;
use rand_core::{OsRng, TryRngCore};

use super::{
    verify_with, Anchors, Attestation, AttestedProver, EncryptedRequest, SignedPolicyFile,
    SignedTeePolicy, TeeError, TeePolicy, VerifiedPolicy, HEADER_VERSION, MAX_ATTESTATION_BYTES,
    NONCE_SIZE, VERSION,
};
use crate::error::ClientError;

type AttestResult = Result<AttestedProver, ClientError>;

const DECRYPTION_FAILED: &str = "tee_decryption_failed";

/// Attestation state one prover client shares across its requests.
pub(crate) struct TeeSession {
    policy: Policy,
    anchors: Anchors,
    // An attestation counts only under the policy that accepted it.
    attested: Mutex<Option<(AttestedProver, Instant, Arc<TeePolicy>)>>,
    // The server answers only a few quotes at once.
    attesting: Flight<Arc<TeePolicy>>,
}

enum Policy {
    Fixed(Arc<TeePolicy>),
    Signed(Box<Downloaded>),
}

/// A signed policy and what its downloads found.
struct Downloaded {
    source: SignedTeePolicy,
    current: Mutex<Option<Current>>,
    downloading: Flight<()>,
}

/// Runs one at a time. A call that waited on a run that failed under the same
/// `K` takes that failure instead of running again.
struct Flight<K> {
    running: tokio::sync::Mutex<()>,
    // Bumped per finished run.
    last: Mutex<(u64, Option<(SharedFailure, K)>)>,
}

/// The accepted file's policy, release version and payload, freshness issue
/// time, and the earlier of its two expiries.
struct Current {
    policy: Arc<TeePolicy>,
    version: u64,
    payload: Vec<u8>,
    issued_at: u64,
    expires_at: u64,
    checked: Instant,
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

impl<K> Flight<K> {
    fn new() -> Self {
        Self {
            running: tokio::sync::Mutex::new(()),
            last: Mutex::new((0, None)),
        }
    }

    fn round(&self) -> u64 {
        lock(&self.last).0
    }

    /// The failure of a run that finished since `round` under a `K` that `same` accepts.
    fn failed_since(&self, round: u64, same: impl FnOnce(&K) -> bool) -> Option<ClientError> {
        let last = lock(&self.last);
        let (failure, under) = last.1.as_ref().filter(|_| last.0 != round)?;
        same(under).then(|| failure.clone().into())
    }

    fn settle<T>(&self, result: &Result<T, ClientError>, under: K) {
        let mut last = lock(&self.last);
        last.0 += 1;
        last.1 = result
            .as_ref()
            .err()
            .map(|error| (SharedFailure::from(error), under));
    }
}

impl TeeSession {
    pub fn new(policy: TeePolicy) -> Self {
        Self::with_policy(Policy::Fixed(Arc::new(policy)))
    }

    pub fn signed(source: SignedTeePolicy) -> Self {
        Self::with_policy(Policy::Signed(Box::new(Downloaded {
            source,
            current: Mutex::new(None),
            downloading: Flight::new(),
        })))
    }

    fn with_policy(policy: Policy) -> Self {
        Self {
            policy,
            anchors: Anchors::PRODUCTION,
            attested: Mutex::new(None),
            attesting: Flight::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn trusting(self, anchors: Anchors) -> Self {
        Self { anchors, ..self }
    }

    /// The policy in force, downloaded again with `fetch` once stale.
    pub async fn policy<F: Future<Output = Result<(StatusCode, Vec<u8>), ClientError>>>(
        &self,
        fetch: impl FnOnce(String) -> F,
    ) -> Result<Arc<TeePolicy>, ClientError> {
        match &self.policy {
            Policy::Fixed(policy) => Ok(Arc::clone(policy)),
            Policy::Signed(signed) => signed.policy(fetch).await,
        }
    }

    #[cfg(test)]
    pub fn fresh_policy(&self) -> Option<Arc<TeePolicy>> {
        match &self.policy {
            Policy::Fixed(policy) => Some(Arc::clone(policy)),
            Policy::Signed(signed) => signed.fresh(),
        }
    }

    /// Runs `attest` while no other attestation of this session runs.
    pub async fn attest_exclusive<F: Future<Output = AttestResult>>(
        &self,
        policy: &Arc<TeePolicy>,
        attest: impl FnOnce() -> F,
    ) -> AttestResult {
        let _running = self.attesting.running.lock().await;
        let result = attest().await;
        self.attesting.settle(&result, Arc::clone(policy));
        result
    }

    /// The cached key, else the outcome of the attestation this call waited on, else `attest`.
    pub async fn key_or_attest<F: Future<Output = AttestResult>>(
        &self,
        policy: &Arc<TeePolicy>,
        attest: impl FnOnce() -> F,
    ) -> Result<[u8; 32], ClientError> {
        if let Some(key) = self.attested_key(policy) {
            return Ok(key);
        }
        let round = self.attesting.round();
        let _running = self.attesting.running.lock().await;
        if let Some(key) = self.attested_key(policy) {
            return Ok(key);
        }
        if let Some(error) = self
            .attesting
            .failed_since(round, |under| Arc::ptr_eq(under, policy))
        {
            return Err(error);
        }
        let result = attest().await;
        self.attesting.settle(&result, Arc::clone(policy));
        result.map(|prover| prover.hpke_public_key)
    }

    /// The key of the last attestation `policy` accepted, still inside its max age.
    pub fn attested_key(&self, policy: &Arc<TeePolicy>) -> Option<[u8; 32]> {
        let attested = lock(&self.attested);
        attested
            .as_ref()
            .filter(|(_, at, accepted)| {
                Arc::ptr_eq(accepted, policy) && at.elapsed() < policy.max_age()
            })
            .map(|(prover, _, _)| prover.hpke_public_key)
    }

    pub fn nonce() -> Result<[u8; NONCE_SIZE], ClientError> {
        let mut nonce = [0u8; NONCE_SIZE];
        OsRng.try_fill_bytes(&mut nonce).map_err(|_| {
            ClientError::Prover("no OS randomness for the attestation nonce".into())
        })?;
        Ok(nonce)
    }

    pub fn check_attestation_len(len: usize) -> Result<(), ClientError> {
        if len > MAX_ATTESTATION_BYTES {
            return Err(TeeError::MalformedAttestation(format!(
                "attestation exceeds {MAX_ATTESTATION_BYTES} bytes"
            ))
            .into());
        }
        Ok(())
    }

    /// Verifies the attestation answer for `nonce` against `policy` and caches the prover.
    pub fn accept(
        &self,
        policy: &Arc<TeePolicy>,
        nonce: &[u8; NONCE_SIZE],
        status: StatusCode,
        body: &[u8],
    ) -> Result<AttestedProver, ClientError> {
        if !status.is_success() {
            return Err(ClientError::ProverServer(format!(
                "attestation failed with status {status}: {}",
                String::from_utf8_lossy(body)
            )));
        }
        let attestation: Attestation = serde_json::from_slice(body)
            .map_err(|e| TeeError::MalformedAttestation(e.to_string()))?;
        let prover = verify_with(attestation, policy, nonce, now_secs()?, &self.anchors)?;
        *lock(&self.attested) = Some((prover.clone(), Instant::now(), Arc::clone(policy)));
        Ok(prover)
    }

    /// The prover holds another key than the call was encrypted to, and read nothing.
    pub fn lost_key(status: StatusCode, body: &[u8]) -> bool {
        #[derive(serde::Deserialize)]
        struct Failure {
            code: String,
        }
        status == StatusCode::BAD_REQUEST
            && serde_json::from_slice::<Failure>(body)
                .is_ok_and(|failure| failure.code == DECRYPTION_FAILED)
    }

    /// Uncaches `key` unless another attestation already replaced it, and reads
    /// a signed policy again before the next attestation: a prover that lost the
    /// key has likely changed release, which the policy may already approve.
    pub fn forget(&self, key: &[u8; 32]) {
        let mut attested = lock(&self.attested);
        if attested
            .as_ref()
            .is_some_and(|(prover, _, _)| prover.hpke_public_key == *key)
        {
            *attested = None;
        }
        if let Policy::Signed(signed) = &self.policy {
            signed.stale();
        }
    }

    /// `route` is the path below the prover URL and its query.
    pub fn encrypt(
        key: &[u8; 32],
        method: &str,
        route: &str,
        body: &[u8],
    ) -> Result<EncryptedRequest, ClientError> {
        Ok(EncryptedRequest::encrypt(key, method, route, body)?)
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

    pub fn is_encrypted(headers: &http::HeaderMap) -> bool {
        headers
            .get(HEADER_VERSION)
            .is_some_and(|value| value.as_bytes() == VERSION.as_bytes())
    }
}

impl Downloaded {
    /// A failed download keeps the accepted policy until it expires.
    async fn policy<F: Future<Output = Result<(StatusCode, Vec<u8>), ClientError>>>(
        &self,
        fetch: impl FnOnce(String) -> F,
    ) -> Result<Arc<TeePolicy>, ClientError> {
        if let Some(policy) = self.fresh() {
            return Ok(policy);
        }
        let round = self.downloading.round();
        let _running = self.downloading.running.lock().await;
        if let Some(policy) = self.fresh() {
            return Ok(policy);
        }
        if let Some(error) = self.downloading.failed_since(round, |()| true) {
            return Err(error);
        }
        let downloaded = fetch(self.source.url.clone()).await;
        let now = now_secs()?;
        let downloaded = downloaded.and_then(|answer| self.verified(answer, now));
        let result = {
            let mut current = lock(&self.current);
            match downloaded {
                Ok(next) => {
                    let policy = Arc::clone(&next.policy);
                    *current = Some(next);
                    Ok(policy)
                }
                Err(error) => match current.as_mut().filter(|kept| now < kept.expires_at) {
                    Some(kept) => {
                        kept.checked = Instant::now();
                        Ok(Arc::clone(&kept.policy))
                    }
                    None => Err(error),
                },
            }
        };
        self.downloading.settle(&result, ());
        result
    }

    fn fresh(&self) -> Option<Arc<TeePolicy>> {
        lock(&self.current)
            .as_ref()
            .filter(|current| {
                current.checked.elapsed() < current.policy.max_age()
                    && now_secs().is_ok_and(|now| now < current.expires_at)
            })
            .map(|current| Arc::clone(&current.policy))
    }

    /// Ages the policy in force past its freshness, so the next call downloads again.
    fn stale(&self) {
        if let Some(current) = lock(&self.current).as_mut() {
            let max_age = current.policy.max_age();
            current.checked = Instant::now()
                .checked_sub(max_age)
                .unwrap_or_else(Instant::now);
        }
    }

    /// Refuses an older release version, another release payload under the same
    /// version, or an older freshness part for the same release.
    fn verified(
        &self,
        (status, body): (StatusCode, Vec<u8>),
        now: u64,
    ) -> Result<Current, ClientError> {
        if !status.is_success() {
            return Err(TeeError::SignedPolicy("unavailable").into());
        }
        let verified = SignedPolicyFile::verify(&body, &self.source.signers, now)?;
        let expires_at = verified.expires_at();
        let VerifiedPolicy {
            release,
            release_payload: payload,
            freshness,
        } = verified;
        let current = lock(&self.current);
        let previous = current.as_ref();
        let same = previous.filter(|previous| previous.payload == payload);
        if previous.is_some_and(|previous| {
            release.version < previous.version
                || (release.version == previous.version && payload != previous.payload)
        }) || same.is_some_and(|previous| freshness.issued_at < previous.issued_at)
        {
            return Err(TeeError::SignedPolicy("rollback").into());
        }
        let policy = same.map_or_else(
            || Arc::new(release.policy),
            |previous| Arc::clone(&previous.policy),
        );
        Ok(Current {
            policy,
            version: release.version,
            payload,
            issued_at: freshness.issued_at,
            expires_at,
            checked: Instant::now(),
        })
    }
}

fn now_secs() -> Result<u64, ClientError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ClientError::Prover("system clock is before 1970".into()))?
        .as_secs())
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        thread,
        time::Duration,
    };

    use ed25519_dalek::SigningKey;
    use serde_json::{json, Value};

    use super::*;
    use crate::prover::tee::{FreshnessSigners, Platform, PolicySigners, ReleasePayload};

    const PROBE: &str = include_str!("../../../../../prover/tee/testdata/probe_policy.json");

    fn session() -> (TeeSession, Arc<TeePolicy>) {
        let session = TeeSession::new(TeePolicy::from_json(PROBE).unwrap());
        let policy = session.fresh_policy().unwrap();
        (session, policy)
    }

    /// Stands in for `accept`, caching the prover the way a verified attestation does.
    fn attest(
        session: &TeeSession,
        policy: &Arc<TeePolicy>,
        attestations: &AtomicUsize,
    ) -> Result<AttestedProver, ClientError> {
        attestations.fetch_add(1, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(50));
        let prover = AttestedProver {
            platform: Platform::DstackTdx,
            hpke_public_key: [7; 32],
            image_id: vec![0; 32],
            tcb_status: Some("UpToDate".into()),
            gpu_verified: false,
        };
        *session.attested.lock().unwrap() =
            Some((prover.clone(), Instant::now(), Arc::clone(policy)));
        Ok(prover)
    }

    #[tokio::test]
    async fn concurrent_calls_share_one_attestation() {
        let (session, policy) = session();
        let attestations = AtomicUsize::new(0);
        let call = || {
            session.key_or_attest(&policy, || async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                attest(&session, &policy, &attestations)
            })
        };
        let keys = futures::future::join_all((0..4).map(|_| call())).await;
        assert_eq!(attestations.load(Ordering::SeqCst), 1);
        assert!(keys.into_iter().all(|key| key.unwrap() == [7; 32]));
    }

    #[test]
    fn a_lost_key_is_forgotten_only_while_still_cached() {
        let (session, policy) = session();
        attest(&session, &policy, &AtomicUsize::new(0)).unwrap();
        session.forget(&[8; 32]);
        assert_eq!(session.attested_key(&policy), Some([7; 32]));
        session.forget(&[7; 32]);
        assert_eq!(session.attested_key(&policy), None);
    }

    #[tokio::test]
    async fn calls_waiting_on_a_failed_attestation_share_its_failure() {
        let (session, policy) = session();
        let attestations = AtomicUsize::new(0);
        let call = || {
            session.key_or_attest(&policy, || async {
                attestations.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(50)).await;
                Err(TeeError::ReportDataMismatch.into())
            })
        };
        let results = futures::future::join_all((0..4).map(|_| call())).await;
        assert_eq!(attestations.load(Ordering::SeqCst), 1);
        assert!(results
            .iter()
            .all(|result| matches!(result, Err(ClientError::Tee(TeeError::ReportDataMismatch)))));
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// Released by any two of the keys of seeds 1, 2 and 3, kept fresh by the key of seed 5.
    fn signed() -> TeeSession {
        let keys = [1, 2, 3]
            .map(|seed| key(seed).verifying_key().to_bytes())
            .to_vec();
        let signers = PolicySigners::new("fixture", keys, 2).unwrap();
        TeeSession::signed(SignedTeePolicy::new("https://policy.example/p.json", signers).unwrap())
    }

    fn file(version: u64, max_age_secs: u64) -> Vec<u8> {
        signed_file(version, max_age_secs, &[1, 2])
    }

    fn signed_file(version: u64, max_age_secs: u64, seeds: &[u8]) -> Vec<u8> {
        fresh_file(version, max_age_secs, seeds, 1_000)
    }

    /// The probe policy as `version`, released by the keys of `seeds` and kept
    /// fresh from `issued_at` by the key of seed 5, which the release names.
    fn fresh_file(version: u64, max_age_secs: u64, seeds: &[u8], issued_at: u64) -> Vec<u8> {
        let mut policy: Value = serde_json::from_str(PROBE).unwrap();
        policy["max_age_secs"] = max_age_secs.into();
        let release: ReleasePayload = serde_json::from_value(json!({
            "network": "fixture",
            "version": version,
            "expires_at": 4_000_000_000u64,
            "freshness": FreshnessSigners::of(&[key(5)], 3_000_000_000),
            "policy": policy,
        }))
        .unwrap();
        let release_keys: Vec<_> = seeds.iter().map(|&seed| key(seed)).collect();
        let file = SignedPolicyFile::sign(
            &release,
            &release_keys,
            (issued_at, 3_000_000_000 + issued_at),
            &[key(5)],
        )
        .unwrap();
        serde_json::to_vec(&file).unwrap()
    }

    /// Downloads again whatever policy is in force.
    async fn download(
        session: &TeeSession,
        status: u16,
        body: Vec<u8>,
    ) -> Result<Arc<TeePolicy>, ClientError> {
        if let Policy::Signed(signed) = &session.policy {
            signed.stale();
        }
        session
            .policy(|_url| async move { Ok((StatusCode::from_u16(status).unwrap(), body)) })
            .await
    }

    #[tokio::test]
    async fn a_signed_policy_is_downloaded_again_only_once_stale() {
        let session = signed();
        let first = download(&session, 200, file(2, 600)).await.unwrap();
        let downloads = AtomicUsize::new(0);
        let again = session
            .policy(|_url| async {
                downloads.fetch_add(1, Ordering::SeqCst);
                Ok((StatusCode::OK, file(3, 600)))
            })
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&first, &again));
        assert_eq!(downloads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn an_attestation_stands_only_under_the_policy_that_accepted_it() {
        let session = signed();
        let v2 = download(&session, 200, file(2, 600)).await.unwrap();
        attest(&session, &v2, &AtomicUsize::new(0)).unwrap();
        let same = download(&session, 200, file(2, 600)).await.unwrap();
        assert!(Arc::ptr_eq(&v2, &same));
        assert_eq!(session.attested_key(&same), Some([7; 32]));
        let v3 = download(&session, 200, file(3, 600)).await.unwrap();
        assert_eq!(session.attested_key(&v3), None);
    }

    #[tokio::test]
    async fn a_lost_key_reads_the_signed_policy_again() {
        let session = signed();
        let v2 = download(&session, 200, file(2, 600)).await.unwrap();
        assert!(session.fresh_policy().is_some());
        session.forget(&[9; 32]);
        assert!(session.fresh_policy().is_none());
        let v3 = session
            .policy(|_url| async { Ok((StatusCode::OK, file(3, 600))) })
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(&v2, &v3));
    }

    #[tokio::test]
    async fn a_refused_download_keeps_the_policy_in_force() {
        let session = signed();
        let v3 = download(&session, 200, file(3, 600)).await.unwrap();
        for (status, body) in [
            (503, Vec::new()),
            (200, b"{}".to_vec()),
            (200, file(2, 600)),
            (200, file(3, 601)),
        ] {
            let kept = download(&session, status, body).await.unwrap();
            assert!(Arc::ptr_eq(&v3, &kept));
        }
        let Policy::Signed(signed) = &session.policy else {
            panic!("a signed session");
        };
        for older in [file(2, 600), file(3, 601)] {
            assert!(matches!(
                signed.verified((StatusCode::OK, older), 0),
                Err(ClientError::Tee(TeeError::SignedPolicy("rollback")))
            ));
        }
    }

    #[tokio::test]
    async fn a_newer_freshness_keeps_the_policy_and_its_attestation() {
        let session = signed();
        let v2 = download(&session, 200, fresh_file(2, 600, &[1, 2], 1_000))
            .await
            .unwrap();
        attest(&session, &v2, &AtomicUsize::new(0)).unwrap();
        let renewed = download(&session, 200, fresh_file(2, 600, &[1, 3], 2_000))
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&v2, &renewed));
        assert_eq!(session.attested_key(&renewed), Some([7; 32]));
        let Policy::Signed(signed) = &session.policy else {
            panic!("a signed session");
        };
        let current = lock(&signed.current);
        let current = current.as_ref().unwrap();
        assert_eq!(
            (current.issued_at, current.expires_at),
            (2_000, 3_000_002_000)
        );
    }

    #[tokio::test]
    async fn an_older_freshness_of_the_same_release_is_a_rollback() {
        let session = signed();
        let v2 = download(&session, 200, fresh_file(2, 600, &[1, 2], 2_000))
            .await
            .unwrap();
        let older = fresh_file(2, 600, &[1, 2], 1_000);
        let kept = download(&session, 200, older.clone()).await.unwrap();
        assert!(Arc::ptr_eq(&v2, &kept));
        let Policy::Signed(signed) = &session.policy else {
            panic!("a signed session");
        };
        assert!(matches!(
            signed.verified((StatusCode::OK, older), 0),
            Err(ClientError::Tee(TeeError::SignedPolicy("rollback")))
        ));
        let v3 = download(&session, 200, fresh_file(3, 600, &[1, 2], 1_500))
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(&v2, &v3));
    }

    #[tokio::test]
    async fn calls_waiting_on_a_failed_download_share_its_failure() {
        let session = signed();
        let downloads = AtomicUsize::new(0);
        let call = || {
            session.policy(|_url| async {
                downloads.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok((StatusCode::SERVICE_UNAVAILABLE, Vec::new()))
            })
        };
        let results = futures::future::join_all((0..4).map(|_| call())).await;
        assert_eq!(downloads.load(Ordering::SeqCst), 1);
        assert!(results.iter().all(|result| matches!(
            result,
            Err(ClientError::Tee(TeeError::SignedPolicy("unavailable")))
        )));
    }

    #[test]
    fn an_attestation_failure_reaches_only_calls_under_its_policy() {
        let (session, policy) = session();
        let other = Arc::new(TeePolicy::from_json(PROBE).unwrap());
        let flight = &session.attesting;
        let round = flight.round();
        flight.settle::<()>(
            &Err(TeeError::ReportDataMismatch.into()),
            Arc::clone(&policy),
        );
        assert!(flight
            .failed_since(round, |under| Arc::ptr_eq(under, &other))
            .is_none());
        assert!(matches!(
            flight.failed_since(round, |under| Arc::ptr_eq(under, &policy)),
            Some(ClientError::Tee(TeeError::ReportDataMismatch))
        ));
    }

    #[tokio::test]
    async fn without_a_policy_in_force_a_refused_download_fails() {
        let session = signed();
        let one_signer = signed_file(2, 600, &[1]);
        for (status, body, check) in [
            (503, Vec::new(), "unavailable"),
            (200, one_signer, "signature"),
        ] {
            assert!(matches!(
                download(&session, status, body).await,
                Err(ClientError::Tee(TeeError::SignedPolicy(refused))) if refused == check
            ));
        }
    }
}
