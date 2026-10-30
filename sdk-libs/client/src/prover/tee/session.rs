use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use http::StatusCode;
use rand_core::{OsRng, TryRngCore};

use super::{
    verify_with, Anchors, Attestation, AttestedProver, EncryptedRequest, TeeError, TeeFleetPolicy,
    TeePolicy, TeePolicySource, HEADER_VERSION, MAX_ATTESTATION_BYTES, NONCE_SIZE, VERSION,
};
use crate::error::ClientError;

type AttestResult = Result<AttestedProver, ClientError>;

const DECRYPTION_FAILED: &str = "tee_decryption_failed";

/// Attestation state one prover client shares across its requests.
pub(crate) struct TeeSession {
    policy: SessionPolicy,
    anchors: Anchors,
    attested: Mutex<Option<(AttestedProver, Instant, Duration, TeePolicy)>>,
    // One attestation at a time, the server answers only a few quotes at once.
    attesting: tokio::sync::Mutex<()>,
    // Bumped per finished attestation, a waiting call takes its failure instead of retrying.
    outcome: Mutex<(u64, Option<SharedFailure>)>,
}

enum SessionPolicy {
    Single(TeePolicy),
    Fleet(TeeFleetPolicy),
    Source(Arc<TeePolicySource>),
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
        Self::with_policy(SessionPolicy::Single(policy))
    }

    pub fn fleet(policy: TeeFleetPolicy) -> Self {
        Self::with_policy(SessionPolicy::Fleet(policy))
    }

    pub fn source(source: Arc<TeePolicySource>) -> Self {
        Self::with_policy(SessionPolicy::Source(source))
    }

    fn with_policy(policy: SessionPolicy) -> Self {
        Self {
            policy,
            anchors: Anchors::PRODUCTION,
            attested: Mutex::new(None),
            attesting: tokio::sync::Mutex::new(()),
            outcome: Mutex::new((0, None)),
        }
    }

    #[cfg(test)]
    pub(super) fn trusting(policy: TeePolicy, anchors: Anchors) -> Self {
        Self {
            anchors,
            ..Self::new(policy)
        }
    }

    /// Runs `attest` while no other attestation of this session runs.
    pub async fn attest_exclusive<F: Future<Output = AttestResult>>(
        &self,
        attest: impl FnOnce() -> F,
    ) -> AttestResult {
        self.refresh_policy().await?;
        let _attesting = self.attesting.lock().await;
        self.settle(attest().await)
    }

    /// The cached key, else the outcome of the attestation this call waited on, else `attest`.
    pub async fn key_or_attest<F: Future<Output = AttestResult>>(
        &self,
        attest: impl FnOnce() -> F,
    ) -> Result<[u8; 32], ClientError> {
        self.refresh_policy().await?;
        if let Some(key) = self.attested_key() {
            return Ok(key);
        }
        let round = self.round();
        let _attesting = self.attesting.lock().await;
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
        self.check_policy_time().ok()?;
        let attested = lock(&self.attested);
        attested
            .as_ref()
            .filter(|(prover, at, max_age, policy)| {
                at.elapsed() < *max_age
                    && self.check_approval(&prover.hpke_public_key, policy).is_ok()
            })
            .map(|(prover, _, _, _)| prover.hpke_public_key)
    }

    pub(crate) async fn refresh_policy(&self) -> Result<(), ClientError> {
        if let SessionPolicy::Source(source) = &self.policy {
            source.resolve().await?;
        }
        self.check_policy_time()
    }

    pub(crate) fn check_policy_time(&self) -> Result<(), ClientError> {
        match &self.policy {
            SessionPolicy::Single(_) => {}
            SessionPolicy::Fleet(fleet) => fleet.check_time(now_secs()?)?,
            SessionPolicy::Source(_) => self.resolved_policy()?.check_time(now_secs()?)?,
        }
        Ok(())
    }

    fn resolved_policy(&self) -> Result<Arc<TeeFleetPolicy>, ClientError> {
        match &self.policy {
            SessionPolicy::Source(source) => source.current().map_err(ClientError::from),
            _ => Err(TeeError::PolicyUnavailable.into()),
        }
    }

    /// The exact entry approved now, retained with prepared ciphertext for the final check.
    pub(crate) fn approval(&self, key: &[u8; 32]) -> Result<TeePolicy, ClientError> {
        let approved = self.selected_policy(key)?;
        if matches!(self.policy, SessionPolicy::Source(_))
            && !lock(&self.attested)
                .as_ref()
                .is_some_and(|(prover, at, age, policy)| {
                    prover.hpke_public_key == *key && at.elapsed() < *age && *policy == approved
                })
        {
            return Err(TeeError::PolicyChanged.into());
        }
        Ok(approved)
    }

    fn selected_policy(&self, key: &[u8; 32]) -> Result<TeePolicy, ClientError> {
        self.check_policy_time()?;
        match &self.policy {
            SessionPolicy::Single(policy) => Ok(policy.clone()),
            SessionPolicy::Fleet(fleet) => fleet
                .deployment_for_key(key)
                .map(|entry| entry.policy.clone())
                .ok_or_else(|| TeeError::PolicyChanged.into()),
            SessionPolicy::Source(_) => self
                .resolved_policy()?
                .deployment_for_key(key)
                .map(|entry| entry.policy.clone())
                .ok_or_else(|| TeeError::PolicyChanged.into()),
        }
    }

    pub(crate) fn check_approval(
        &self,
        key: &[u8; 32],
        approved: &TeePolicy,
    ) -> Result<(), ClientError> {
        if self.selected_policy(key)? != *approved {
            return Err(TeeError::PolicyChanged.into());
        }
        Ok(())
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

    /// Verifies the attestation answer for `nonce` and caches the prover.
    pub fn accept(
        &self,
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
        let now = now_secs()?;
        let resolved = match &self.policy {
            SessionPolicy::Source(_) => Some(self.resolved_policy()?),
            _ => None,
        };
        let (prover, policy) = match &self.policy {
            SessionPolicy::Single(policy) => (
                verify_with(attestation, policy, nonce, now, &self.anchors)?,
                policy.clone(),
            ),
            SessionPolicy::Fleet(fleet) => {
                let prover = fleet.verify_with(attestation, nonce, now, &self.anchors)?;
                let deployment = fleet
                    .deployment_for_key(&prover.hpke_public_key)
                    .ok_or(TeeError::HpkeKeyMismatch)?;
                (prover, deployment.policy.clone())
            }
            SessionPolicy::Source(_) => {
                let fleet = resolved.as_ref().ok_or(TeeError::PolicyUnavailable)?;
                let prover = fleet.verify_with(attestation, nonce, now, &self.anchors)?;
                let policy = fleet
                    .deployment_for_key(&prover.hpke_public_key)
                    .ok_or(TeeError::HpkeKeyMismatch)?
                    .policy
                    .clone();
                (prover, policy)
            }
        };
        *lock(&self.attested) = Some((prover.clone(), Instant::now(), policy.max_age(), policy));
        Ok(prover)
    }

    pub fn lost_key(&self, key: &[u8; 32], status: StatusCode, body: &[u8]) -> bool {
        #[derive(serde::Deserialize)]
        struct Failure {
            code: String,
        }
        let platform = match &self.policy {
            SessionPolicy::Single(policy) => Some(policy.platform()),
            SessionPolicy::Fleet(fleet) => fleet
                .deployment_for_key(key)
                .map(|entry| entry.policy.platform()),
            SessionPolicy::Source(_) => self.resolved_policy().ok().and_then(|fleet| {
                fleet
                    .deployment_for_key(key)
                    .map(|entry| entry.policy.platform())
            }),
        };
        serde_json::from_slice::<Failure>(body).is_ok_and(|failure| {
            (status == StatusCode::SERVICE_UNAVAILABLE
                && failure.code == "tee_generation_unavailable")
                || (platform.is_some_and(|platform| platform.rotates_key_per_boot())
                    && status == StatusCode::BAD_REQUEST
                    && failure.code == DECRYPTION_FAILED)
        })
    }

    /// Uncaches `key` unless another attestation already replaced it.
    pub fn forget(&self, key: &[u8; 32]) {
        let mut attested = lock(&self.attested);
        if attested
            .as_ref()
            .is_some_and(|(prover, _, _, _)| prover.hpke_public_key == *key)
        {
            *attested = None;
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

fn now_secs() -> Result<u64, ClientError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|now| now.as_secs())
        .map_err(|_| ClientError::Prover("system clock is before 1970".into()))
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

    use super::*;
    use crate::prover::tee::{NitroFixture, Platform, TeeDeployment};
    use crate::prover::{
        call::{Call, CallError, Recipient},
        endpoint::ProverEndpoint,
        tee::{TeePolicyDocument, TeePolicyLoader},
    };

    #[derive(Clone)]
    struct MutablePolicy(Arc<Mutex<Result<String, TeeError>>>);

    #[async_trait::async_trait]
    impl TeePolicyLoader for MutablePolicy {
        async fn load(&self) -> Result<TeePolicyDocument, TeeError> {
            Ok(TeePolicyDocument {
                policy_json: self.0.lock().unwrap().clone()?,
                valid_until: now_secs().unwrap() + 600,
            })
        }
    }

    struct SourceFixture {
        source: Arc<TeePolicySource>,
        session: TeeSession,
        fixture: NitroFixture,
        policy: MutablePolicy,
    }

    impl SourceFixture {
        async fn new() -> Self {
            let fixture = NitroFixture::at([0x11; NONCE_SIZE], now_secs().unwrap()).pinning_key();
            let fleet = TeeFleetPolicy::new(
                "fixture".into(),
                1,
                now_secs().unwrap() + 3600,
                vec![TeeDeployment {
                    id: "eu-1".into(),
                    region: "eu-north-1".into(),
                    policy: fixture.policy().clone(),
                }],
            )
            .unwrap();
            let policy = MutablePolicy(Arc::new(Mutex::new(Ok(
                serde_json::to_string(&fleet).unwrap()
            ))));
            let source = Arc::new(TeePolicySource::new("fixture", policy.clone()));
            let session = TeeSession {
                anchors: fixture.anchors(),
                ..TeeSession::source(Arc::clone(&source))
            };
            session.refresh_policy().await.unwrap();
            session
                .accept(
                    &[0x11; NONCE_SIZE],
                    StatusCode::OK,
                    &serde_json::to_vec(&fixture.attestation_json()).unwrap(),
                )
                .unwrap();
            Self {
                source,
                session,
                fixture,
                policy,
            }
        }

        async fn replace(&self, edit: impl FnOnce(&mut serde_json::Value)) {
            let mut json: serde_json::Value =
                serde_json::from_str(self.policy.0.lock().unwrap().as_ref().unwrap()).unwrap();
            json["revision"] = 2.into();
            edit(&mut json);
            *self.policy.0.lock().unwrap() = Ok(json.to_string());
            self.source.expire_for_test();
            self.source.resolve().await.unwrap();
        }
    }

    #[tokio::test]
    async fn source_revocation_invalidates_cached_key_and_prepared_ciphertext() {
        let test = SourceFixture::new().await;
        let key = test.session.attested_key().unwrap();
        let endpoint = ProverEndpoint::parse("https://prover.example");
        let url = endpoint.url("/prove/merge").unwrap();
        let call = Call::post(
            &url,
            "private proof inputs",
            crate::prover::client::Delivery::InResponse,
            Duration::from_secs(1),
        );
        let prepared = call
            .prepare(
                Some(Recipient {
                    session: &test.session,
                    key,
                }),
                &endpoint,
            )
            .ok()
            .unwrap();
        assert_ne!(
            prepared.body.as_ref().unwrap().as_slice(),
            b"private proof inputs"
        );
        test.replace(|json| {
            json["deployments"][0]["policy"]["hpke_public_key"] = serde_json::json!("44".repeat(32))
        })
        .await;
        assert!(test.session.attested_key().is_none());
        assert!(matches!(
            prepared.authorize().await,
            Err(CallError::Refused(ClientError::Tee(
                TeeError::PolicyChanged
            )))
        ));
    }

    #[tokio::test]
    async fn changed_measurements_cannot_relabel_a_key_obtained_from_an_old_quote() {
        let test = SourceFixture::new().await;
        let key = test
            .session
            .key_or_attest(|| async { panic!("cached quote should be reused") })
            .await
            .unwrap();
        test.replace(|json| {
            json["deployments"][0]["policy"]["measurements"][0]["pcr0"] =
                serde_json::json!("04".repeat(48))
        })
        .await;
        assert!(matches!(
            test.session.approval(&key),
            Err(ClientError::Tee(TeeError::PolicyChanged))
        ));
        assert!(test.session.attested_key().is_none());
        assert!(matches!(
            test.session.accept(
                &[0x11; NONCE_SIZE],
                StatusCode::OK,
                &serde_json::to_vec(&test.fixture.attestation_json()).unwrap()
            ),
            Err(ClientError::Tee(TeeError::EnclaveMeasurementNotAllowed))
        ));
    }

    #[tokio::test]
    async fn unchanged_entry_survives_policy_renewal_without_reusing_removed_entries() {
        let test = SourceFixture::new().await;
        let key = test.session.attested_key().unwrap();
        test.replace(|json| json["expires_at"] = (now_secs().unwrap() + 7200).into())
            .await;
        assert_eq!(test.session.attested_key(), Some(key));
        assert!(test.session.approval(&key).is_ok());
    }

    #[tokio::test]
    async fn source_failure_blocks_cached_recipients_and_never_launches_another_quote() {
        let test = SourceFixture::new().await;
        *test.policy.0.lock().unwrap() = Err(TeeError::PolicyUnavailable);
        test.source.expire_for_test();
        let calls = AtomicUsize::new(0);
        let result = test
            .session
            .key_or_attest(|| async {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(TeeError::NoPolicy.into())
            })
            .await;
        assert!(matches!(
            result,
            Err(ClientError::Tee(TeeError::PolicyUnavailable))
        ));
        assert!(test.session.attested_key().is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

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
            platform: Platform::DstackTdx,
            hpke_public_key: [7; 32],
            image_id: vec![0; 32],
            tcb_status: Some("UpToDate".into()),
            gpu_verified: false,
        };
        *session.attested.lock().unwrap() = Some((
            prover.clone(),
            Instant::now(),
            Duration::from_secs(600),
            session.approval(&prover.hpke_public_key)?,
        ));
        Ok(prover)
    }

    #[tokio::test]
    async fn concurrent_calls_share_one_attestation() {
        let session = session();
        let attestations = AtomicUsize::new(0);
        let call = || {
            session.key_or_attest(|| async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                attest(&session, &attestations)
            })
        };
        let keys = futures::future::join_all((0..4).map(|_| call())).await;
        assert_eq!(attestations.load(Ordering::SeqCst), 1);
        assert!(keys.into_iter().all(|key| key.unwrap() == [7; 32]));
    }

    #[test]
    fn a_lost_key_is_forgotten_only_while_still_cached() {
        let session = session();
        attest(&session, &AtomicUsize::new(0)).unwrap();
        session.forget(&[8; 32]);
        assert_eq!(session.attested_key(), Some([7; 32]));
        session.forget(&[7; 32]);
        assert_eq!(session.attested_key(), None);
    }

    #[tokio::test]
    async fn calls_waiting_on_a_failed_attestation_share_its_failure() {
        let session = session();
        let attestations = AtomicUsize::new(0);
        let call = || {
            session.key_or_attest(|| async {
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

    #[tokio::test]
    async fn an_expired_fleet_cannot_reuse_a_cached_key_or_launch_attestation() {
        let now = now_secs().unwrap();
        let nonce = [0x11; NONCE_SIZE];
        let fixture = NitroFixture::at(nonce, now).pinning_key();
        let prover = verify_with(
            serde_json::from_value(fixture.attestation_json()).unwrap(),
            fixture.policy(),
            &nonce,
            now,
            &fixture.anchors(),
        )
        .unwrap();
        let fleet = TeeFleetPolicy::new(
            "fixture".into(),
            1,
            now - 1,
            vec![TeeDeployment {
                id: "eu-1".into(),
                region: "eu-north-1".into(),
                policy: fixture.policy().clone(),
            }],
        )
        .unwrap();
        let session = TeeSession::fleet(fleet);
        *lock(&session.attested) = Some((
            prover,
            Instant::now(),
            Duration::from_secs(600),
            fixture.policy().clone(),
        ));
        let calls = AtomicUsize::new(0);
        let launch = || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(TeeError::NoPolicy.into())
        };
        assert!(session.attested_key().is_none());
        assert!(matches!(
            session.key_or_attest(launch).await,
            Err(ClientError::Tee(TeeError::PolicyExpired))
        ));
        assert!(matches!(
            session.attest_exclusive(launch).await,
            Err(ClientError::Tee(TeeError::PolicyExpired))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn fleet_cache_uses_the_matched_generations_quote_lifetime() {
        let now = now_secs().unwrap();
        let nonce = [0x11; NONCE_SIZE];
        let fixture = NitroFixture::at(nonce, now).pinning_key();
        let mut other: serde_json::Value = serde_json::to_value(fixture.policy()).unwrap();
        other["hpke_public_key"] = serde_json::json!("44".repeat(32));
        let fleet = TeeFleetPolicy::new(
            "fixture".into(),
            1,
            now + 600,
            vec![
                TeeDeployment {
                    id: "eu-1".into(),
                    region: "eu-north-1".into(),
                    policy: fixture
                        .policy()
                        .clone()
                        .with_max_age(Duration::from_secs(1)),
                },
                TeeDeployment {
                    id: "us-1".into(),
                    region: "us-east-1".into(),
                    policy: TeePolicy::from_json(&other.to_string()).unwrap(),
                },
            ],
        )
        .unwrap();
        let session = TeeSession {
            anchors: fixture.anchors(),
            ..TeeSession::fleet(fleet)
        };
        let prover = session
            .accept(
                &nonce,
                StatusCode::OK,
                &serde_json::to_vec(&fixture.attestation_json()).unwrap(),
            )
            .unwrap();
        assert_eq!(session.attested_key(), Some(prover.hpke_public_key));
        lock(&session.attested).as_mut().unwrap().1 -= Duration::from_secs(2);
        assert_eq!(session.attested_key(), None);
        assert!(session.lost_key(
            &prover.hpke_public_key,
            StatusCode::BAD_REQUEST,
            br#"{"code":"tee_decryption_failed"}"#
        ));
    }
}
