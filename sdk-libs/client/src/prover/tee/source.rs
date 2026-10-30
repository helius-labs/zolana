//! Authenticated policy loading and freshness, independent of HTTP and signing backends.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;

use super::{TeeError, TeeFleetPolicy};

const DEFAULT_REFRESH: Duration = Duration::from_secs(60);
const MAX_REFRESH: Duration = Duration::from_secs(300);
pub(super) const LOAD_TIMEOUT: Duration = Duration::from_secs(30);
pub(super) const MAX_POLICY_BYTES: usize = 1 << 20;

/// Publisher-authenticated bytes. A custom loader owns authentication and durable rollback state.
pub struct TeePolicyDocument {
    pub policy_json: String,
    /// Unix seconds, bounded by the authentication metadata's earliest expiry.
    pub valid_until: u64,
}

/// An application-authorized policy publisher. Dropping the future cancels this caller.
///
/// Implementations must authenticate the publisher and preserve durable rollback
/// state. This interface does not turn an unsigned HTTP fetch into trusted policy.
#[async_trait]
pub trait TeePolicyLoader: Send + Sync {
    async fn load(&self) -> Result<TeePolicyDocument, TeeError>;
}

/// Resolves a network's approved generations before attestation and transmission.
pub struct TeePolicySource {
    network: String,
    loader: Arc<dyn TeePolicyLoader>,
    interval: Duration,
    state: Mutex<State>,
    loading: tokio::sync::Mutex<()>,
}

#[derive(Default)]
struct State {
    accepted: Option<Accepted>,
    round: u64,
    failure: Option<TeeError>,
}

struct Accepted {
    original: TeeFleetPolicy,
    bounded: Arc<TeeFleetPolicy>,
    // Include host suspension in the refresh budget and reject future observations.
    at: SystemTime,
}

impl TeePolicySource {
    pub fn new(network: impl Into<String>, loader: impl TeePolicyLoader + 'static) -> Self {
        Self {
            network: network.into(),
            loader: Arc::new(loader),
            interval: DEFAULT_REFRESH,
            state: Mutex::new(State::default()),
            loading: tokio::sync::Mutex::new(()),
        }
    }

    /// Default one minute; at most five minutes. Authenticated expiry takes precedence.
    pub fn with_refresh_interval(mut self, interval: Duration) -> Result<Self, TeeError> {
        if interval.is_zero() || interval > MAX_REFRESH {
            return Err(TeeError::Policy("invalid source refresh interval".into()));
        }
        self.interval = interval;
        Ok(self)
    }

    /// Shares one refresh. Cancellation releases waiters to retry; errors never extend stale pins.
    pub async fn resolve(&self) -> Result<Arc<TeeFleetPolicy>, TeeError> {
        tokio::time::timeout(LOAD_TIMEOUT, self.resolve_inner())
            .await
            .unwrap_or(Err(TeeError::PolicyUnavailable))
    }

    /// Read the latest accepted snapshot, never a result another task resolved earlier.
    pub(super) fn current(&self) -> Result<Arc<TeeFleetPolicy>, TeeError> {
        let state = self.state()?;
        if state.failure.is_some() {
            return Err(TeeError::PolicyUnavailable);
        }
        let accepted = state.accepted.as_ref().ok_or(TeeError::PolicyUnavailable)?;
        if !accepted.at.elapsed().is_ok_and(|age| age < self.interval) {
            return Err(TeeError::PolicyUnavailable);
        }
        accepted.bounded.check_time(now_secs()?)?;
        Ok(Arc::clone(&accepted.bounded))
    }

    async fn resolve_inner(&self) -> Result<Arc<TeeFleetPolicy>, TeeError> {
        let round = self.state()?.round;
        let _loading = self.loading.lock().await;
        {
            let state = self.state()?;
            if state.round != round {
                if let Some(failure) = &state.failure {
                    return Err(failure.clone());
                }
            }
            if let Some(accepted) = &state.accepted {
                if state.failure.is_none()
                    && accepted.at.elapsed().is_ok_and(|age| age < self.interval)
                    && accepted.bounded.check_time(now_secs()?).is_ok()
                {
                    return Ok(Arc::clone(&accepted.bounded));
                }
            }
        }
        let result = self.refresh().await;
        let mut state = self.state()?;
        state.round = state.round.wrapping_add(1);
        state.failure = result.as_ref().err().cloned();
        result
    }

    async fn refresh(&self) -> Result<Arc<TeeFleetPolicy>, TeeError> {
        let document = self.loader.load().await?;
        if document.policy_json.len() > MAX_POLICY_BYTES
            || document.valid_until == 0
            || document.valid_until > (1 << 53) - 1
        {
            return Err(TeeError::Policy(
                "invalid authenticated policy document".into(),
            ));
        }
        let original = TeeFleetPolicy::from_json(&document.policy_json, &self.network)?;
        let bounded = Arc::new(TeeFleetPolicy::new(
            original.network().into(),
            original.revision(),
            original.expires_at().min(document.valid_until),
            original.deployments().to_vec(),
        )?);
        bounded.check_time(now_secs()?)?;
        let mut state = self.state()?;
        if let Some(previous) = &state.accepted {
            if original.revision() < previous.original.revision()
                || (original.revision() == previous.original.revision()
                    && original != previous.original)
            {
                return Err(TeeError::PolicyRollback);
            }
        }
        state.accepted = Some(Accepted {
            original,
            bounded: Arc::clone(&bounded),
            at: SystemTime::now(),
        });
        Ok(bounded)
    }

    fn state(&self) -> Result<std::sync::MutexGuard<'_, State>, TeeError> {
        self.state.lock().map_err(|_| TeeError::PolicyStorage)
    }

    #[cfg(test)]
    pub(super) fn expire_for_test(&self) {
        self.state().unwrap().accepted.as_mut().unwrap().at -=
            self.interval + Duration::from_secs(1);
    }
}

pub(super) fn now_secs() -> Result<u64, TeeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| TeeError::PolicyExpired)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    #[derive(Clone)]
    struct Queue {
        documents: Arc<Mutex<VecDeque<Result<TeePolicyDocument, TeeError>>>>,
        calls: Arc<AtomicUsize>,
    }

    impl Queue {
        fn new(documents: Vec<Result<TeePolicyDocument, TeeError>>) -> Self {
            Self {
                documents: Arc::new(Mutex::new(documents.into())),
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    #[async_trait]
    impl TeePolicyLoader for Queue {
        async fn load(&self) -> Result<TeePolicyDocument, TeeError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(10)).await;
            self.documents
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected extra load")
        }
    }

    fn document(revision: u64) -> TeePolicyDocument {
        let mut vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../test-vectors/tee_fleet_policy.json"
        ))
        .unwrap();
        vector["policy"]["revision"] = revision.into();
        TeePolicyDocument {
            policy_json: vector["policy"].to_string(),
            valid_until: now_secs().unwrap() + 600,
        }
    }

    fn expire(source: &TeePolicySource) {
        source.state().unwrap().accepted.as_mut().unwrap().at -= Duration::from_secs(61);
    }

    #[tokio::test]
    async fn concurrent_calls_share_one_refresh_and_metadata_caps_validity() {
        let loader = Queue::new(vec![Ok(document(1))]);
        let source = TeePolicySource::new("fixture", loader.clone());
        let values = futures::future::join_all((0..4).map(|_| source.resolve())).await;
        let first = values[0].as_ref().unwrap();
        assert!(first.expires_at() <= now_secs().unwrap() + 600);
        assert!(values
            .iter()
            .all(|value| Arc::ptr_eq(value.as_ref().unwrap(), first)));
        assert_eq!(loader.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn waiters_share_failure_and_a_new_call_can_retry() {
        let loader = Queue::new(vec![Err(TeeError::PolicyUnavailable), Ok(document(1))]);
        let source = TeePolicySource::new("fixture", loader.clone());
        let values = futures::future::join_all((0..4).map(|_| source.resolve())).await;
        assert!(values
            .iter()
            .all(|value| matches!(value, Err(TeeError::PolicyUnavailable))));
        assert_eq!(loader.calls.load(Ordering::SeqCst), 1);
        assert_eq!(source.resolve().await.unwrap().revision(), 1);
        assert_eq!(loader.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn required_refresh_failure_never_reuses_an_old_approval() {
        let loader = Queue::new(vec![Ok(document(1)), Err(TeeError::PolicyUnavailable)]);
        let source = TeePolicySource::new("fixture", loader);
        source.resolve().await.unwrap();
        expire(&source);
        assert!(matches!(
            source.resolve().await,
            Err(TeeError::PolicyUnavailable)
        ));
        assert!(matches!(source.current(), Err(TeeError::PolicyUnavailable)));
    }

    #[tokio::test]
    async fn a_future_observation_requires_a_new_policy_load() {
        let loader = Queue::new(vec![Ok(document(1)), Ok(document(2))]);
        let source = TeePolicySource::new("fixture", loader.clone());
        source.resolve().await.unwrap();
        source.state().unwrap().accepted.as_mut().unwrap().at += Duration::from_secs(60);
        assert!(matches!(source.current(), Err(TeeError::PolicyUnavailable)));
        assert_eq!(source.resolve().await.unwrap().revision(), 2);
        assert_eq!(loader.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn rollback_and_same_revision_changes_preserve_the_floor() {
        let mut substitution = document(2);
        let mut json: serde_json::Value = serde_json::from_str(&substitution.policy_json).unwrap();
        json["expires_at"] = 1_999_999_999u64.into();
        substitution.policy_json = json.to_string();
        let loader = Queue::new(vec![
            Ok(document(1)),
            Ok(document(2)),
            Ok(document(1)),
            Ok(substitution),
            Ok(document(3)),
        ]);
        let source = TeePolicySource::new("fixture", loader);
        let old = source.resolve().await.unwrap();
        expire(&source);
        assert_eq!(source.resolve().await.unwrap().revision(), 2);
        assert_eq!(old.revision(), 1);
        assert_eq!(source.current().unwrap().revision(), 2);
        expire(&source);
        assert!(matches!(
            source.resolve().await,
            Err(TeeError::PolicyRollback)
        ));
        assert!(matches!(
            source.resolve().await,
            Err(TeeError::PolicyRollback)
        ));
        assert_eq!(source.resolve().await.unwrap().revision(), 3);
    }

    struct FirstHangs {
        calls: AtomicUsize,
        entered: tokio::sync::Notify,
    }

    #[async_trait]
    impl TeePolicyLoader for Arc<FirstHangs> {
        async fn load(&self) -> Result<TeePolicyDocument, TeeError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.entered.notify_one();
                std::future::pending().await
            } else {
                Ok(document(1))
            }
        }
    }

    #[tokio::test]
    async fn cancelling_refresh_owner_releases_followers_without_trusting_its_result() {
        let loader = Arc::new(FirstHangs {
            calls: AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
        });
        let source = Arc::new(TeePolicySource::new("fixture", Arc::clone(&loader)));
        let owner = tokio::spawn({
            let source = Arc::clone(&source);
            async move { source.resolve().await }
        });
        loader.entered.notified().await;
        let follower = tokio::spawn({
            let source = Arc::clone(&source);
            async move { source.resolve().await }
        });
        owner.abort();
        assert!(owner.await.unwrap_err().is_cancelled());
        assert_eq!(follower.await.unwrap().unwrap().revision(), 1);
        assert_eq!(loader.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn load_deadline_covers_an_application_loader_that_never_finishes() {
        let loader = Arc::new(FirstHangs {
            calls: AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
        });
        let source = TeePolicySource::new("fixture", Arc::clone(&loader));
        assert!(matches!(
            source.resolve().await,
            Err(TeeError::PolicyUnavailable)
        ));
        assert!(source.state().unwrap().accepted.is_none());
        assert_eq!(source.resolve().await.unwrap().revision(), 1);
    }

    #[tokio::test]
    async fn malformed_wrong_network_oversized_and_expired_documents_never_commit() {
        let mut expired = document(1);
        expired.valid_until = now_secs().unwrap();
        let loader = Queue::new(vec![
            Ok(expired),
            Ok(TeePolicyDocument {
                policy_json: " ".repeat(MAX_POLICY_BYTES + 1),
                valid_until: 2_000_000_000,
            }),
            Ok(TeePolicyDocument {
                policy_json: "{}".into(),
                valid_until: 2_000_000_000,
            }),
        ]);
        let source = TeePolicySource::new("fixture", loader);
        for _ in 0..3 {
            assert!(source.resolve().await.is_err());
            assert!(source.state().unwrap().accepted.is_none());
        }
        let source = TeePolicySource::new("mainnet", Queue::new(vec![Ok(document(1))]));
        assert!(source.resolve().await.is_err());
        assert!(source.state().unwrap().accepted.is_none());
    }
}
