use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use solana_address::Address;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use thiserror::Error;
use tokio::sync::{watch, Mutex as AsyncMutex, Semaphore, SemaphorePermit};
use zolana_client::ClientError;
use zolana_keypair::ViewingKey;
use zolana_ring_client::{auditor_view_tag, ReaderKey};
use zolana_transaction::AssetRegistry;

use crate::{
    api::unix_now,
    audit::{AuditService, ASSET_REFRESH_INTERVAL},
    authorize::Unauthorized,
    config::RootSecret,
    error::RingRpcError,
    keys::{service_keypair, AuditorKeyDerivation, KeyMode, KeySource},
    limits::{
        PublicRequest, RequestRate, MAX_CONCURRENT_AUTHENTICATIONS, MAX_CONCURRENT_DEPOSIT_SCANS,
        MAX_CONCURRENT_READS,
    },
    origins::Origins,
    replay::ReplayGuard,
    upstream::{DepositHistory, DepositPage, TransactionSource},
};

pub struct Hub<S> {
    signer: Keypair,
    shared: Arc<Shared<S>>,
    keys: KeySource,
}

const READINESS_CACHE_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadinessStatus {
    Ready,
    Unavailable(&'static str),
}

/// Names the readiness check that failed, which `/ready` reports.
#[derive(Debug, Error)]
pub enum NotReady {
    #[error("upstream probe failed because {0}")]
    Upstream(#[source] RingRpcError),
    #[error("the local ring config is unusable because {0}")]
    AuditorKey(#[source] Unauthorized),
    #[error("the cluster genesis hash differs from the one captured at boot")]
    Cluster,
}

impl NotReady {
    pub fn check(&self) -> &'static str {
        match self {
            Self::Upstream(_) => "unavailable upstream",
            Self::AuditorKey(_) => "unavailable auditor key",
            Self::Cluster => "unavailable cluster",
        }
    }
}

/// Unix seconds for the auth skew rule and the nonce eviction window.
#[derive(Debug, Clone, Copy)]
pub enum Clock {
    System,
    Fixed(u64),
}

impl Clock {
    pub(crate) fn now(self) -> Result<u64, RingRpcError> {
        match self {
            Self::System => unix_now().map_err(|_| RingRpcError::StateUnavailable),
            Self::Fixed(now) => Ok(now),
        }
    }
}

#[must_use]
pub struct HubBuilder<S> {
    source: S,
    genesis_hash: [u8; 32],
    assets: AssetRegistry,
    origins: Origins,
    clock: Clock,
}

pub(crate) struct Shared<S> {
    pub(crate) source: S,
    /// Captured at boot, every authority signature and derived key binds to it.
    pub(crate) genesis_hash: [u8; 32],
    pub(crate) clock: Clock,
    assets: AsyncMutex<AssetCache>,
    pub(crate) origins: Origins,
    pub(crate) replay: ReplayGuard,
    pub(crate) active_readers: Mutex<HashSet<(Address, ReaderKey)>>,
    pub(crate) read_limit: Semaphore,
    authentication_limit: Semaphore,
    deposit_limit: Semaphore,
    standard_rate: RequestRate,
    deposit_rate: RequestRate,
    authentication_rate: RequestRate,
    audit_rate: RequestRate,
    readiness: AsyncMutex<ReadinessCache>,
}

struct AssetCache {
    registry: AssetRegistry,
    refresh: RefreshState,
}

struct ReadinessCache {
    checked_at: Option<Instant>,
    status: ReadinessStatus,
    in_flight: Option<watch::Receiver<Option<ReadinessStatus>>>,
}

enum RefreshState {
    Never,
    Succeeded(Instant),
    Failed(Instant),
}

struct AuditServiceInit<S> {
    ring: Address,
    auditor: ViewingKey,
    shared: Arc<Shared<S>>,
}

impl<S> AuditServiceInit<S> {
    fn build(self) -> AuditService<S> {
        let view_tag = auditor_view_tag(&self.auditor.pubkey());
        AuditService {
            ring: self.ring,
            auditor: self.auditor,
            view_tag,
            shared: self.shared,
        }
    }
}

impl<S: TransactionSource> Shared<S> {
    pub(crate) async fn cached_assets(&self) -> AssetRegistry {
        self.assets.lock().await.registry.clone()
    }

    pub(crate) async fn refresh_assets(&self) -> Result<AssetRegistry, RingRpcError> {
        let mut cache = self.assets.lock().await;
        let refresh_due = match cache.refresh {
            RefreshState::Never => true,
            RefreshState::Succeeded(at) | RefreshState::Failed(at) => {
                at.elapsed() >= ASSET_REFRESH_INTERVAL
            }
        };
        if refresh_due {
            cache.refresh = RefreshState::Failed(Instant::now());
            cache.registry = self.source.asset_registry().await?;
            cache.refresh = RefreshState::Succeeded(Instant::now());
        } else if matches!(cache.refresh, RefreshState::Failed(_)) {
            return Err(ClientError::Rpc("asset registry is unavailable".to_owned()).into());
        }
        Ok(cache.registry.clone())
    }
}

impl<S: TransactionSource> Hub<S> {
    pub fn builder(source: S, genesis_hash: [u8; 32]) -> HubBuilder<S> {
        HubBuilder {
            source,
            genesis_hash,
            assets: AssetRegistry::default(),
            origins: Origins::default(),
            clock: Clock::System,
        }
    }

    pub(crate) fn accept_public(&self, request: PublicRequest) -> Result<(), RingRpcError> {
        match request {
            PublicRequest::Standard => &self.shared.standard_rate,
            PublicRequest::DepositScan { .. } => &self.shared.deposit_rate,
        }
        .accept(Instant::now(), request)
    }

    pub(crate) fn accept_audit(&self) -> Result<(), RingRpcError> {
        self.shared
            .audit_rate
            .accept(Instant::now(), PublicRequest::Standard)
    }

    pub(crate) fn accept_authentication(&self) -> Result<(), RingRpcError> {
        self.shared
            .authentication_rate
            .accept(Instant::now(), PublicRequest::Standard)
    }

    pub(crate) fn authentication_slot(&self) -> Result<SemaphorePermit<'_>, RingRpcError> {
        self.shared
            .authentication_limit
            .try_acquire()
            .map_err(|_| RingRpcError::Busy)
    }

    /// Held for a whole decrypting page, which no other method needs.
    pub(crate) fn read_slot(&self) -> Result<SemaphorePermit<'_>, RingRpcError> {
        self.shared
            .read_limit
            .try_acquire()
            .map_err(|_| RingRpcError::Busy)
    }

    pub(crate) fn deposit_slot(&self) -> Result<SemaphorePermit<'_>, RingRpcError> {
        self.shared
            .deposit_limit
            .try_acquire()
            .map_err(|_| RingRpcError::Busy)
    }

    pub fn mode(&self) -> KeyMode {
        match self.keys {
            KeySource::Local { .. } => KeyMode::Local,
            KeySource::Derived(_) => KeyMode::Derived,
        }
    }

    /// Value entering the ring, which no auditor message announces.
    pub async fn ring_deposits(&self, page: DepositPage) -> Result<DepositHistory, RingRpcError> {
        Ok(self.shared.source.ring_deposits(page).await?)
    }

    pub fn service_pubkey(&self) -> Address {
        self.signer.pubkey()
    }

    pub(crate) fn sign_attestation(&self, attestation: &[u8]) -> Signature {
        self.signer.sign_message(attestation)
    }

    pub fn origins(&self) -> &Origins {
        &self.shared.origins
    }

    pub fn local_view_tag(&self) -> Option<[u8; 32]> {
        match &self.keys {
            KeySource::Local { auditor, .. } => Some(auditor_view_tag(&auditor.pubkey())),
            KeySource::Derived(_) => None,
        }
    }

    pub fn service(&self) -> Result<AuditService<S>, RingRpcError> {
        let KeySource::Local { ring, auditor } = &self.keys else {
            return Err(RingRpcError::RingRequired);
        };
        Ok((AuditServiceInit {
            ring: *ring,
            auditor: auditor.clone(),
            shared: self.shared.clone(),
        })
        .build())
    }

    pub fn service_for(&self, ring: Address) -> Result<AuditService<S>, RingRpcError> {
        match &self.keys {
            KeySource::Local {
                ring: configured,
                auditor,
            } => {
                if ring != *configured {
                    return Err(RingRpcError::RingNotServed);
                }
                Ok((AuditServiceInit {
                    ring: *configured,
                    auditor: auditor.clone(),
                    shared: self.shared.clone(),
                })
                .build())
            }
            KeySource::Derived(root) => {
                let auditor = AuditorKeyDerivation {
                    root,
                    genesis_hash: &self.shared.genesis_hash,
                    ring,
                }
                .derive()?;
                Ok((AuditServiceInit {
                    ring,
                    auditor,
                    shared: self.shared.clone(),
                })
                .build())
            }
        }
    }

    pub(crate) fn validate_ring(&self, ring: Address) -> Result<(), RingRpcError> {
        match &self.keys {
            KeySource::Local {
                ring: configured, ..
            } if ring != *configured => Err(RingRpcError::RingNotServed),
            KeySource::Local { .. } | KeySource::Derived(_) => Ok(()),
        }
    }

    /// Local mode holds one key for one ring, so it also checks the config.
    pub async fn probe_upstreams(&self) -> Result<(), NotReady> {
        self.shared
            .source
            .health()
            .await
            .map_err(|error| NotReady::Upstream(error.into()))?;
        let current = self
            .shared
            .source
            .genesis_hash()
            .await
            .map_err(|error| NotReady::Upstream(error.into()))?;
        if current != self.shared.genesis_hash {
            return Err(NotReady::Cluster);
        }
        if let KeySource::Local { ring, auditor } = &self.keys {
            let config = self
                .shared
                .source
                .ring_config(*ring)
                .await
                .map_err(|error| NotReady::Upstream(error.into()))?
                .ok_or(NotReady::AuditorKey(Unauthorized::NoConfig))?;
            if config.auditor_pubkey != auditor.pubkey() {
                return Err(NotReady::AuditorKey(Unauthorized::AuditorKeyMismatch));
            }
        }
        Ok(())
    }

    pub(crate) async fn readiness(self: &Arc<Self>) -> ReadinessStatus
    where
        S: 'static,
    {
        let mut receiver = {
            let mut cache = self.shared.readiness.lock().await;
            if cache
                .checked_at
                .is_some_and(|checked_at| checked_at.elapsed() < READINESS_CACHE_INTERVAL)
            {
                return cache.status;
            }
            if let Some(receiver) = &cache.in_flight {
                receiver.clone()
            } else {
                let (sender, receiver) = watch::channel(None);
                cache.in_flight = Some(receiver.clone());
                let probe_hub = self.clone();
                let probe = tokio::spawn(async move { probe_hub.probe_upstreams().await });
                let hub = self.clone();
                tokio::spawn(async move {
                    let status = match probe.await {
                        Ok(Ok(())) => ReadinessStatus::Ready,
                        Ok(Err(error)) => {
                            log::error!("readiness probe failed because {error}");
                            ReadinessStatus::Unavailable(error.check())
                        }
                        Err(error) => {
                            log::error!("readiness task failed because {error}");
                            ReadinessStatus::Unavailable("unavailable readiness task")
                        }
                    };
                    let mut cache = hub.shared.readiness.lock().await;
                    cache.status = status;
                    cache.checked_at = Some(Instant::now());
                    cache.in_flight = None;
                    drop(cache);
                    let _ = sender.send(Some(status));
                });
                receiver
            }
        };
        let status = match receiver.wait_for(Option::is_some).await {
            Ok(status) => status.unwrap_or(ReadinessStatus::Unavailable("unavailable probe")),
            Err(_) => ReadinessStatus::Unavailable("unavailable readiness task"),
        };
        status
    }
}

impl<S: TransactionSource> HubBuilder<S> {
    #[must_use = "use the updated builder"]
    pub fn with_assets(mut self, assets: AssetRegistry) -> Self {
        self.assets = assets;
        self
    }

    #[must_use = "use the updated builder"]
    pub fn with_origins(mut self, origins: Origins) -> Self {
        self.origins = origins;
        self
    }

    #[must_use = "use the updated builder"]
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    pub fn local(self, ring: Address, auditor: ViewingKey) -> Result<Hub<S>, RingRpcError> {
        let signer = service_keypair(auditor.secret_bytes().as_slice())?;
        Ok(Hub {
            signer,
            shared: self.shared(),
            keys: KeySource::Local { ring, auditor },
        })
    }

    pub fn derived(self, root: RootSecret) -> Result<Hub<S>, RingRpcError> {
        let signer = service_keypair(root.as_bytes())?;
        Ok(Hub {
            signer,
            shared: self.shared(),
            keys: KeySource::Derived(root),
        })
    }

    fn shared(self) -> Arc<Shared<S>> {
        Arc::new(Shared {
            source: self.source,
            genesis_hash: self.genesis_hash,
            clock: self.clock,
            assets: AsyncMutex::new(AssetCache {
                registry: self.assets,
                refresh: RefreshState::Never,
            }),
            origins: self.origins,
            replay: ReplayGuard::default(),
            active_readers: Mutex::new(HashSet::new()),
            read_limit: Semaphore::new(MAX_CONCURRENT_READS),
            authentication_limit: Semaphore::new(MAX_CONCURRENT_AUTHENTICATIONS),
            deposit_limit: Semaphore::new(MAX_CONCURRENT_DEPOSIT_SCANS),
            standard_rate: RequestRate::default(),
            deposit_rate: RequestRate::default(),
            authentication_rate: RequestRate::default(),
            audit_rate: RequestRate::default(),
            readiness: AsyncMutex::new(ReadinessCache {
                checked_at: None,
                status: ReadinessStatus::Unavailable("not checked"),
                in_flight: None,
            }),
        })
    }
}
