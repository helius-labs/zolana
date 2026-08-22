use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
    time::Instant,
};

use solana_address::Address;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use zolana_client::ClientError;
use zolana_keypair::ViewingKey;
use zolana_ring_client::{auditor_view_tag, ReaderKey};
use zolana_transaction::AssetRegistry;

use crate::{
    audit::{AuditService, ASSET_REFRESH_INTERVAL},
    authorize::Unauthorized,
    config::RootSecret,
    error::RingRpcError,
    keys::{service_keypair, AuditorKeyDerivation, KeyMode, KeySource},
    limits::{RequestRate, MAX_CONCURRENT_READS},
    origins::Origins,
    replay::ReplayGuard,
    upstream::{DepositHistory, DepositPage, TransactionSource},
};

pub struct Hub<S> {
    signer: Keypair,
    shared: Arc<Shared<S>>,
    keys: KeySource,
}

#[must_use]
pub struct HubBuilder<S> {
    source: S,
    assets: AssetRegistry,
    origins: Origins,
}

pub(crate) struct Shared<S> {
    pub(crate) source: S,
    assets: AsyncMutex<AssetCache>,
    pub(crate) origins: Origins,
    pub(crate) replay: ReplayGuard,
    pub(crate) active_readers: Mutex<HashSet<(Address, ReaderKey)>>,
    pub(crate) read_limit: Semaphore,
    pub(crate) request_rate: RequestRate,
}

struct AssetCache {
    registry: AssetRegistry,
    refresh: RefreshState,
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
    pub fn builder(source: S) -> HubBuilder<S> {
        HubBuilder {
            source,
            assets: AssetRegistry::default(),
            origins: Origins::default(),
        }
    }

    pub fn mode(&self) -> KeyMode {
        match self.keys {
            KeySource::Local { .. } => KeyMode::Local,
            KeySource::Derived { .. } => KeyMode::Derived,
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
            KeySource::Derived { .. } => None,
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
            KeySource::Derived { root, genesis_hash } => {
                let auditor = AuditorKeyDerivation {
                    root,
                    genesis_hash,
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

    pub async fn probe_upstreams(&self) -> Result<(), RingRpcError> {
        self.shared.source.health().await?;
        if let KeySource::Local { ring, auditor } = &self.keys {
            let config = self
                .shared
                .source
                .ring_config(*ring)
                .await?
                .ok_or(Unauthorized::NoConfig)?;
            if config.auditor_pubkey != auditor.pubkey() {
                return Err(Unauthorized::AuditorKeyMismatch.into());
            }
        }
        Ok(())
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

    pub fn local(self, ring: Address, auditor: ViewingKey) -> Result<Hub<S>, RingRpcError> {
        let signer = service_keypair(auditor.secret_bytes().as_slice())?;
        Ok(Hub {
            signer,
            shared: self.shared(),
            keys: KeySource::Local { ring, auditor },
        })
    }

    pub fn derived(self, root: RootSecret, genesis_hash: [u8; 32]) -> Result<Hub<S>, RingRpcError> {
        let signer = service_keypair(root.as_bytes())?;
        Ok(Hub {
            signer,
            shared: self.shared(),
            keys: KeySource::Derived { root, genesis_hash },
        })
    }

    fn shared(self) -> Arc<Shared<S>> {
        Arc::new(Shared {
            source: self.source,
            assets: AsyncMutex::new(AssetCache {
                registry: self.assets,
                refresh: RefreshState::Never,
            }),
            origins: self.origins,
            replay: ReplayGuard::default(),
            active_readers: Mutex::new(HashSet::new()),
            read_limit: Semaphore::new(MAX_CONCURRENT_READS),
            request_rate: RequestRate::default(),
        })
    }
}
