use std::{collections::HashMap, num::NonZeroU32, sync::Arc, time::Duration};

use solana_address::Address;
use solana_signature::Signature;
use zolana_client::{GetShieldedTransactionsByTagsResponse, Shape, SPP_SUPPORTED_SHAPES};
use zolana_indexer_api::{Base64String, Limit};
use zolana_keypair::{P256Pubkey, ViewingKey};
use zolana_ring_client::{
    AuditError, AuditedTransaction, RingOrigin, RingWithdrawal, TransactionAudit,
};

use crate::{
    api::{
        cursor_in_bounds, limit_in_bounds, unix_now, AuditorKeyAttestation, AuthorityAuth,
        DecryptedOutput, DecryptedTransaction, DecryptedTransactionsPage, DecryptedWithdrawal,
        GetDecryptedTransactionsResponse, ReadAttestation, ReadAuth, SkippedReason,
        SkippedTransaction, AUDIT_PAGE_LIMIT,
    },
    authorize::{AuthorityCheck, ReadCheck, Unauthorized},
    error::RingRpcError,
    hub::Shared,
    limits::ReaderPermit,
    replay::ReplayCheck,
    upstream::{ReaderGrant, TransactionPage, TransactionSource},
};

pub(crate) const ASSET_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
pub(crate) const MAX_ASSET_REGISTRY_ACCOUNTS: usize = 4_096;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    cursor: Option<Vec<u8>>,
    limit: NonZeroU32,
    attested_limit: Option<Limit>,
}

#[derive(Default)]
#[must_use]
pub struct PageOptions {
    cursor: Option<Vec<u8>>,
    limit: Option<Limit>,
}

pub struct AuditService<S> {
    pub(crate) ring: Address,
    pub(crate) auditor: ViewingKey,
    pub(crate) view_tag: [u8; 32],
    pub(crate) shared: Arc<Shared<S>>,
}

pub(crate) struct AuthorizedRead<'a, S> {
    service: &'a AuditService<S>,
    page: &'a Page,
    replay: ReplayCheck,
    _reader: ReaderPermit<'a>,
}

#[must_use]
pub struct AuditRead<'a> {
    pub auth: &'a ReadAuth,
    pub page: &'a Page,
}

impl PageOptions {
    #[must_use = "use the updated options"]
    pub fn with_cursor(mut self, cursor: Base64String) -> Result<Self, RingRpcError> {
        if !cursor_in_bounds(&cursor.0) {
            return Err(RingRpcError::InvalidPage);
        }
        self.cursor = Some(cursor.0);
        Ok(self)
    }

    #[must_use = "use the updated options"]
    pub fn with_limit(mut self, limit: Limit) -> Result<Self, RingRpcError> {
        if !limit_in_bounds(&limit) {
            return Err(RingRpcError::InvalidPage);
        }
        self.limit = Some(limit);
        Ok(self)
    }

    pub fn build(self) -> Result<Page, RingRpcError> {
        let attested_limit = self.limit;
        let limit = attested_limit
            .as_ref()
            .map_or(AUDIT_PAGE_LIMIT, Limit::value);
        let limit = u32::try_from(limit)
            .ok()
            .and_then(NonZeroU32::new)
            .ok_or(RingRpcError::InvalidPage)?;
        Ok(Page {
            cursor: self.cursor,
            limit,
            attested_limit,
        })
    }
}

impl Page {
    pub fn cursor(&self) -> Option<&[u8]> {
        self.cursor.as_deref()
    }

    pub fn limit(&self) -> NonZeroU32 {
        self.limit
    }
}

impl<S: TransactionSource> AuditService<S> {
    pub fn ring(&self) -> Address {
        self.ring
    }

    pub fn auditor_pubkey(&self) -> P256Pubkey {
        self.auditor.pubkey()
    }

    pub fn auditor_view_tag(&self) -> [u8; 32] {
        self.view_tag
    }

    /// The auditor key the ring's config names, `None` until the config exists.
    /// The config fixes it forever, so a ring whose key is not this service's
    /// can never be read here.
    pub async fn configured_auditor(&self) -> Result<Option<P256Pubkey>, RingRpcError> {
        Ok(self
            .shared
            .source
            .ring_config(self.ring)
            .await?
            .map(|config| config.auditor_pubkey))
    }

    pub async fn read(
        &self,
        request: AuditRead<'_>,
    ) -> Result<GetDecryptedTransactionsResponse, RingRpcError> {
        self.authorize(request).await?.execute().await
    }

    /// Before the config exists only the upgrade authority can ask, afterwards
    /// only the config authority, the same split the program enforces.
    pub async fn authorize_auditor_key(&self, auth: &AuthorityAuth) -> Result<(), RingRpcError> {
        let now = unix_now().map_err(|_| RingRpcError::StateUnavailable)?;
        let nonce = auth
            .nonce
            .0
            .as_slice()
            .try_into()
            .map_err(|_| Unauthorized::InvalidNonce)?;
        let attestation = AuditorKeyAttestation {
            genesis_hash: &self.shared.genesis_hash,
            ring: self.ring,
            timestamp: auth.timestamp,
            nonce: &nonce,
        };
        let claim = AuthorityCheck::new(auth, &attestation).at(now).decide()?;
        let source = &self.shared.source;
        let expected = match source.ring_config(self.ring).await? {
            Some(config) => Some(config.authority),
            None => source.upgrade_authority(self.ring).await?,
        }
        .filter(|authority| *authority != Address::default());
        if expected != Some(claim.authority()) {
            return Err(Unauthorized::NotRingAuthority.into());
        }
        self.shared.replay.accept(ReplayCheck {
            ring: self.ring,
            nonce: claim.nonce(),
            timestamp: auth.timestamp,
            now,
        })?;
        Ok(())
    }

    pub(crate) async fn authorize<'a>(
        &'a self,
        request: AuditRead<'a>,
    ) -> Result<AuthorizedRead<'a, S>, RingRpcError> {
        // One reading for the skew rule and for the nonce eviction window.
        let now = unix_now().map_err(|_| RingRpcError::StateUnavailable)?;
        let nonce = request
            .auth
            .nonce
            .0
            .as_slice()
            .try_into()
            .map_err(|_| Unauthorized::InvalidNonce)?;
        let attestation = ReadAttestation {
            ring: self.ring,
            timestamp: request.auth.timestamp,
            nonce: &nonce,
            cursor: request.page.cursor.as_deref(),
            limit: request.page.attested_limit.clone(),
        };
        let claim = ReadCheck::new(request.auth, &attestation)
            .at(now)
            .against(&self.shared.origins)
            .decide()?;
        let permit =
            ReaderPermit::acquire(&self.shared.active_readers, (self.ring, claim.reader_key()))?;
        let config = self
            .shared
            .source
            .ring_config(self.ring)
            .await?
            .ok_or(Unauthorized::NoConfig)?;
        if config.auditor_pubkey != self.auditor.pubkey() {
            return Err(Unauthorized::AuditorKeyMismatch.into());
        }
        self.shared
            .source
            .reader_granted(ReaderGrant {
                ring: self.ring,
                reader: claim.reader_key(),
            })
            .await?
            .then_some(())
            .ok_or(Unauthorized::NotGranted)?;
        Ok(AuthorizedRead {
            service: self,
            page: request.page,
            replay: ReplayCheck {
                ring: self.ring,
                nonce: claim.nonce(),
                timestamp: request.auth.timestamp,
                now,
            },
            _reader: permit,
        })
    }

    async fn decrypted_transactions(
        &self,
        page: &Page,
    ) -> Result<GetDecryptedTransactionsResponse, RingRpcError> {
        let response = self
            .shared
            .source
            .transactions_by_tag(TransactionPage {
                tag: self.view_tag,
                page,
            })
            .await?;
        validate_indexer_response(&response, page, self.view_tag)?;
        let mut assets = self.shared.cached_assets().await;
        let mut refreshed_assets = false;

        let mut audited = Vec::new();
        let mut skipped = Vec::new();
        let mut origins: HashMap<Signature, RingOrigin> = HashMap::new();
        for tx in response.transactions {
            let origin = match origins.get(&tx.tx_signature) {
                Some(known) => known.clone(),
                None => {
                    let found = self
                        .shared
                        .source
                        .transaction_origin(tx.tx_signature, self.ring)
                        .await?;
                    origins.insert(tx.tx_signature, found.clone());
                    found
                }
            };
            if !origin.ring_invoked {
                continue;
            }
            let mut result = (TransactionAudit {
                auditor: &self.auditor,
                transaction: &tx,
                assets: &assets,
            })
            .run();
            if matches!(result, Err(AuditError::UnknownAsset { .. })) && !refreshed_assets {
                assets = self.shared.refresh_assets().await?;
                refreshed_assets = true;
                result = (TransactionAudit {
                    auditor: &self.auditor,
                    transaction: &tx,
                    assets: &assets,
                })
                .run();
            }
            match result {
                Ok(opened) => {
                    audited.push((opened, tx.nullifiers, origin.signers, origin.withdrawals))
                }
                Err(reason) => skipped.push(SkippedTransaction {
                    slot: tx.slot,
                    tx_signature: tx.tx_signature.into(),
                    reason: skipped_reason(&reason),
                }),
            }
        }
        let items = audited
            .into_iter()
            .map(|(opened, nullifiers, signers, withdrawals)| {
                decrypted_transaction(opened, nullifiers, signers, withdrawals)
            })
            .collect();

        Ok(GetDecryptedTransactionsResponse {
            context: zolana_indexer_api::Context {
                block_time: response.context.block_time,
                slot: response.context.slot,
            },
            value: DecryptedTransactionsPage {
                items,
                skipped,
                cursor: response.next_cursor.map(Into::into),
            },
        })
    }
}

impl<S: TransactionSource> AuthorizedRead<'_, S> {
    pub(crate) async fn execute(self) -> Result<GetDecryptedTransactionsResponse, RingRpcError> {
        self.service.shared.replay.accept(self.replay)?;
        self.service.decrypted_transactions(self.page).await
    }
}

fn skipped_reason(error: &AuditError) -> SkippedReason {
    match error {
        AuditError::MissingAuditorMessage => SkippedReason::MissingAuditorMessage,
        _ => SkippedReason::InvalidAuditData,
    }
}

fn validate_indexer_response(
    response: &GetShieldedTransactionsByTagsResponse,
    page: &Page,
    auditor_tag: [u8; 32],
) -> Result<(), RingRpcError> {
    if response.transactions.len() > page.limit.get() as usize
        || response
            .next_cursor
            .as_ref()
            .is_some_and(|cursor| !cursor_in_bounds(cursor) || page.cursor.as_ref() == Some(cursor))
    {
        return Err(RingRpcError::InvalidIndexerResponse);
    }
    for transaction in &response.transactions {
        let has_auditor_message = transaction
            .messages
            .iter()
            .any(|message| message.view_tag == auditor_tag);
        let supported_shape = SPP_SUPPORTED_SHAPES.contains(&Shape::new(
            transaction.nullifiers.len(),
            transaction.output_slots.len(),
        ));
        if has_auditor_message && !supported_shape {
            return Err(RingRpcError::InvalidIndexerResponse);
        }
    }
    Ok(())
}

fn decrypted_transaction(
    audited: AuditedTransaction,
    nullifiers: Vec<[u8; 32]>,
    signers: Vec<Address>,
    withdrawals: Vec<RingWithdrawal>,
) -> DecryptedTransaction {
    DecryptedTransaction {
        slot: audited.slot,
        tx_signature: audited.tx_signature.into(),
        tx_viewing_pk: audited.tx_viewing_pk.as_bytes().to_vec().into(),
        outputs: audited
            .outputs
            .into_iter()
            .map(|output| DecryptedOutput {
                slot_index: output.slot_index,
                recipient_viewing_pk: output.recipient_viewing_pk.as_bytes().to_vec().into(),
                owner_tag: output.owner_tag.into(),
                asset: output.asset.to_bytes().into(),
                amount: output.amount,
                ring_program_id: output.ring_program_id.map(|id| id.to_bytes().into()),
            })
            .collect(),
        undecryptable_slots: audited.undecryptable_slots,
        nullifiers: nullifiers.into_iter().map(Into::into).collect(),
        signers: signers
            .into_iter()
            .map(|key| key.to_bytes().into())
            .collect(),
        withdrawals: withdrawals
            .into_iter()
            .map(|withdrawal| DecryptedWithdrawal {
                recipient: withdrawal.recipient.to_bytes().into(),
                asset: withdrawal.asset.to_bytes().into(),
                amount: withdrawal.amount,
            })
            .collect(),
    }
}
