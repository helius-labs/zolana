use std::{num::NonZeroU32, sync::Arc, time::Duration};

use custom_ring_interface::RingMode;
use solana_address::Address;
use zolana_client::GetShieldedTransactionsByTagsResponse;
use zolana_indexer_api::{HistoryFilters, Limit, PageRequest, PaginationToken};
use zolana_keypair::{X25519Keypair, X25519Pubkey};
use zolana_ring_client::{AuditError, AuditedTransaction, RingWithdrawal, TransactionAudit};
use zolana_transaction::instructions::transact::canonical_shape;

use crate::{
    api::{
        limit_in_bounds, AuthorityAuth, DecryptedAnonymousInput, DecryptedAnonymousRecipient,
        DecryptedAnonymousTrace, DecryptedOutput, DecryptedSpendCounter, DecryptedSpendRecord,
        DecryptedTransaction, DecryptedTransactionGroup, DecryptedWithdrawal,
        GetDecryptedTransactionsResponse, ReadAttestation, ReadAuth, SkippedReason,
        SkippedTransaction, AUDIT_PAGE_LIMIT,
    },
    authorize::{self, AuthorityCheck, ReadCheck, Unauthorized},
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
    pagination_token: Option<PaginationToken>,
    limit: NonZeroU32,
    attested_limit: Option<Limit>,
    filters: HistoryFilters,
    min_context_slot: Option<u64>,
}

#[derive(Default)]
#[must_use]
pub struct PageOptions {
    pagination_token: Option<PaginationToken>,
    limit: Option<Limit>,
    filters: HistoryFilters,
    min_context_slot: Option<u64>,
}

pub struct AuditService<S> {
    pub(crate) ring: Address,
    pub(crate) auditor: X25519Keypair,
    pub(crate) view_tag: [u8; 32],
    pub(crate) shared: Arc<Shared<S>>,
}

pub(crate) struct AuthorizedRead<'a, S> {
    service: &'a AuditService<S>,
    page: &'a Page,
    replay: ReplayCheck,
    mode: RingMode,
    _reader: ReaderPermit<'a>,
}

#[must_use]
pub struct AuditRead<'a> {
    pub auth: &'a ReadAuth,
    pub page: &'a Page,
}

impl PageOptions {
    #[must_use = "use the updated options"]
    pub fn with_pagination_token(mut self, token: PaginationToken) -> Self {
        self.pagination_token = Some(token);
        self
    }

    #[must_use = "use the updated options"]
    pub fn with_filters(mut self, filters: HistoryFilters) -> Self {
        self.filters = filters;
        self
    }

    #[must_use = "use the updated options"]
    pub fn with_min_context_slot(mut self, slot: u64) -> Self {
        self.min_context_slot = Some(slot);
        self
    }

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
            pagination_token: self.pagination_token,
            filters: self.filters,
            min_context_slot: self.min_context_slot,
            limit,
            attested_limit,
        })
    }
}

impl Page {
    pub fn limit(&self) -> NonZeroU32 {
        self.limit
    }

    /// What the indexer page must answer.
    fn request(&self) -> PageRequest {
        PageRequest {
            pagination_token: self.pagination_token,
            limit: u64::from(self.limit.get()),
            filters: self.filters,
            min_context_slot: self.min_context_slot,
        }
    }
}

impl<S: TransactionSource> AuditService<S> {
    pub fn ring(&self) -> Address {
        self.ring
    }

    pub fn auditor_pubkey(&self) -> X25519Pubkey {
        self.auditor.pubkey()
    }

    pub fn auditor_view_tag(&self) -> [u8; 32] {
        self.view_tag
    }

    /// The auditor key the ring's config names, `None` until the config exists.
    /// The config fixes it forever, so a ring whose key is not this service's
    /// can never be read here.
    pub async fn configured_auditor(&self) -> Result<Option<X25519Pubkey>, RingRpcError> {
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
        let now = self.shared.clock.now()?;
        let claim = AuthorityCheck {
            auth,
            ring: self.ring,
            genesis_hash: &self.shared.genesis_hash,
            now,
        }
        .decide()?;
        let source = &self.shared.source;
        let ring_authority = match source.ring_config(self.ring).await? {
            Some(config) => Some(config.authority),
            None => source.upgrade_authority(self.ring).await?,
        };
        if ring_authority != Some(claim.authority()) {
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
        let now = self.shared.clock.now()?;
        let nonce = authorize::nonce(&request.auth.nonce)?;
        let attestation = ReadAttestation {
            ring: self.ring,
            timestamp: request.auth.timestamp,
            nonce: &nonce,
            pagination_token: request.page.pagination_token,
            filters: request.page.filters,
            min_context_slot: request.page.min_context_slot,
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
            mode: config.mode,
            _reader: permit,
        })
    }

    async fn decrypted_transactions(
        &self,
        page: &Page,
        mode: RingMode,
    ) -> Result<GetDecryptedTransactionsResponse, RingRpcError> {
        let response = self
            .shared
            .source
            .transactions_by_tag(TransactionPage {
                tag: self.view_tag,
                pagination_token: page.pagination_token,
                filters: page.filters,
                min_context_slot: page.min_context_slot,
                limit: page.limit(),
            })
            .await?;
        validate_indexer_response(&response, page, self.view_tag)?;
        let mut assets = self.shared.cached_assets().await;
        let mut refreshed_assets = false;

        let mut items = Vec::new();
        for group in response.items {
            let mut item = DecryptedTransactionGroup {
                slot: group.slot,
                signature: group.signature.into(),
                events: Vec::new(),
                skipped: Vec::new(),
            };
            for tx in group.events {
                if tx.ring_program_id != Some(self.ring) {
                    continue;
                }
                let event_index = tx.event_index.ok_or(RingRpcError::InvalidIndexerResponse)?;
                let origin = self
                    .shared
                    .source
                    .transaction_origin(tx.tx_signature, event_index, self.ring)
                    .await?;
                if !origin.ring_invoked {
                    continue;
                }
                let mut result = (TransactionAudit {
                    auditor: &self.auditor,
                    transaction: &tx,
                    assets: &assets,
                })
                .run_with_mode(mode);
                if matches!(result, Err(AuditError::UnknownAsset { .. })) && !refreshed_assets {
                    assets = self.shared.refresh_assets().await?;
                    refreshed_assets = true;
                    result = (TransactionAudit {
                        auditor: &self.auditor,
                        transaction: &tx,
                        assets: &assets,
                    })
                    .run_with_mode(mode);
                }
                match result {
                    Ok(opened) => item.events.push(decrypted_transaction(
                        opened,
                        tx.nullifiers,
                        origin.signers,
                        origin.withdrawals,
                    )),
                    Err(reason) => item.skipped.push(SkippedTransaction {
                        slot: tx.slot,
                        tx_signature: tx.tx_signature.into(),
                        reason: skipped_reason(&reason),
                    }),
                }
            }
            if !item.events.is_empty() || !item.skipped.is_empty() {
                items.push(item);
            }
        }
        Ok(GetDecryptedTransactionsResponse {
            context: response.context,
            output_tree_id: None,
            items,
            pagination_token: response.pagination_token,
        })
    }
}

impl<S: TransactionSource> AuthorizedRead<'_, S> {
    pub(crate) async fn execute(self) -> Result<GetDecryptedTransactionsResponse, RingRpcError> {
        self.service.shared.replay.accept(self.replay)?;
        self.service
            .decrypted_transactions(self.page, self.mode)
            .await
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
    response
        .validate_indexed(&page.request())
        .map_err(|_| RingRpcError::InvalidIndexerResponse)?;
    for group in &response.items {
        group
            .validate_events(|event| (event.slot, event.tx_signature, event.event_index))
            .map_err(|_| RingRpcError::InvalidIndexerResponse)?;
        for transaction in &group.events {
            let has_auditor_message = transaction
                .messages
                .iter()
                .any(|message| message.view_tag == auditor_tag);
            // Compact padding leaves trailing slots out of the instruction, so a
            // transaction publishes at most, not exactly, its circuit's slots.
            let supported_shape = !transaction.nullifiers.is_empty()
                && canonical_shape(transaction.nullifiers.len(), transaction.output_slots.len())
                    .is_ok();
            if has_auditor_message && !supported_shape {
                return Err(RingRpcError::InvalidIndexerResponse);
            }
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
        anonymous: audited.anonymous.map(|disclosure| DecryptedAnonymousTrace {
            sender: Address::new_from_array(disclosure.sender).into(),
            inputs: disclosure
                .inputs
                .into_iter()
                .filter(|input| *input != Default::default())
                .map(|input| DecryptedAnonymousInput {
                    tree_id: input.tree_id,
                    amount: input.amount,
                    asset: input.asset.into(),
                })
                .collect(),
            recipients: (0u32..)
                .zip(disclosure.outputs)
                .filter(|(_, output)| output.identity_tag != 0)
                .map(|(slot_index, output)| DecryptedAnonymousRecipient {
                    slot_index,
                    identity_tag: output.identity_tag,
                    identity_key: output.identity_key.into(),
                    nullifier_pk: output.nullifier_pk.into(),
                    amount: output.amount,
                    asset: output.asset.into(),
                })
                .collect(),
        }),
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
        spend_records: audited
            .spend_records
            .into_iter()
            .map(|spend| DecryptedSpendRecord {
                slot_index: spend.slot_index,
                member: (*spend.record.member.as_bytes()).into(),
                version: spend.record.version,
                window: spend.record.window,
                counters_commitment: spend.record.counters_commitment.into(),
                counters: spend.counters.map(|counters| {
                    (0u8..)
                        .zip(counters.assets.iter().zip(counters.spent))
                        .filter(|(_, (asset, _))| **asset != [0; 32])
                        .map(|(slot, (asset, spent))| DecryptedSpendCounter {
                            slot,
                            asset: (*asset).into(),
                            spent,
                        })
                        .collect()
                }),
            })
            .collect(),
    }
}
