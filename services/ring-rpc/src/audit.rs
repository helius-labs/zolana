use std::{collections::HashMap, num::NonZeroU32, sync::Arc, time::Duration};

use solana_address::Address;
use solana_signature::Signature;
use zolana_client::GetShieldedTransactionsByTagsResponse;
use zolana_indexer_api::{Base64String, Limit};
use zolana_keypair::{P256Pubkey, ViewingKey};
use zolana_ring_client::{
    auditor_view_tag, AuditError, AuditedTransaction, RingOrigin, RingWithdrawal, TransactionAudit,
};
use zolana_transaction::{instructions::transact::canonical_shape, AssetRegistry};

use crate::{
    api::{
        cursor_in_bounds, limit_in_bounds, Attestation, AuthorityAuth, DecryptedOutput,
        DecryptedSpendCounter, DecryptedSpendRecord, DecryptedTransaction,
        DecryptedTransactionsPage, DecryptedWithdrawal, GetDecryptedTransactionsResponse,
        ReadAttestation, ReadAuth, SkippedReason, SkippedTransaction, AUDIT_PAGE_LIMIT,
    },
    authorize::{self, check_authority, check_read, Unauthorized},
    error::RingRpcError,
    hub::Shared,
    limits::ReaderPermit,
    replay::ReplayCheck,
    upstream::{ReaderGrant, TransactionPage, TransactionSource},
};

pub(crate) const ASSET_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// The attested limit is what the reader signed, absent for the default page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    cursor: Option<Base64String>,
    limit: NonZeroU32,
    attested_limit: Option<Limit>,
}

pub struct AuditService<S> {
    ring: Address,
    auditor: ViewingKey,
    view_tag: [u8; 32],
    shared: Arc<Shared<S>>,
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

impl Page {
    pub fn new(cursor: Option<Base64String>, limit: Option<Limit>) -> Result<Self, RingRpcError> {
        if cursor
            .as_ref()
            .is_some_and(|cursor| !cursor_in_bounds(&cursor.0))
            || limit.as_ref().is_some_and(|limit| !limit_in_bounds(limit))
        {
            return Err(RingRpcError::InvalidPage);
        }
        let count = limit.as_ref().map_or(AUDIT_PAGE_LIMIT, Limit::value);
        Ok(Self {
            cursor,
            limit: u32::try_from(count)
                .ok()
                .and_then(NonZeroU32::new)
                .ok_or(RingRpcError::InvalidPage)?,
            attested_limit: limit,
        })
    }

    pub fn cursor(&self) -> Option<&[u8]> {
        self.cursor.as_ref().map(|cursor| cursor.0.as_slice())
    }

    pub fn limit(&self) -> NonZeroU32 {
        self.limit
    }
}

impl<S: TransactionSource> AuditService<S> {
    pub(crate) fn new(ring: Address, auditor: ViewingKey, shared: Arc<Shared<S>>) -> Self {
        Self {
            ring,
            view_tag: auditor_view_tag(&auditor.pubkey()),
            auditor,
            shared,
        }
    }

    pub fn ring(&self) -> Address {
        self.ring
    }

    pub fn auditor_pubkey(&self) -> P256Pubkey {
        self.auditor.pubkey()
    }

    pub fn auditor_view_tag(&self) -> [u8; 32] {
        self.view_tag
    }

    /// `None` until the config exists. The config fixes the key forever.
    pub async fn configured_auditor(&self) -> Result<Option<P256Pubkey>, RingRpcError> {
        let config = self.shared.source.ring_config(self.ring).await?;
        Ok(config.map(|config| config.auditor_pubkey))
    }

    pub async fn read(
        &self,
        request: AuditRead<'_>,
    ) -> Result<GetDecryptedTransactionsResponse, RingRpcError> {
        self.authorize(request).await?.execute().await
    }

    /// The upgrade authority asks before the config exists, the config authority after,
    /// the same split the program enforces.
    pub async fn authorize_auditor_key(&self, auth: &AuthorityAuth) -> Result<(), RingRpcError> {
        let now = self.shared.clock.now()?;
        let (authority, nonce) = check_authority(auth, self.ring, self.shared.genesis_hash, now)?;
        let source = &self.shared.source;
        let ring_authority = match source.ring_config(self.ring).await? {
            Some(config) => Some(config.authority),
            None => source.upgrade_authority(self.ring).await?,
        };
        if ring_authority != Some(authority) {
            return Err(Unauthorized::NotRingAuthority.into());
        }
        Ok(self.shared.replay.accept(ReplayCheck {
            ring: self.ring,
            nonce,
            timestamp: auth.timestamp,
            now,
        })?)
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
            cursor: request.page.cursor.clone(),
            limit: request.page.attested_limit.clone(),
        }
        .message(request.auth.timestamp, &nonce);
        let reader = check_read(request.auth, &attestation, now, &self.shared.origins)?;
        let permit = ReaderPermit::acquire(&self.shared.active_readers, (self.ring, reader))?;
        let source = &self.shared.source;
        let config = source
            .ring_config(self.ring)
            .await?
            .ok_or(Unauthorized::NoConfig)?;
        if config.auditor_pubkey != self.auditor.pubkey() {
            return Err(Unauthorized::AuditorKeyMismatch.into());
        }
        let grant = ReaderGrant {
            ring: self.ring,
            reader,
        };
        if !source.reader_granted(grant).await? {
            return Err(Unauthorized::NotGranted.into());
        }
        Ok(AuthorizedRead {
            service: self,
            page: request.page,
            replay: ReplayCheck {
                ring: self.ring,
                nonce,
                timestamp: request.auth.timestamp,
                now,
            },
            _reader: permit,
        })
    }

    fn audit(
        &self,
        transaction: &zolana_client::ShieldedTransaction,
        assets: &AssetRegistry,
    ) -> Result<AuditedTransaction, AuditError> {
        TransactionAudit {
            auditor: &self.auditor,
            transaction,
            assets,
        }
        .run()
    }

    async fn decrypted_transactions(
        &self,
        page: &Page,
    ) -> Result<GetDecryptedTransactionsResponse, RingRpcError> {
        let source = &self.shared.source;
        let response = source
            .transactions_by_tag(TransactionPage {
                tag: self.view_tag,
                page,
            })
            .await?;
        validate_indexer_response(&response, page, self.view_tag)?;
        let mut assets = self.shared.cached_assets().await;
        let mut refreshed = false;
        let mut items = Vec::new();
        let mut skipped = Vec::new();
        let mut origins: HashMap<(Signature, u16), RingOrigin> = HashMap::new();
        for tx in response.transactions {
            if tx.ring_program_id != Some(self.ring) {
                continue;
            }
            let event_index = tx.event_index.ok_or(RingRpcError::InvalidIndexerResponse)?;
            let origin = match origins.get(&(tx.tx_signature, event_index)) {
                Some(known) => known.clone(),
                None => {
                    let found = source
                        .transaction_origin(tx.tx_signature, event_index, self.ring)
                        .await?;
                    origins.insert((tx.tx_signature, event_index), found.clone());
                    found
                }
            };
            if !origin.ring_invoked {
                continue;
            }
            let mut result = self.audit(&tx, &assets);
            // One registry refresh per page covers a mint registered since the last one.
            if matches!(result, Err(AuditError::UnknownAsset { .. })) && !refreshed {
                assets = self.shared.refresh_assets().await?;
                refreshed = true;
                result = self.audit(&tx, &assets);
            }
            match result {
                Ok(opened) => items.push(decrypted_transaction(
                    opened,
                    tx.nullifiers,
                    origin.signers,
                    origin.withdrawals,
                )),
                Err(reason) => skipped.push(SkippedTransaction {
                    slot: tx.slot,
                    tx_signature: tx.tx_signature.into(),
                    reason: match reason {
                        AuditError::MissingAuditorMessage => SkippedReason::MissingAuditorMessage,
                        _ => SkippedReason::InvalidAuditData,
                    },
                }),
            }
        }
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

fn validate_indexer_response(
    response: &GetShieldedTransactionsByTagsResponse,
    page: &Page,
    auditor_tag: [u8; 32],
) -> Result<(), RingRpcError> {
    let next = response.next_cursor.as_deref();
    if response.transactions.len() > page.limit.get() as usize
        || next.is_some_and(|cursor| !cursor_in_bounds(cursor) || page.cursor() == Some(cursor))
    {
        return Err(RingRpcError::InvalidIndexerResponse);
    }
    // Compact padding leaves trailing slots out, so a transaction publishes at most its shape.
    let unsupported = response.transactions.iter().any(|transaction| {
        transaction
            .messages
            .iter()
            .any(|message| message.view_tag == auditor_tag)
            && (transaction.nullifiers.is_empty()
                || canonical_shape(transaction.nullifiers.len(), transaction.output_slots.len())
                    .is_err())
    });
    if unsupported {
        return Err(RingRpcError::InvalidIndexerResponse);
    }
    Ok(())
}

fn decrypted_transaction(
    audited: AuditedTransaction,
    nullifiers: Vec<[u8; 32]>,
    signers: Vec<Address>,
    withdrawals: Vec<RingWithdrawal>,
) -> DecryptedTransaction {
    let outputs = audited.outputs.into_iter().map(|output| DecryptedOutput {
        slot_index: output.slot_index,
        recipient_viewing_pk: output.recipient_viewing_pk.as_bytes().to_vec().into(),
        owner_tag: output.owner_tag.into(),
        asset: output.asset.to_bytes().into(),
        amount: output.amount,
        ring_program_id: output.ring_program_id.map(|id| id.to_bytes().into()),
    });
    let withdrawals = withdrawals
        .into_iter()
        .map(|withdrawal| DecryptedWithdrawal {
            recipient: withdrawal.recipient.to_bytes().into(),
            asset: withdrawal.asset.to_bytes().into(),
            amount: withdrawal.amount,
        });
    let spend_records = audited.spend_records.into_iter().map(|spend| {
        // A zero asset marks an empty counter slot.
        let counters = spend.counters.map(|counters| {
            (0u8..)
                .zip(counters.assets.iter().zip(counters.spent))
                .filter(|(_, (asset, _))| **asset != [0; 32])
                .map(|(slot, (asset, spent))| DecryptedSpendCounter {
                    slot,
                    asset: (*asset).into(),
                    spent,
                })
                .collect()
        });
        DecryptedSpendRecord {
            slot_index: spend.slot_index,
            member: (*spend.record.member.as_bytes()).into(),
            version: spend.record.version,
            window: spend.record.window,
            counters_commitment: spend.record.counters_commitment.into(),
            counters,
        }
    });
    DecryptedTransaction {
        slot: audited.slot,
        tx_signature: audited.tx_signature.into(),
        tx_viewing_pk: audited.tx_viewing_pk.as_bytes().to_vec().into(),
        outputs: outputs.collect(),
        undecryptable_slots: audited.undecryptable_slots,
        nullifiers: nullifiers.into_iter().map(Into::into).collect(),
        signers: signers
            .into_iter()
            .map(|key| key.to_bytes().into())
            .collect(),
        withdrawals: withdrawals.collect(),
        spend_records: spend_records.collect(),
    }
}
