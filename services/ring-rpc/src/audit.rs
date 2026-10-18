use std::{collections::HashMap, num::NonZeroU32, sync::Arc, time::Duration};

use custom_ring_interface::RingMode;
use solana_address::Address;
use solana_signature::Signature;
use zolana_client::GetShieldedTransactionsByTagsResponse;
use zolana_indexer_api::{Base64String, Limit};
use zolana_keypair::{X25519Pubkey, X25519Secret};
use zolana_ring_client::{
    auditor_view_tag,
    rpc::{
        cursor_in_bounds, limit_in_bounds, Attestation, AuthorityAuth, DecryptedTransaction,
        DecryptedTransactionsPage, GetAuditedMergesResponse, GetDecryptedTransactionsResponse,
        ReadAttestation, ReadAuth, SkippedReason, SkippedTransaction, AUDIT_PAGE_LIMIT,
    },
    AuditError, AuditedTransaction, RingOrigin, TransactionAudit,
};
use zolana_transaction::{instructions::transact::canonical_shape, AssetRegistry};

use crate::{
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
    auditor: X25519Secret,
    view_tag: [u8; 32],
    shared: Arc<Shared<S>>,
}

pub(crate) struct AuthorizedRead<'a, S> {
    service: &'a AuditService<S>,
    page: &'a Page,
    replay: ReplayCheck,
    /// The config read at authorization selects the disclosure layout.
    mode: RingMode,
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
    pub(crate) fn new(ring: Address, auditor: X25519Secret, shared: Arc<Shared<S>>) -> Self {
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

    pub fn auditor_pubkey(&self) -> X25519Pubkey {
        self.auditor.pubkey()
    }

    pub fn auditor_view_tag(&self) -> [u8; 32] {
        self.view_tag
    }

    /// `None` until the config exists. The config fixes the key forever.
    pub async fn configured_auditor(&self) -> Result<Option<X25519Pubkey>, RingRpcError> {
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
            mode: config.mode,
            _reader: permit,
        })
    }

    fn audit(
        &self,
        transaction: &zolana_client::ShieldedTransaction,
        assets: &AssetRegistry,
        mode: RingMode,
    ) -> Result<AuditedTransaction, AuditError> {
        TransactionAudit {
            auditor: &self.auditor,
            transaction,
            assets,
        }
        .run_with_mode(mode)
    }

    async fn decrypted_transactions(
        &self,
        page: &Page,
        mode: RingMode,
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
        for mut tx in response.transactions {
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
            if !origin.requires_audit() {
                continue;
            }
            let mut result = origin
                .bind_transaction(&mut tx, self.ring)
                .and_then(|()| self.audit(&tx, &assets, mode));
            let missing_asset = match &result {
                Ok(opened) => opened.has_unknown_assets(&assets)?,
                Err(_) => false,
            };
            // Missing mint preimages affect optional metadata, never verified disclosure.
            if missing_asset && !refreshed {
                refreshed = true;
                if let Ok(updated) = self.shared.refresh_assets().await {
                    assets = updated;
                    result = self.audit(&tx, &assets, mode);
                }
            }
            match result {
                Ok(opened) => items.push(DecryptedTransaction::new(
                    opened,
                    event_index,
                    tx.nullifiers,
                    origin.signers,
                    origin.withdrawals,
                )),
                Err(reason) => skipped.push(SkippedTransaction {
                    slot: tx.slot,
                    tx_signature: tx.tx_signature.into(),
                    event_index,
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
                // Photon reports the last matched row even on a terminal page.
                // A scan frontier means there is no next page to fetch.
                cursor: response
                    .next_cursor
                    .filter(|_| response.scanned_through.is_none())
                    .map(Into::into),
            },
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

    pub(crate) async fn execute_merges(self) -> Result<GetAuditedMergesResponse, RingRpcError> {
        self.service.shared.replay.accept(self.replay)?;
        let page = self
            .service
            .shared
            .source
            .merge_audit_page(
                self.service.ring,
                &self.service.auditor,
                self.page.cursor().map(ToOwned::to_owned),
                self.page.limit(),
            )
            .await?;
        if page
            .next_cursor
            .as_deref()
            .is_some_and(|cursor| !cursor_in_bounds(cursor))
        {
            return Err(RingRpcError::InvalidIndexerResponse);
        }
        Ok(page.into())
    }
}

fn validate_indexer_response(
    response: &GetShieldedTransactionsByTagsResponse,
    page: &Page,
    auditor_tag: [u8; 32],
) -> Result<(), RingRpcError> {
    let next = response.next_cursor.as_deref();
    let frontier = response.scanned_through.as_deref();
    if response.transactions.len() > page.limit.get() as usize
        || next.is_some_and(|cursor| !cursor_in_bounds(cursor) || page.cursor() == Some(cursor))
        || frontier.is_some_and(|cursor| {
            !cursor_in_bounds(cursor) || response.transactions.len() >= page.limit.get() as usize
        })
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
