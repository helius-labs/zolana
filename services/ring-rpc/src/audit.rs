use std::{collections::HashMap, num::NonZeroU32, sync::Arc, time::Duration};

use custom_ring_interface::RingMode;
use solana_address::Address;
use solana_signature::Signature;
use zolana_client::GetShieldedTransactionsByTagsResponse;
use zolana_indexer_api::{
    Base64String, GetRingMemberOpeningsRequest, GetRingMemberRecordsRequest, Hash, Limit,
    RingMemberOpening, MAX_RING_MEMBER_PAGE_LIMIT,
};
use zolana_keypair::{X25519Keypair, X25519Pubkey};
use zolana_ring_client::{
    auditor_view_tag,
    records::{MemberOpeningRead, RegistryTip},
    rpc::{
        cursor_in_bounds, limit_in_bounds, utxo_hashes_in_bounds, Attestation,
        AuditedUtxosAttestation, AuditedUtxosPage, AuditorKeyStatement, AuthorityAuth,
        ConfirmedAudit, DecryptedTransaction, DecryptedTransactionsPage, GetAuditedMergesResponse,
        GetAuditedUtxosRequest, GetAuditedUtxosResponse, GetDecryptedTransactionsResponse,
        PagedRead, ReadAttestation, ReadAuth, ReadTarget, RingChainStatus, SkippedReason,
        SkippedTransaction, AUDIT_PAGE_LIMIT,
    },
    AuditError, AuditedTransaction, CreatedUtxos, MergeAuditPage, RingOrigin, TransactionAudit,
};
use zolana_ring_policy::Member;
use zolana_transaction::{instructions::transact::canonical_shape, AssetRegistry};

use crate::{
    authorize::{AuthorityCheck, AuthorityClaim, ReadCheck, ReadClaim, Unauthorized},
    error::{redacted, RingRpcError},
    hub::Shared,
    limits::ReaderPermit,
    replay::ReplayCheck,
    upstream::{
        MergeAuditRequest, ReaderGrant, RingHistoryPage, TransactionPage, TransactionSource,
    },
    utxos::{AuditStore, CreatedIn, EscrowRoot, EscrowedOwner, MAX_BACKFILL_PAGES},
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
    auditor: X25519Keypair,
    view_tag: [u8; 32],
    shared: Arc<Shared<S>>,
}

#[must_use]
pub(crate) struct AuditServiceInit<S> {
    pub ring: Address,
    pub auditor: X25519Keypair,
    pub shared: Arc<Shared<S>>,
}

/// Its nonce is spent when the read executes.
struct Grant<'a, S> {
    service: &'a AuditService<S>,
    nonce: [u8; 32],
    timestamp: u64,
    /// The config read at authorization names the rail its frames parse under.
    mode: RingMode,
    _reader: ReaderPermit<'a>,
}

pub(crate) struct AuthorizedRead<'a, S> {
    grant: Grant<'a, S>,
    page: &'a Page,
}

struct AuthorizedUtxos<'a, S> {
    grant: Grant<'a, S>,
    utxo_hashes: &'a [Hash],
}

#[must_use]
pub struct AuditRead<'a> {
    pub read: PagedRead,
    pub auth: &'a ReadAuth,
    pub page: &'a Page,
}

#[derive(Clone, Copy)]
struct BoundTransaction<'a> {
    transaction: &'a zolana_client::ShieldedTransaction,
    origin: &'a RingOrigin,
    store: &'a AuditStore,
    mode: RingMode,
}

struct AuditedRows {
    items: Vec<DecryptedTransaction>,
    skipped: Vec<SkippedTransaction>,
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

impl<S> AuditServiceInit<S> {
    pub(crate) fn build(self) -> AuditService<S> {
        AuditService {
            ring: self.ring,
            view_tag: auditor_view_tag(&self.auditor.pubkey()),
            auditor: self.auditor,
            shared: self.shared,
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

    /// `None` until the config exists, the config then fixes the key forever.
    pub async fn configured_auditor(&self) -> Result<Option<X25519Pubkey>, RingRpcError> {
        let config = self.shared.source.ring_config(self.ring).await?;
        Ok(config.map(|config| config.auditor_pubkey))
    }

    pub async fn chain_status(&self) -> Result<RingChainStatus, RingRpcError> {
        Ok(self.shared.source.ring_chain_status(self.ring).await?)
    }

    pub async fn read(
        &self,
        request: AuditRead<'_>,
    ) -> Result<GetDecryptedTransactionsResponse, RingRpcError> {
        self.authorize(request).await?.execute().await
    }

    pub async fn audited_utxos(
        &self,
        request: &GetAuditedUtxosRequest,
    ) -> Result<GetAuditedUtxosResponse, RingRpcError> {
        self.authorize_utxos(request).await?.execute()
    }

    /// The upgrade authority asks before the config exists, the config authority after.
    pub async fn auditor_key_statement(
        &self,
        auth: &AuthorityAuth,
    ) -> Result<Vec<u8>, RingRpcError> {
        let now = self.shared.clock.now()?;
        let AuthorityClaim { authority, nonce } = AuthorityCheck {
            auth,
            ring: self.ring,
            genesis_hash: self.shared.genesis_hash,
            now,
        }
        .decide()?;
        let source = &self.shared.source;
        let ring_authority = match source.ring_config(self.ring).await? {
            Some(config) => Some(config.authority),
            None => source.upgrade_authority(self.ring).await?,
        };
        if ring_authority != Some(authority) {
            return Err(Unauthorized::NotRingAuthority.into());
        }
        self.shared.replay.accept(ReplayCheck {
            ring: self.ring,
            nonce,
            timestamp: auth.timestamp,
            now: self.shared.clock.now()?,
        })?;
        Ok(AuditorKeyStatement {
            cluster: &self.shared.genesis_hash,
            ring: &self.ring,
            auditor_pubkey: &self.auditor.pubkey(),
            nonce: &nonce,
        }
        .message())
    }

    /// The service's own cluster, key and ring, a reader's signature carries to no other.
    fn read_target(&self) -> ReadTarget {
        ReadTarget {
            cluster: self.shared.genesis_hash,
            service: self.shared.service,
            ring: self.ring,
        }
    }

    pub(crate) async fn authorize<'a>(
        &'a self,
        request: AuditRead<'a>,
    ) -> Result<AuthorizedRead<'a, S>, RingRpcError> {
        let attestation = ReadAttestation {
            read: request.read,
            target: self.read_target(),
            cursor: request.page.cursor.clone(),
            limit: request.page.attested_limit.clone(),
        };
        Ok(AuthorizedRead {
            grant: self.grant(request.auth, &attestation).await?,
            page: request.page,
        })
    }

    /// Refuses a count out of bounds before the signature is checked.
    async fn authorize_utxos<'a>(
        &'a self,
        request: &'a GetAuditedUtxosRequest,
    ) -> Result<AuthorizedUtxos<'a, S>, RingRpcError> {
        if !utxo_hashes_in_bounds(&request.utxo_hashes) {
            return Err(RingRpcError::InvalidUtxoRequest);
        }
        let attestation = AuditedUtxosAttestation::new(self.read_target(), &request.utxo_hashes);
        Ok(AuthorizedUtxos {
            grant: self.grant(&request.auth, &attestation).await?,
            utxo_hashes: &request.utxo_hashes,
        })
    }

    async fn grant<'a>(
        &'a self,
        auth: &ReadAuth,
        attestation: &impl Attestation,
    ) -> Result<Grant<'a, S>, RingRpcError> {
        let ReadClaim { reader, nonce } = ReadCheck {
            auth,
            attestation,
            now: self.shared.clock.now()?,
            origins: &self.shared.origins,
        }
        .decide()?;
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
        Ok(Grant {
            service: self,
            nonce,
            timestamp: auth.timestamp,
            mode: config.mode,
            _reader: permit,
        })
    }

    /// Opens the ring's transfers, audited deposits and anonymous merges from the store's resume point.
    pub async fn backfill_utxos(&self) -> Result<(), RingRpcError> {
        let source = &self.shared.source;
        let Some(config) = source.ring_config(self.ring).await? else {
            return Ok(());
        };
        if config.auditor_pubkey != self.auditor.pubkey() {
            return Err(Unauthorized::AuditorKeyMismatch.into());
        }
        let store = self.shared.store(self.ring);
        let mut cursor = store.backfill.lock().await;
        for _ in 0..MAX_BACKFILL_PAGES {
            let page = Page::new(cursor.clone().map(Base64String), None)?;
            let response = source
                .ring_history(RingHistoryPage {
                    ring: self.ring,
                    page: &page,
                })
                .await?;
            validate_indexer_response(&response, &page, self.view_tag)?;
            // Read after the page, the root every transfer on it proves under is already on chain.
            if config.mode == RingMode::Registry {
                if let Err(error) = self.refresh_escrow(&store).await {
                    log::warn!(
                        "escrow refresh of ring {} failed because {}",
                        self.ring,
                        redacted(&error)
                    );
                }
            }
            let (next, frontier) = (
                response.next_cursor.clone(),
                response.scanned_through.clone(),
            );
            let context = zolana_indexer_api::Context {
                block_time: response.context.block_time,
                slot: response.context.slot,
            };
            self.audit_rows(response, config.mode, &store).await?;
            match frontier {
                Some(frontier) => {
                    store.absorbed(context);
                    *cursor = Some(frontier);
                    return Ok(());
                }
                None => *cursor = next,
            }
        }
        Ok(())
    }

    /// Rereads only the members the writes applied since the last refresh name, else every record.
    async fn refresh_escrow(&self, store: &AuditStore) -> Result<(), RingRpcError> {
        let source = &self.shared.source;
        let Some(registry) = source.ring_chain_status(self.ring).await?.registry else {
            return Ok(());
        };
        let newest = registry
            .history
            .get(usize::from(registry.history_cursor))
            .and_then(Option::as_ref)
            .ok_or(RingRpcError::InvalidIndexerResponse)?;
        let root = EscrowRoot {
            root: newest.root.0,
            applied: newest.applied,
        };
        let current = store.escrow_root();
        // A lagging RPC node answers an older root, the map never moves back to it.
        let settled = current
            .is_some_and(|current| current.root == root.root || root.applied < current.applied);
        if !settled {
            let tip = RegistryTip {
                root: root.root,
                root_index: registry.history_cursor,
                next_index: u64::from(registry.next_index),
            };
            match current.and_then(|current| store.applied_members(current.applied..root.applied)) {
                Some(members) => {
                    store.update_escrow(root, self.reread_members(tip, members).await?)
                }
                None => store.replace_escrow(root, self.rescan_registry(tip).await?),
            }
        }
        if registry.queue_head < registry.queue_tail {
            let queue = source.ring_record_queue(self.ring).await?;
            store.remember_pending(registry.queue_head..registry.queue_tail, &queue.entries);
        }
        Ok(())
    }

    /// Each member's opening under the tip, `None` where it escrows no key.
    async fn reread_members(
        &self,
        tip: RegistryTip,
        members: Vec<[u8; 32]>,
    ) -> Result<Vec<([u8; 32], Option<EscrowedOwner>)>, RingRpcError> {
        let mut reread = Vec::with_capacity(members.len());
        for chunk in members.chunks(MAX_RING_MEMBER_PAGE_LIMIT as usize) {
            let response = self
                .shared
                .source
                .ring_member_openings(GetRingMemberOpeningsRequest {
                    ring_program_id: self.ring.into(),
                    members: chunk.iter().copied().map(Hash).collect(),
                    expected_root: Hash(tip.root),
                })
                .await?;
            if response.openings.len() != chunk.len() {
                return Err(RingRpcError::InvalidIndexerResponse);
            }
            for (member, opening) in chunk.iter().zip(&response.openings) {
                reread.push((*member, escrowed_owner(opening, &tip.root, member)?));
            }
        }
        Ok(reread)
    }

    /// Every record from leaf 1, each verified under the chain-pinned root.
    async fn rescan_registry(
        &self,
        tip: RegistryTip,
    ) -> Result<HashMap<[u8; 32], EscrowedOwner>, RingRpcError> {
        let mut owners = HashMap::new();
        let mut start_index = 1;
        while start_index < tip.next_index {
            let response = self
                .shared
                .source
                .ring_member_records(GetRingMemberRecordsRequest {
                    ring_program_id: self.ring.into(),
                    expected_root: Hash(tip.root),
                    expected_next_index: tip.next_index,
                    start_index,
                    limit: MAX_RING_MEMBER_PAGE_LIMIT,
                })
                .await?;
            if !tip.covers(&response, start_index) {
                return Err(RingRpcError::InvalidIndexerResponse);
            }
            for row in &response.records {
                let opening = RingMemberOpening {
                    present: true,
                    record: row.record.clone(),
                    path: row.path.clone(),
                };
                let member = row.record.member.0;
                if let Some(owner) = escrowed_owner(&opening, &tip.root, &member)? {
                    owners.insert(member, owner);
                }
            }
            start_index = response.next_leaf_index.unwrap_or(tip.next_index);
        }
        Ok(owners)
    }

    fn audit(
        &self,
        bound: BoundTransaction<'_>,
        assets: &AssetRegistry,
    ) -> Result<AuditedTransaction, AuditError> {
        let trees = bound.origin.event.input_tree_ids(bound.transaction);
        let known = bound.store.known();
        TransactionAudit::new(
            bound.transaction,
            bound.origin.disclosure_layout(bound.mode)?,
        )
        .with_input_trees(&trees)?
        .with_known_utxos(&*known)
        .with_escrowed_keys(bound.store)
        .run(&self.auditor, assets)
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
        let context = zolana_indexer_api::Context {
            block_time: response.context.block_time,
            slot: response.context.slot,
        };
        // A frontier ends the read, Photon names the last matched row even on a terminal page.
        let cursor = response
            .next_cursor
            .clone()
            .filter(|_| response.scanned_through.is_none())
            .map(Into::into);
        let rows = self
            .audit_rows(response, mode, &self.shared.store(self.ring))
            .await?;
        Ok(GetDecryptedTransactionsResponse {
            context,
            value: DecryptedTransactionsPage {
                items: rows.items,
                skipped: rows.skipped,
                cursor,
            },
        })
    }

    /// Every opened UTXO enters `store` before the next row, a later input resolves through it.
    async fn audit_rows(
        &self,
        response: GetShieldedTransactionsByTagsResponse,
        mode: RingMode,
        store: &AuditStore,
    ) -> Result<AuditedRows, RingRpcError> {
        let source = &self.shared.source;
        let mut assets = self.shared.cached_assets().await;
        let mut refreshed = false;
        let mut items = Vec::new();
        let mut skipped = Vec::new();
        let mut origins: HashMap<(Signature, u16), RingOrigin> = HashMap::new();
        for mut tx in response.transactions {
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
            if !origin.requires_audit() {
                if origin.ring_invoked {
                    // A later commitment layout spends a deposited or merged UTXO by hash or prefix.
                    let created = origin.bind_transaction(&mut tx, self.ring).and_then(|()| {
                        CreatedUtxos {
                            transaction: &tx,
                            origin: &origin,
                            ring: self.ring,
                        }
                        .open(&self.auditor)
                    });
                    match created {
                        Ok(created) => store.record(
                            CreatedIn {
                                slot: tx.slot,
                                tx_signature: tx.tx_signature,
                                event_index,
                            },
                            created,
                        ),
                        Err(error) => log::warn!(
                            "ring {} event {}:{event_index} opened no UTXOs because {}",
                            self.ring,
                            tx.tx_signature,
                            redacted(&error)
                        ),
                    }
                }
                continue;
            }
            let bound = origin.bind_transaction(&mut tx, self.ring);
            let audit = BoundTransaction {
                transaction: &tx,
                origin: &origin,
                store,
                mode,
            };
            let mut result = bound.and_then(|()| self.audit(audit, &assets));
            let missing_asset = matches!(&result, Ok(opened) if opened.has_unknown_assets());
            // Missing mint preimages affect optional metadata, never verified disclosure.
            if missing_asset && !refreshed {
                refreshed = true;
                if let Ok(updated) = self.shared.refresh_assets().await {
                    assets = updated;
                    result = self.audit(audit, &assets);
                }
            }
            match result {
                Ok(opened) => {
                    store.record(
                        CreatedIn {
                            slot: opened.slot,
                            tx_signature: opened.tx_signature,
                            event_index,
                        },
                        opened.utxos(),
                    );
                    items.push(
                        ConfirmedAudit {
                            audited: opened,
                            event_index,
                            nullifiers: tx.nullifiers,
                            signers: origin.signers,
                            withdrawals: origin.withdrawals,
                        }
                        .into(),
                    )
                }
                Err(reason) => skipped.push(SkippedTransaction {
                    slot: tx.slot,
                    tx_signature: tx.tx_signature.into(),
                    event_index,
                    reason: match reason {
                        AuditError::MissingAuditorMessage => SkippedReason::MissingAuditorMessage,
                        AuditError::UnseenInput { .. } | AuditError::UnseenInputPrefix { .. } => {
                            SkippedReason::UnseenInput
                        }
                        _ => SkippedReason::InvalidAuditData,
                    },
                }),
            }
        }
        Ok(AuditedRows { items, skipped })
    }
}

impl<S> Grant<'_, S> {
    /// The clock is read again, a nonce evicted while the read awaited stays spent.
    fn spend(&self) -> Result<(), RingRpcError> {
        let service = self.service;
        Ok(service.shared.replay.accept(ReplayCheck {
            ring: service.ring,
            nonce: self.nonce,
            timestamp: self.timestamp,
            now: service.shared.clock.now()?,
        })?)
    }
}

impl<S: TransactionSource> AuthorizedRead<'_, S> {
    pub(crate) async fn execute(self) -> Result<GetDecryptedTransactionsResponse, RingRpcError> {
        let service = self.grant.service;
        self.grant.spend()?;
        service
            .decrypted_transactions(self.page, self.grant.mode)
            .await
    }

    pub(crate) async fn execute_merges(self) -> Result<GetAuditedMergesResponse, RingRpcError> {
        let service = self.grant.service;
        self.grant.spend()?;
        let page = service
            .shared
            .source
            .merge_audit_page(MergeAuditRequest {
                ring: service.ring,
                auditor: &service.auditor,
                page: self.page,
            })
            .await
            .map_err(|error| match error {
                AuditError::ScanFrontierMissing => RingRpcError::InvalidIndexerResponse,
                error => error.into(),
            })?;
        validate_merge_page(&page, self.page)?;
        Ok(page.into())
    }
}

impl<S: TransactionSource> AuthorizedUtxos<'_, S> {
    /// The store answers alone, a UTXO no page or backfill opened yet reads `null`.
    fn execute(self) -> Result<GetAuditedUtxosResponse, RingRpcError> {
        let service = self.grant.service;
        self.grant.spend()?;
        let store = service.shared.store(service.ring);
        Ok(GetAuditedUtxosResponse {
            context: store.context(),
            value: AuditedUtxosPage {
                utxos: self
                    .utxo_hashes
                    .iter()
                    .map(|hash| store.view(hash))
                    .collect(),
            },
        })
    }
}

/// The escrowed key of a record verified under `root`, `None` while its member holds none.
fn escrowed_owner(
    opening: &RingMemberOpening,
    root: &[u8; 32],
    member: &[u8; 32],
) -> Result<Option<EscrowedOwner>, RingRpcError> {
    let invalid = |_| RingRpcError::InvalidIndexerResponse;
    let read = MemberOpeningRead::verify(opening, root, member).map_err(invalid)?;
    let Some(owner) = read.owner_pubkey else {
        return Ok(None);
    };
    let Some(nullifier_pk) = read.nullifier_pk else {
        return Ok(None);
    };
    if read.sealed.is_none() {
        return Ok(None);
    }
    // The record binds the owner key through its member identity.
    let bound = Member::owner_tag(owner.as_array()).is_ok_and(|tag| tag.as_bytes() == member);
    let escrowed = read.escrowed(&nullifier_pk).map_err(invalid)?;
    if escrowed.is_none() || !bound {
        return Err(RingRpcError::InvalidIndexerResponse);
    }
    Ok(Some(EscrowedOwner {
        owner_key: owner.to_bytes(),
        nullifier_pk,
    }))
}

fn validate_merge_page(page: &MergeAuditPage, request: &Page) -> Result<(), RingRpcError> {
    let rows = page.result.opened.len() + page.result.unresolved.len();
    if rows > request.limit.get() as usize
        || page
            .next_cursor
            .as_deref()
            .is_some_and(|cursor| !cursor_in_bounds(cursor) || request.cursor() == Some(cursor))
    {
        return Err(RingRpcError::InvalidIndexerResponse);
    }
    Ok(())
}

fn validate_indexer_response(
    response: &GetShieldedTransactionsByTagsResponse,
    page: &Page,
    auditor_tag: [u8; 32],
) -> Result<(), RingRpcError> {
    let next = response.next_cursor.as_deref();
    let frontier = response.scanned_through.as_deref();
    if response.transactions.len() > page.limit.get() as usize
        || next.or(frontier).is_none()
        || next.is_some_and(|cursor| !cursor_in_bounds(cursor) || page.cursor() == Some(cursor))
        || frontier.is_some_and(|cursor| {
            !cursor_in_bounds(cursor) || response.transactions.len() >= page.limit.get() as usize
        })
    {
        return Err(RingRpcError::InvalidIndexerResponse);
    }
    // Compact padding leaves trailing slots out, a transaction publishes at most its shape.
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

#[cfg(test)]
mod tests {
    use zolana_indexer_api::Context;
    use zolana_ring_client::{MergeAuditResult, UnresolvedMerge};

    use super::*;

    #[test]
    fn merge_page_rejects_an_unchanged_cursor_and_extra_rows() {
        let request = Page::new(Some(Base64String(vec![7])), Some(Limit::new(1).unwrap())).unwrap();
        let mut response = MergeAuditPage {
            context: Context {
                slot: 1,
                block_time: 1,
            },
            result: MergeAuditResult::default(),
            next_cursor: Some(vec![7]),
        };
        assert!(matches!(
            validate_merge_page(&response, &request),
            Err(RingRpcError::InvalidIndexerResponse)
        ));
        response.next_cursor = Some(vec![8]);
        let unresolved = UnresolvedMerge {
            tx_signature: Signature::from([3; 64]),
            event_index: 0,
            output_commitment: [1; 32],
        };
        response.result.unresolved.push(unresolved);
        assert!(validate_merge_page(&response, &request).is_ok());
        response.result.unresolved.push(UnresolvedMerge {
            tx_signature: Signature::from([4; 64]),
            event_index: 0,
            output_commitment: [2; 32],
        });
        assert!(matches!(
            validate_merge_page(&response, &request),
            Err(RingRpcError::InvalidIndexerResponse)
        ));
    }
}
