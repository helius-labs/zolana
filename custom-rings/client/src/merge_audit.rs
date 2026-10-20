//! Opens every confirmed ring merge with keys authenticated by the member registry.
//! A registry leaf names only the owner's proof hash, so this API returns raw
//! openings. A wallet that knows the signing key can turn one into a spendable note.

use std::{
    collections::HashSet,
    num::{NonZeroU32, NonZeroUsize},
};

use custom_ring_interface::{
    EscrowKey, MemberOpening, MemberRecord, MemberRegistryRoot, MerklePath, RingAccount,
    MEMBER_REGISTRY_CAPACITY,
};
use solana_address::Address;
use solana_signature::Signature;
use zolana_client::{
    next_page, AsyncRpc, GetShieldedTransactionsByTagsResponse, IndexerRpcConfig, ProofInputUtxo,
    RingHistoryOptions, ShieldedTransaction,
};
use zolana_event::{
    merge_output::MERGE_OUTPUT_SALT_LEN, split_merge_output_body, OutputDataEncoding,
    MERGE_OUTPUT_BODY_LEN, MERGE_OUTPUT_SCHEME,
};
use zolana_hasher::{primitives::is_canonical_bn254_scalar_be, Hasher, Poseidon};
use zolana_indexer_api::{
    Context, GetRingMemberRecordsRequest, GetRingMemberRecordsResponse, Hash, SerializablePubkey,
    MAX_RING_MEMBER_PAGE_LIMIT,
};
use zolana_interface::instruction::instruction_data::merge_transact::merge_circuit_width;
use zolana_keypair::{NullifierKey, X25519Keypair, X25519Pubkey};
use zolana_ring_policy::Member;
use zolana_transaction::instructions::merge::{
    merge_output_blinding, merge_output_key, MergeOutputPlaintext,
};

use crate::{
    encryption::{open_merge_disclosure, MergeOpening, SealedNullifierKey},
    origin::{ConfirmedEventKind, ConfirmedMergeDisclosure, TransactionOrigin},
    AuditError,
};

const DEFAULT_PAGE_SIZE: NonZeroU32 = NonZeroU32::new(1000).unwrap();
const DEFAULT_MAX_PAGES: NonZeroUsize = NonZeroUsize::new(4096).unwrap();
const DEFAULT_MAX_MEMBER_PAGES: NonZeroUsize =
    NonZeroUsize::new((MEMBER_REGISTRY_CAPACITY - 1).div_ceil(MAX_RING_MEMBER_PAGE_LIMIT) as usize)
        .unwrap();

/// One merge output whose raw amount, mint and blinding reproduce its settled leaf.
pub struct AuditedMerge {
    pub tx_signature: Signature,
    pub event_index: u16,
    pub output_commitment: [u8; 32],
    pub owner_member: [u8; 32],
    /// RegisterKey's confirmed signer tag, absent in older indexer projections.
    /// The merge proof does not disclose whether the shielded key used Ed25519 or a PDA.
    pub owner_pubkey: Option<Address>,
    pub mint: Address,
    pub amount: u64,
    pub blinding: [u8; 32],
    pub ring_data_hash: [u8; 32],
    pub input_nullifiers: Vec<[u8; 32]>,
    pub keys: MergeKeys,
}

/// What the auditor holds of the merge owner beyond the opening.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeKeys {
    /// The registry escrow opened the nullifier key, the merged note's nullifier follows.
    Escrowed { nullifier: [u8; 32] },
    /// An anonymous merge disclosed every spent commitment, padding zero, the nullifier key stays hidden.
    Disclosed { input_commitments: Vec<[u8; 32]> },
}

/// A confirmed merge that no authenticated current registration opened.
/// It remains visible rather than disappearing from the audit result.
pub struct UnresolvedMerge {
    pub tx_signature: Signature,
    pub event_index: u16,
    pub output_commitment: [u8; 32],
}

#[derive(Default)]
pub struct MergeAuditResult {
    pub opened: Vec<AuditedMerge>,
    pub unresolved: Vec<UnresolvedMerge>,
}

/// One bounded history page. The cursor belongs to the ring-history scan,
/// including non-merge rows the page examined.
pub struct MergeAuditPage {
    pub context: Context,
    pub result: MergeAuditResult,
    pub next_cursor: Option<Vec<u8>>,
}

/// Scans ring history and opens merges using authenticated auditor keys.
/// Registry keys are final, so the current authenticated leaves cover earlier
/// merges. The ciphertext carries no owner hint, so an unresolved output may
/// require trying every registered key. A changed root or incomplete scan
/// aborts instead of returning partial coverage.
#[must_use = "run or discard the merge audit explicitly"]
pub struct MergeAudit<'a> {
    ring: Address,
    auditor: &'a X25519Keypair,
    cursor: Option<Vec<u8>>,
    page_size: NonZeroU32,
    max_pages: NonZeroUsize,
    max_member_pages: NonZeroUsize,
    max_candidate_attempts: Option<NonZeroUsize>,
    indexer_config: Option<IndexerRpcConfig>,
}

struct RegisteredKey {
    member: [u8; 32],
    owner_pubkey: Option<Address>,
    key: NullifierKey,
}

struct MergeFields {
    mint: Address,
    amount: u64,
    blinding: [u8; 32],
    nullifier: [u8; 32],
}

/// A confirmed output retains only the data needed to try one registered key.
/// The history page bounds this vector, while registry keys are discarded after use.
struct PendingMerge {
    tx_signature: Signature,
    event_index: u16,
    output_commitment: [u8; 32],
    tree_id: u16,
    ring_data_hash: [u8; 32],
    first_nullifier: [u8; 32],
    input_nullifiers: Vec<[u8; 32]>,
    encrypted: Vec<u8>,
    opened: Option<AuditedMerge>,
}

impl PendingMerge {
    fn try_open(&mut self, registered: &RegisteredKey, ring: Address) -> Result<(), AuditError> {
        if self.opened.is_some() {
            return Ok(());
        }
        let Some(fields) = open_candidate(
            registered,
            &self.first_nullifier,
            &self.encrypted,
            self.output_commitment,
            self.tree_id,
            self.ring_data_hash,
            ring,
        )?
        else {
            return Ok(());
        };
        self.opened = Some(AuditedMerge {
            tx_signature: self.tx_signature,
            event_index: self.event_index,
            output_commitment: self.output_commitment,
            owner_member: registered.member,
            owner_pubkey: registered.owner_pubkey,
            mint: fields.mint,
            amount: fields.amount,
            blinding: fields.blinding,
            ring_data_hash: self.ring_data_hash,
            input_nullifiers: self.input_nullifiers.clone(),
            keys: MergeKeys::Escrowed {
                nullifier: fields.nullifier,
            },
        });
        Ok(())
    }
}

impl<'a> MergeAudit<'a> {
    pub fn new(ring: Address, auditor: &'a X25519Keypair) -> Self {
        Self {
            ring,
            auditor,
            cursor: None,
            page_size: DEFAULT_PAGE_SIZE,
            max_pages: DEFAULT_MAX_PAGES,
            max_member_pages: DEFAULT_MAX_MEMBER_PAGES,
            max_candidate_attempts: None,
            indexer_config: None,
        }
    }

    pub fn with_page_size(mut self, page_size: NonZeroU32) -> Self {
        self.page_size = page_size;
        self
    }

    pub fn with_cursor(mut self, cursor: Option<Vec<u8>>) -> Self {
        self.cursor = cursor;
        self
    }

    pub fn with_max_pages(mut self, max_pages: NonZeroUsize) -> Self {
        self.max_pages = max_pages;
        self
    }

    pub fn with_max_member_pages(mut self, max_member_pages: NonZeroUsize) -> Self {
        self.max_member_pages = max_member_pages;
        self
    }

    /// Fail closed before trying more than this many key/output pairs. The
    /// default scans the complete registry, so offline callers can exhaustively
    /// audit a large ring. An RPC server can set a smaller per-request budget.
    pub fn with_max_candidate_attempts(mut self, limit: NonZeroUsize) -> Self {
        self.max_candidate_attempts = Some(limit);
        self
    }

    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.indexer_config = Some(config);
        self
    }

    pub async fn run<I: AsyncRpc, O: TransactionOrigin>(
        self,
        indexer: &I,
        origin: &O,
    ) -> Result<MergeAuditResult, AuditError> {
        let registry = self.registry_root(indexer).await?;
        let mut cursor = self.cursor.clone();
        let mut result = MergeAuditResult::default();
        let mut seen = HashSet::new();
        for _ in 0..self.max_pages.get() {
            let (response, next_cursor) = self.read_history_page(indexer, &cursor).await?;
            let page = self
                .open_transactions(response.transactions, &registry, indexer, origin, &mut seen)
                .await?;
            result.opened.extend(page.opened);
            result.unresolved.extend(page.unresolved);
            if next_cursor.is_none() {
                return Ok(result);
            }
            cursor = next_cursor;
        }
        Err(AuditError::IncompleteScan)
    }

    /// Open one ring-history page for an authenticated RPC reader.
    pub async fn page<I: AsyncRpc, O: TransactionOrigin>(
        self,
        indexer: &I,
        origin: &O,
    ) -> Result<MergeAuditPage, AuditError> {
        let registry = self.registry_root(indexer).await?;
        let (response, next_cursor) = self.read_history_page(indexer, &self.cursor).await?;
        let mut seen = HashSet::new();
        let result = self
            .open_transactions(response.transactions, &registry, indexer, origin, &mut seen)
            .await?;
        Ok(MergeAuditPage {
            context: Context {
                slot: response.context.slot,
                block_time: response.context.block_time,
            },
            result,
            next_cursor,
        })
    }

    async fn read_history_page<I: AsyncRpc>(
        &self,
        indexer: &I,
        cursor: &Option<Vec<u8>>,
    ) -> Result<(GetShieldedTransactionsByTagsResponse, Option<Vec<u8>>), AuditError> {
        let response = indexer
            .get_shielded_transactions_by_ring(
                RingHistoryOptions {
                    ring_program_id: self.ring,
                    cursor: cursor.clone(),
                    limit: Some(self.page_size.get()),
                },
                self.indexer_config,
            )
            .await?;
        if response.transactions.len() > self.page_size.get() as usize {
            return Err(AuditError::IncompleteScan);
        }
        let next_cursor = next_page(
            cursor,
            response.next_cursor.clone(),
            &response.scanned_through,
        )?;
        Ok((response, next_cursor))
    }

    async fn open_transactions<I: AsyncRpc, O: TransactionOrigin>(
        &self,
        transactions: Vec<ShieldedTransaction>,
        registry: &MemberRegistryRoot,
        indexer: &I,
        origin: &O,
        seen: &mut HashSet<(Signature, u16)>,
    ) -> Result<MergeAuditResult, AuditError> {
        let mut pending = Vec::new();
        let mut disclosed = Vec::new();
        for mut tx in transactions {
            let event_index = tx.event_index.ok_or(AuditError::MissingEventIndex)?;
            let confirmed = origin
                .origin(tx.tx_signature, event_index, self.ring)
                .await?;
            if !confirmed.ring_invoked || confirmed.event.kind() != ConfirmedEventKind::Merge {
                continue;
            }
            confirmed.bind_transaction(&mut tx, self.ring)?;
            remember_merge(seen, tx.tx_signature, event_index)?;
            let slot = tx.output_slots.first().ok_or_else(invalid_merge)?;
            let first_nullifier = tx.nullifiers.first().ok_or_else(invalid_merge)?;
            if tx.output_slots.len() != 1 || merge_circuit_width(tx.nullifiers.len()).is_none() {
                return Err(invalid_merge());
            }
            let Some(OutputDataEncoding::VerifiablyEncrypted(blob)) = slot.output_data() else {
                return Err(invalid_merge());
            };
            let Some((&MERGE_OUTPUT_SCHEME, body)) = blob.split_first() else {
                return Err(invalid_merge());
            };
            let Some((Some(&ring_data_hash), encrypted)) = split_merge_output_body(body) else {
                return Err(invalid_merge());
            };
            validate_confirmed_merge_fields(
                first_nullifier,
                &slot.output_context.hash,
                &ring_data_hash,
                encrypted,
            )?;
            if let Some(disclosure) = &confirmed.merge_disclosure {
                let opening = open_disclosed(self.auditor, disclosure, encrypted)?;
                if opening.input_commitments.len()
                    != merge_circuit_width(tx.nullifiers.len()).unwrap_or_default()
                {
                    return Err(invalid_merge());
                }
                let owner_member = *Member::owner_tag(&opening.owner_key)?.as_bytes();
                let mint = Address::new_from_array(opening.mint);
                let owner_hash = Poseidon::hashv(&[&owner_member, &opening.nullifier_pk])?;
                let commitment = ProofInputUtxo::new(
                    owner_hash,
                    &mint,
                    opening.amount,
                    &opening.output_blinding,
                    slot.output_context.tree_id,
                )?
                .with_ring(ring_data_hash, &Some(self.ring))?
                .hash()?;
                if commitment != slot.output_context.hash {
                    return Err(AuditError::MergeDisclosureMismatch);
                }
                disclosed.push(AuditedMerge {
                    tx_signature: tx.tx_signature,
                    event_index,
                    output_commitment: commitment,
                    owner_member,
                    owner_pubkey: Some(Address::new_from_array(opening.owner_key)),
                    mint,
                    amount: opening.amount,
                    blinding: opening.output_blinding,
                    ring_data_hash,
                    input_nullifiers: tx.nullifiers,
                    keys: MergeKeys::Disclosed {
                        input_commitments: opening.input_commitments,
                    },
                });
                continue;
            }
            pending.push(PendingMerge {
                tx_signature: tx.tx_signature,
                event_index,
                output_commitment: slot.output_context.hash,
                tree_id: slot.output_context.tree_id,
                ring_data_hash,
                first_nullifier: *first_nullifier,
                input_nullifiers: tx.nullifiers,
                encrypted: encrypted.to_vec(),
                opened: None,
            });
        }
        if pending.is_empty() {
            return Ok(MergeAuditResult {
                opened: disclosed,
                unresolved: Vec::new(),
            });
        }
        let mut attempts = 0;
        self.scan_registry(indexer, registry, |registered| {
            try_registered_key(
                &mut pending,
                registered,
                self.ring,
                &mut attempts,
                self.max_candidate_attempts,
            )
        })
        .await?;
        let mut result = MergeAuditResult {
            opened: disclosed,
            unresolved: Vec::new(),
        };
        for merge in pending {
            if let Some(opened) = merge.opened {
                result.opened.push(opened);
            } else {
                result.unresolved.push(UnresolvedMerge {
                    tx_signature: merge.tx_signature,
                    event_index: merge.event_index,
                    output_commitment: merge.output_commitment,
                });
            }
        }
        Ok(result)
    }

    async fn registry_root<I: AsyncRpc>(
        &self,
        indexer: &I,
    ) -> Result<MemberRegistryRoot, AuditError> {
        let (pda, bump) = Address::find_program_address(&[MemberRegistryRoot::SEED], &self.ring);
        let account = indexer
            .get_account(pda)
            .await?
            .ok_or(AuditError::InvalidMemberRegistry)?;
        let state = MemberRegistryRoot::decode(&account.owner, &self.ring, &account.data)
            .filter(|state| state.bump == bump && state.next_index() <= MEMBER_REGISTRY_CAPACITY)
            .ok_or(AuditError::InvalidMemberRegistry)?;
        state.root().ok_or(AuditError::InvalidMemberRegistry)?;
        Ok(state)
    }

    /// Authenticate leaves at one chain-pinned root until every merge opens or
    /// the registry ends. The caller may stop only after it has authenticated
    /// a key that opens each settled output.
    async fn scan_registry<I: AsyncRpc>(
        &self,
        indexer: &I,
        state: &MemberRegistryRoot,
        mut visit: impl FnMut(&RegisteredKey) -> Result<bool, AuditError>,
    ) -> Result<(), AuditError> {
        let root = state.root().ok_or(AuditError::InvalidMemberRegistry)?;
        let next_index = state.next_index();
        let mut start_index = 1;
        let mut pages_read = 0;
        while start_index < next_index {
            if pages_read == self.max_member_pages.get() {
                return Err(AuditError::MergeAuditWorkBudget);
            }
            let response = indexer
                .get_ring_member_records(GetRingMemberRecordsRequest {
                    ring_program_id: SerializablePubkey(self.ring),
                    expected_root: Hash(root),
                    expected_next_index: next_index,
                    start_index,
                    limit: MAX_RING_MEMBER_PAGE_LIMIT,
                })
                .await?;
            if !complete_member_page(
                &response,
                &root,
                state.history_cursor,
                next_index,
                start_index,
            ) {
                return Err(AuditError::InvalidMemberRegistry);
            }
            for row in response.records {
                let member = row.record.member.0;
                let owner_pubkey = row
                    .record
                    .owner_pubkey
                    .map(|pubkey| Address::new_from_array(pubkey.0.to_bytes()));
                if owner_pubkey.is_some_and(|owner| {
                    Member::owner_tag(owner.as_array())
                        .map(|tag| *tag.as_bytes() != member)
                        .unwrap_or(true)
                }) {
                    return Err(AuditError::InvalidMemberRegistry);
                }
                let path: Vec<_> = row.path.into_iter().map(|hash| hash.0).collect();
                let record = MemberRecord {
                    member,
                    next: row.record.next.0,
                    lists: row.record.lists,
                    escrow_key: row.record.escrow_key.0,
                };
                MemberOpening::Present {
                    record,
                    path: MerklePath {
                        index: row.index,
                        siblings: &path,
                    },
                }
                .verify(&root, &member)
                .map_err(|_| AuditError::InvalidMemberRegistry)?;
                if record.escrow_key != [0; 32] {
                    let (Some(eph_pk), Some(ciphertext)) =
                        (row.record.eph_pk, row.record.ciphertext)
                    else {
                        return Err(AuditError::InvalidMemberRegistry);
                    };
                    let eph_pk: [u8; 33] = eph_pk
                        .0
                        .try_into()
                        .map_err(|_| AuditError::InvalidMemberRegistry)?;
                    let ciphertext: [u8; 32] = ciphertext
                        .0
                        .try_into()
                        .map_err(|_| AuditError::InvalidMemberRegistry)?;
                    let sealed = SealedNullifierKey {
                        eph_pk: X25519Pubkey::from_bytes(eph_pk)?,
                        ciphertext,
                    };
                    let key = sealed.open(self.auditor)?;
                    let escrow_hash = EscrowKey {
                        nullifier_pk: &key.pubkey()?,
                        ciphertext: &sealed.ciphertext,
                    }
                    .hash()?;
                    if escrow_hash != record.escrow_key {
                        return Err(AuditError::InvalidMemberRegistry);
                    }
                    let complete = visit(&RegisteredKey {
                        member,
                        owner_pubkey,
                        key,
                    })?;
                    if complete {
                        return Ok(());
                    }
                }
                start_index += 1;
            }
            pages_read += 1;
        }
        Ok(())
    }
}

fn try_registered_key(
    pending: &mut [PendingMerge],
    registered: &RegisteredKey,
    ring: Address,
    attempts: &mut usize,
    limit: Option<NonZeroUsize>,
) -> Result<bool, AuditError> {
    for merge in pending.iter_mut().filter(|merge| merge.opened.is_none()) {
        if limit.is_some_and(|limit| *attempts >= limit.get()) {
            return Err(AuditError::MergeAuditWorkBudget);
        }
        *attempts += 1;
        merge.try_open(registered, ring)?;
    }
    // Each opening is checked against the settled commitment. Later leaves
    // cannot change the result once every merge opened.
    Ok(pending.iter().all(|merge| merge.opened.is_some()))
}

/// A short, oversized or gapped page cannot silently reduce registry coverage.
fn complete_member_page(
    response: &GetRingMemberRecordsResponse,
    root: &[u8; 32],
    root_index: u8,
    next_index: u64,
    start_index: u64,
) -> bool {
    if start_index >= next_index {
        return false;
    }
    let end_index = start_index + (next_index - start_index).min(MAX_RING_MEMBER_PAGE_LIMIT);
    response.root.0 == *root
        && response.root_index == root_index
        && response.next_index == next_index
        && response.records.len() == (end_index - start_index) as usize
        && response
            .records
            .iter()
            .enumerate()
            .all(|(offset, row)| row.index == start_index + offset as u64)
        && response.next_leaf_index == (end_index < next_index).then_some(end_index)
}

/// Malformed fields in a confirmed output are an audit error, not a key miss.
/// Once these public fields are valid, a failed candidate commitment can only
/// be caused by decrypted data that does not belong to that registered key.
fn validate_confirmed_merge_fields(
    first_nullifier: &[u8; 32],
    output_commitment: &[u8; 32],
    ring_data_hash: &[u8; 32],
    encrypted: &[u8],
) -> Result<(), AuditError> {
    if !is_canonical_bn254_scalar_be(first_nullifier)
        || !is_canonical_bn254_scalar_be(output_commitment)
        || !is_canonical_bn254_scalar_be(ring_data_hash)
        || encrypted.len() != MERGE_OUTPUT_BODY_LEN
        || encrypted[MERGE_OUTPUT_SALT_LEN..]
            .as_chunks::<32>()
            .0
            .iter()
            .any(|chunk| !is_canonical_bn254_scalar_be(chunk))
    {
        return Err(invalid_merge());
    }
    Ok(())
}

/// The ciphertext is unauthenticated by itself. Only the settled commitment
/// decides whether an opened amount and mint belong to this member.
fn open_candidate(
    registered: &RegisteredKey,
    first_nullifier: &[u8; 32],
    encrypted: &[u8],
    output_commitment: [u8; 32],
    tree_id: u16,
    ring_data_hash: [u8; 32],
    ring: Address,
) -> Result<Option<MergeFields>, AuditError> {
    let key = merge_output_key(&registered.key, first_nullifier)?;
    let Ok(plain) = MergeOutputPlaintext::decrypt(encrypted, &key) else {
        return Ok(None);
    };
    let blinding = merge_output_blinding(&registered.key, first_nullifier)?;
    let owner_hash = Poseidon::hashv(&[&registered.member, &registered.key.pubkey()?])?;
    let Ok(output) = ProofInputUtxo::new(owner_hash, &plain.mint, plain.amount, &blinding, tree_id)
    else {
        return Ok(None);
    };
    let Ok(output) = output.with_ring(ring_data_hash, &Some(ring)) else {
        return Ok(None);
    };
    let Ok(expected) = output.hash() else {
        return Ok(None);
    };
    if expected != output_commitment {
        return Ok(None);
    }
    Ok(Some(MergeFields {
        mint: plain.mint,
        amount: plain.amount,
        blinding,
        nullifier: registered.key.nullifier(&output_commitment, &blinding)?,
    }))
}

/// The ring verified the disclosure proof, so the salt is the SPP merge output salt it binds.
fn open_disclosed(
    auditor: &X25519Keypair,
    disclosure: &ConfirmedMergeDisclosure,
    encrypted: &[u8],
) -> Result<MergeOpening, AuditError> {
    let salt = encrypted
        .first_chunk::<MERGE_OUTPUT_SALT_LEN>()
        .ok_or_else(invalid_merge)?;
    open_merge_disclosure(
        auditor,
        &X25519Pubkey::from_bytes(disclosure.eph_pk)?,
        &disclosure.ciphertext,
        *salt,
        &disclosure.fields,
    )
}

fn invalid_merge() -> AuditError {
    AuditError::InvalidConfirmedEvent("ring merge output is malformed".to_owned())
}

fn remember_merge(
    seen: &mut HashSet<(Signature, u16)>,
    signature: Signature,
    event_index: u16,
) -> Result<(), AuditError> {
    if !seen.insert((signature, event_index)) {
        return Err(AuditError::InvalidConfirmedEvent(
            "duplicate confirmed ring merge".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use zolana_hasher::primitives::right_align;
    use zolana_indexer_api::{Base64String, RingIndexedMemberRecordView, RingMemberRecordView};
    use zolana_ring_member_registry::MemberRegistryTree;

    struct RegistryPages {
        first: GetRingMemberRecordsResponse,
        requests: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl AsyncRpc for RegistryPages {
        async fn get_ring_member_records(
            &self,
            request: GetRingMemberRecordsRequest,
        ) -> Result<GetRingMemberRecordsResponse, zolana_client::ClientError> {
            self.requests.fetch_add(1, Ordering::Relaxed);
            if request.start_index != 1 {
                return Err(zolana_client::ClientError::Indexer(
                    "unexpected second registry page".to_owned(),
                ));
            }
            Ok(self.first.clone())
        }
    }

    #[tokio::test]
    async fn authenticated_opening_stops_before_unneeded_registry_pages() {
        let ring = Address::new_from_array([9; 32]);
        let auditor = X25519Keypair::new();
        let key = NullifierKey::from_secret([7; 31]);
        let envelope = crate::NullifierKeyEnvelope::new(&key, &auditor.pubkey()).unwrap();
        let escrow_key = EscrowKey {
            nullifier_pk: &envelope.nullifier_pk,
            ciphertext: &envelope.sealed.ciphertext,
        }
        .hash()
        .unwrap();
        let mut tree = MemberRegistryTree::new().unwrap();
        for index in 1u64..=101 {
            let member = right_align(&index.to_be_bytes());
            let item = tree
                .register_item(&member, if index == 1 { escrow_key } else { [0; 32] })
                .unwrap();
            tree.apply(&[item]).unwrap();
        }
        let records = (1..=100)
            .map(|index| {
                let record = tree.records()[index];
                let sealed = (index == 1).then_some(&envelope.sealed);
                RingIndexedMemberRecordView {
                    index: index as u64,
                    record: RingMemberRecordView {
                        member: Hash(record.member),
                        next: Hash(record.next),
                        lists: record.lists,
                        escrow_key: Hash(record.escrow_key),
                        owner_pubkey: None,
                        eph_pk: sealed
                            .map(|sealed| Base64String(sealed.eph_pk.as_bytes().to_vec())),
                        ciphertext: sealed.map(|sealed| Base64String(sealed.ciphertext.to_vec())),
                    },
                    path: tree
                        .path(index as u64)
                        .unwrap()
                        .into_iter()
                        .map(Hash)
                        .collect(),
                }
            })
            .collect();
        let mut history = [[0; 32]; custom_ring_interface::MEMBER_REGISTRY_ROOT_HISTORY];
        history[0] = tree.root();
        let state = MemberRegistryRoot {
            discriminator: 0,
            next_index: tree.next_index().to_le_bytes(),
            bump: 0,
            history_cursor: 0,
            history,
        };
        let pages = RegistryPages {
            first: GetRingMemberRecordsResponse {
                context: Context::default(),
                root: Hash(tree.root()),
                root_index: 0,
                next_index: tree.next_index(),
                records,
                next_leaf_index: Some(101),
            },
            requests: AtomicUsize::new(0),
        };
        MergeAudit::new(ring, &auditor)
            .scan_registry(&pages, &state, |registered| {
                assert_eq!(registered.key.secret(), key.secret());
                Ok(true)
            })
            .await
            .unwrap();
        assert_eq!(pages.requests.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn member_page_must_be_complete_and_contiguous() {
        let root = [4; 32];
        let record = RingMemberRecordView {
            member: Hash([1; 32]),
            next: Hash([2; 32]),
            lists: 0,
            escrow_key: Hash([0; 32]),
            owner_pubkey: None,
            eph_pk: None,
            ciphertext: None,
        };
        let mut response = GetRingMemberRecordsResponse {
            context: Context {
                slot: 1,
                block_time: 0,
            },
            root: Hash(root),
            root_index: 7,
            next_index: 8,
            records: (5..8)
                .map(|index| RingIndexedMemberRecordView {
                    index,
                    record: record.clone(),
                    path: Vec::new(),
                })
                .collect(),
            next_leaf_index: None,
        };
        assert!(complete_member_page(&response, &root, 7, 8, 5));
        response.records[1].index = 8;
        assert!(!complete_member_page(&response, &root, 7, 8, 5));
        response.records[1].index = 6;
        response.records.pop();
        assert!(!complete_member_page(&response, &root, 7, 8, 5));
        response.records.push(RingIndexedMemberRecordView {
            index: 7,
            record,
            path: Vec::new(),
        });
        response.next_leaf_index = Some(8);
        assert!(!complete_member_page(&response, &root, 7, 8, 5));
        response.next_leaf_index = None;
        response.root = Hash([9; 32]);
        assert!(!complete_member_page(&response, &root, 7, 8, 5));
    }

    #[test]
    fn default_member_page_cap_covers_the_full_registry() {
        let capacity = MEMBER_REGISTRY_CAPACITY - 1;
        let covered = DEFAULT_MAX_MEMBER_PAGES.get() as u64 * MAX_RING_MEMBER_PAGE_LIMIT;
        assert!(covered >= capacity);
        assert!(covered - MAX_RING_MEMBER_PAGE_LIMIT < capacity);
    }

    #[test]
    fn a_confirmed_merge_cannot_be_counted_twice_across_history_pages() {
        let mut seen = HashSet::new();
        let signature = Signature::default();
        remember_merge(&mut seen, signature, 1).unwrap();
        remember_merge(&mut seen, signature, 2).unwrap();
        assert!(matches!(
            remember_merge(&mut seen, signature, 1),
            Err(AuditError::InvalidConfirmedEvent(_))
        ));
    }

    #[test]
    fn merge_opening_requires_the_registered_key_and_settled_commitment() {
        let ring = Address::new_from_array([9; 32]);
        let mint = Address::new_from_array([3; 32]);
        let registered = RegisteredKey {
            member: Poseidon::hashv(&[&right_align(&[7; 1])]).unwrap(),
            owner_pubkey: None,
            key: NullifierKey::from_secret([4; 31]),
        };
        let first_nullifier = [5; 32];
        let salt = [6; 16];
        let ciphertext = MergeOutputPlaintext { amount: 8, mint }
            .encrypt(
                &merge_output_key(&registered.key, &first_nullifier).unwrap(),
                &salt,
            )
            .unwrap();
        let mut encrypted = salt.to_vec();
        for element in ciphertext {
            encrypted.extend_from_slice(&element);
        }
        validate_confirmed_merge_fields(&first_nullifier, &[0; 32], &[1; 32], &encrypted).unwrap();
        let mut malformed = encrypted.clone();
        malformed[MERGE_OUTPUT_SALT_LEN..MERGE_OUTPUT_SALT_LEN + 32].fill(0xff);
        assert!(matches!(
            validate_confirmed_merge_fields(&first_nullifier, &[0; 32], &[1; 32], &malformed),
            Err(AuditError::InvalidConfirmedEvent(_))
        ));
        assert!(matches!(
            validate_confirmed_merge_fields(&first_nullifier, &[0; 32], &[0xff; 32], &encrypted),
            Err(AuditError::InvalidConfirmedEvent(_))
        ));
        let blinding = merge_output_blinding(&registered.key, &first_nullifier).unwrap();
        let owner_hash =
            Poseidon::hashv(&[&registered.member, &registered.key.pubkey().unwrap()]).unwrap();
        let commitment = ProofInputUtxo::new(owner_hash, &mint, 8, &blinding, 0)
            .unwrap()
            .with_ring([1; 32], &Some(ring))
            .unwrap()
            .hash()
            .unwrap();
        let opened = open_candidate(
            &registered,
            &first_nullifier,
            &encrypted,
            commitment,
            0,
            [1; 32],
            ring,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            (opened.mint, opened.amount, opened.blinding),
            (mint, 8, blinding)
        );
        assert_eq!(
            opened.nullifier,
            registered.key.nullifier(&commitment, &blinding).unwrap()
        );
        assert!(open_candidate(
            &registered,
            &first_nullifier,
            &encrypted,
            [2; 32],
            0,
            [1; 32],
            ring
        )
        .unwrap()
        .is_none());
        let wrong_key = RegisteredKey {
            member: registered.member,
            owner_pubkey: None,
            key: NullifierKey::from_secret([8; 31]),
        };
        assert!(open_candidate(
            &wrong_key,
            &first_nullifier,
            &encrypted,
            commitment,
            0,
            [1; 32],
            ring
        )
        .unwrap()
        .is_none());
        for secret in 8..40 {
            let wrong_key = RegisteredKey {
                member: registered.member,
                owner_pubkey: None,
                key: NullifierKey::from_secret([secret; 31]),
            };
            assert!(open_candidate(
                &wrong_key,
                &first_nullifier,
                &encrypted,
                commitment,
                0,
                [1; 32],
                ring
            )
            .unwrap()
            .is_none());
        }

        let mut pending = PendingMerge {
            tx_signature: Signature::default(),
            event_index: 2,
            output_commitment: commitment,
            tree_id: 0,
            ring_data_hash: [1; 32],
            first_nullifier,
            input_nullifiers: vec![first_nullifier],
            encrypted,
            opened: None,
        };
        pending.try_open(&wrong_key, ring).unwrap();
        assert!(pending.opened.is_none());
        pending.try_open(&registered, ring).unwrap();
        let opened = pending.opened.as_ref().unwrap();
        assert_eq!(opened.owner_member, registered.member);
        assert_eq!(opened.output_commitment, commitment);
        assert_eq!(opened.input_nullifiers, [first_nullifier]);
        pending.try_open(&wrong_key, ring).unwrap();
        assert_eq!(
            pending.opened.as_ref().unwrap().owner_member,
            registered.member
        );

        pending.opened = None;
        let mut pending = [pending];
        let mut attempts = 0;
        let limit = Some(NonZeroUsize::new(1).unwrap());
        assert!(!try_registered_key(&mut pending, &wrong_key, ring, &mut attempts, limit).unwrap());
        assert!(matches!(
            try_registered_key(&mut pending, &registered, ring, &mut attempts, limit),
            Err(AuditError::MergeAuditWorkBudget)
        ));
        assert!(pending[0].opened.is_none());
        assert!(try_registered_key(
            &mut pending,
            &registered,
            ring,
            &mut attempts,
            Some(NonZeroUsize::new(2).unwrap()),
        )
        .unwrap());
        assert_eq!(attempts, 2);
    }
}
