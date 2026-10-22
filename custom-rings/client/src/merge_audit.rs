//! Opens every confirmed ring merge with keys the member registry authenticates.

use std::{
    collections::HashSet,
    num::{NonZeroU32, NonZeroUsize},
};

use custom_ring_interface::{EscrowKey, MemberRegistry, RingAccount, MEMBER_REGISTRY_CAPACITY};
use solana_address::Address;
use solana_signature::Signature;
use zolana_client::{
    AsyncRpc, GetShieldedTransactionsByTagsResponse, IndexerRpcConfig, ProofInputUtxo,
    RingHistoryOptions, ShieldedTransaction,
};
use zolana_event::{
    merge_output::MERGE_OUTPUT_SALT_LEN, split_merge_output_body, OutputDataEncoding,
    MERGE_OUTPUT_BODY_LEN, MERGE_OUTPUT_SCHEME,
};
use zolana_hasher::{primitives::is_canonical_bn254_scalar_be, Hasher, Poseidon};
use zolana_indexer_api::{
    Context, GetRingMemberRecordsRequest, Hash, SerializablePubkey, MAX_RING_MEMBER_PAGE_LIMIT,
};
use zolana_interface::instruction::instruction_data::merge_transact::merge_circuit_width;
use zolana_keypair::{NullifierKey, X25519Keypair, X25519Pubkey};
use zolana_ring_member_registry::{OpeningCheck, RecordOpening};
use zolana_ring_policy::Member;
use zolana_transaction::{
    instructions::merge::{merge_output_blinding, merge_output_key, MergeOutputPlaintext},
    utxo::program_id_proof_input_hash,
};

use crate::{
    encryption::{open_merge_disclosure, MergeOpening},
    origin::{ConfirmedEventKind, ConfirmedMergeDisclosure, TransactionOrigin},
    records::{member_record, quad_path, sealed_key, RegistryTip},
    scan::{PageEnd, RING_HISTORY_MAX_PAGES, RING_HISTORY_PAGE_SIZE},
    AuditError,
};

const DEFAULT_MAX_MEMBER_PAGES: NonZeroUsize =
    NonZeroUsize::new((MEMBER_REGISTRY_CAPACITY - 1).div_ceil(MAX_RING_MEMBER_PAGE_LIMIT) as usize)
        .unwrap();

/// One merge output whose raw amount, mint and blinding reproduce its settled leaf.
pub struct AuditedMerge {
    pub tx_signature: Signature,
    pub event_index: u16,
    pub output_commitment: [u8; 32],
    pub owner_member: [u8; 32],
    /// The confirmed `RegisterKey` signer, absent in older indexer projections.
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

/// A confirmed merge no authenticated registration opened.
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

/// The cursor names a ring history position past every row the page examined.
pub struct MergeAuditPage {
    pub context: Context,
    pub result: MergeAuditResult,
    pub next_cursor: Option<Vec<u8>>,
}

/// Registry keys are final so current leaves open earlier merges, an incomplete scan aborts.
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

struct PendingMerge {
    tx_signature: Signature,
    event_index: u16,
    output: MergeOutput,
    input_nullifiers: Vec<[u8; 32]>,
    opened: Option<AuditedMerge>,
}

/// One confirmed merge output, its body length and fields checked.
pub(crate) struct MergeOutput {
    pub(crate) commitment: [u8; 32],
    pub(crate) tree_id: u16,
    pub(crate) first_nullifier: [u8; 32],
    pub(crate) width: usize,
    pub(crate) ring_program_id: [u8; 32],
    pub(crate) ring_data_hash: [u8; 32],
    pub(crate) salt: [u8; MERGE_OUTPUT_SALT_LEN],
    pub(crate) encrypted: Vec<u8>,
}

/// Key and output attempts across one merge page, bounded by `limit`.
struct KeySearch<'a> {
    pending: &'a mut [PendingMerge],
    attempts: usize,
    limit: Option<NonZeroUsize>,
}

/// An anonymous ring merge and the settled leaf its disclosure must reproduce.
#[must_use]
struct DisclosedMerge<'a> {
    auditor: &'a X25519Keypair,
    disclosure: &'a ConfirmedMergeDisclosure,
    output: &'a MergeOutput,
}

impl PendingMerge {
    fn try_open(&mut self, registered: &RegisteredKey) -> Result<(), AuditError> {
        if self.opened.is_some() {
            return Ok(());
        }
        let Some(fields) = self.output.open_candidate(registered)? else {
            return Ok(());
        };
        self.opened = Some(AuditedMerge {
            tx_signature: self.tx_signature,
            event_index: self.event_index,
            output_commitment: self.output.commitment,
            owner_member: registered.member,
            owner_pubkey: registered.owner_pubkey,
            mint: fields.mint,
            amount: fields.amount,
            blinding: fields.blinding,
            ring_data_hash: self.output.ring_data_hash,
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
            page_size: RING_HISTORY_PAGE_SIZE,
            max_pages: RING_HISTORY_MAX_PAGES,
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

    /// Fails closed past `limit` key and output attempts, unbounded by default.
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
        let registry = self.registry_tip(indexer).await?;
        let mut cursor = self.cursor.clone();
        let mut result = MergeAuditResult::default();
        let mut seen = HashSet::new();
        for _ in 0..self.max_pages.get() {
            let (response, next_cursor) = self.read_history_page(indexer, &cursor).await?;
            let page = self
                .open_transactions(response.transactions, registry, indexer, origin, &mut seen)
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
        let registry = self.registry_tip(indexer).await?;
        let (response, next_cursor) = self.read_history_page(indexer, &self.cursor).await?;
        let mut seen = HashSet::new();
        let result = self
            .open_transactions(response.transactions, registry, indexer, origin, &mut seen)
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
        let next_cursor = PageEnd {
            next_cursor: response.next_cursor.clone(),
            scanned_through: response.scanned_through.clone(),
        }
        .next(cursor)?;
        Ok((response, next_cursor))
    }

    async fn open_transactions<I: AsyncRpc, O: TransactionOrigin>(
        &self,
        transactions: Vec<ShieldedTransaction>,
        registry: RegistryTip,
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
            let output = MergeOutput::of(&tx, self.ring)?;
            if let Some(disclosure) = &confirmed.merge_disclosure {
                let opening = output.disclose(self.auditor, disclosure)?;
                disclosed.push(AuditedMerge {
                    tx_signature: tx.tx_signature,
                    event_index,
                    output_commitment: output.commitment,
                    owner_member: *Member::owner_tag(&opening.owner_key)?.as_bytes(),
                    owner_pubkey: Some(Address::new_from_array(opening.owner_key)),
                    mint: Address::new_from_array(opening.mint),
                    amount: opening.amount,
                    blinding: opening.output_blinding,
                    ring_data_hash: output.ring_data_hash,
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
                output,
                input_nullifiers: tx.nullifiers,
                opened: None,
            });
        }
        if pending.is_empty() {
            return Ok(MergeAuditResult {
                opened: disclosed,
                unresolved: Vec::new(),
            });
        }
        let mut search = KeySearch {
            pending: &mut pending,
            attempts: 0,
            limit: self.max_candidate_attempts,
        };
        self.scan_registry(indexer, registry, |registered| search.try_key(registered))
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
                    output_commitment: merge.output.commitment,
                });
            }
        }
        Ok(result)
    }

    async fn registry_tip<I: AsyncRpc>(&self, indexer: &I) -> Result<RegistryTip, AuditError> {
        let (pda, bump) = Address::find_program_address(&[MemberRegistry::SEED], &self.ring);
        let account = indexer
            .get_account(pda)
            .await?
            .ok_or(AuditError::InvalidMemberRegistry)?;
        let registry = MemberRegistry::decode(&account.owner, &self.ring, &account.data)
            .filter(|registry| registry.bump == bump)
            .ok_or(AuditError::InvalidMemberRegistry)?;
        Ok(RegistryTip {
            root: registry.current_root(),
            root_index: registry.history_cursor,
            next_index: u64::from(registry.next_index()),
        })
    }

    /// Records read at one chain-pinned root, `visit` ends the scan once every merge opened.
    async fn scan_registry<I: AsyncRpc>(
        &self,
        indexer: &I,
        tip: RegistryTip,
        mut visit: impl FnMut(&RegisteredKey) -> Result<bool, AuditError>,
    ) -> Result<(), AuditError> {
        let mut start_index = 1;
        let mut pages_read = 0;
        while start_index < tip.next_index {
            if pages_read == self.max_member_pages.get() {
                return Err(AuditError::MergeAuditWorkBudget);
            }
            let response = indexer
                .get_ring_member_records(GetRingMemberRecordsRequest {
                    ring_program_id: SerializablePubkey(self.ring),
                    expected_root: Hash(tip.root),
                    expected_next_index: tip.next_index,
                    start_index,
                    limit: MAX_RING_MEMBER_PAGE_LIMIT,
                })
                .await?;
            if !tip.covers(&response, start_index) {
                return Err(AuditError::InvalidMemberRegistry);
            }
            for row in &response.records {
                let record = member_record(&row.record);
                let member = record.member;
                let owner_pubkey = row.record.owner_pubkey.as_ref().map(|owner| owner.0);
                if owner_pubkey.is_some_and(|owner| {
                    Member::owner_tag(owner.as_array())
                        .map(|tag| *tag.as_bytes() != member)
                        .unwrap_or(true)
                }) {
                    return Err(AuditError::InvalidMemberRegistry);
                }
                OpeningCheck {
                    opening: &RecordOpening::Present {
                        record,
                        path: quad_path(&row.path)?,
                    },
                    root: &tip.root,
                    member: &member,
                }
                .verify()
                .map_err(|_| AuditError::InvalidMemberRegistry)?;
                if record.escrow_key != [0; 32] {
                    let sealed =
                        sealed_key(&row.record)?.ok_or(AuditError::InvalidMemberRegistry)?;
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

impl KeySearch<'_> {
    fn try_key(&mut self, registered: &RegisteredKey) -> Result<bool, AuditError> {
        for merge in self
            .pending
            .iter_mut()
            .filter(|merge| merge.opened.is_none())
        {
            if self.limit.is_some_and(|limit| self.attempts >= limit.get()) {
                return Err(AuditError::MergeAuditWorkBudget);
            }
            self.attempts += 1;
            merge.try_open(registered)?;
        }
        // Every opening matched its settled commitment, later leaves change nothing.
        Ok(self.pending.iter().all(|merge| merge.opened.is_some()))
    }
}

impl MergeOutput {
    /// A malformed confirmed field is an audit error, a commitment miss after it is a key miss.
    pub(crate) fn of(tx: &ShieldedTransaction, ring: Address) -> Result<Self, AuditError> {
        let [slot] = tx.output_slots.as_slice() else {
            return Err(invalid_merge());
        };
        let first_nullifier = *tx.nullifiers.first().ok_or_else(invalid_merge)?;
        let width = merge_circuit_width(tx.nullifiers.len()).ok_or_else(invalid_merge)?;
        let Some(OutputDataEncoding::VerifiablyEncrypted(blob)) = slot.output_data() else {
            return Err(invalid_merge());
        };
        let Some((&MERGE_OUTPUT_SCHEME, body)) = blob.split_first() else {
            return Err(invalid_merge());
        };
        let Some((Some(&ring_data_hash), encrypted)) = split_merge_output_body(body) else {
            return Err(invalid_merge());
        };
        let commitment = slot.output_context.hash;
        let (salt, fields) = encrypted
            .split_first_chunk::<MERGE_OUTPUT_SALT_LEN>()
            .filter(|_| encrypted.len() == MERGE_OUTPUT_BODY_LEN)
            .ok_or_else(invalid_merge)?;
        if ![first_nullifier, commitment, ring_data_hash]
            .iter()
            .chain(fields.as_chunks::<32>().0)
            .all(is_canonical_bn254_scalar_be)
        {
            return Err(invalid_merge());
        }
        Ok(Self {
            commitment,
            tree_id: slot.output_context.tree_id,
            first_nullifier,
            width,
            ring_program_id: program_id_proof_input_hash(&Some(ring))?,
            ring_data_hash,
            salt: *salt,
            encrypted: encrypted.to_vec(),
        })
    }

    pub(crate) fn disclose(
        &self,
        auditor: &X25519Keypair,
        disclosure: &ConfirmedMergeDisclosure,
    ) -> Result<MergeOpening, AuditError> {
        DisclosedMerge {
            auditor,
            disclosure,
            output: self,
        }
        .open()
    }

    /// The ciphertext is unauthenticated, the settled commitment alone decides the opening.
    fn open_candidate(
        &self,
        registered: &RegisteredKey,
    ) -> Result<Option<MergeFields>, AuditError> {
        let key = merge_output_key(&registered.key, &self.first_nullifier)?;
        let Ok(plain) = MergeOutputPlaintext::decrypt(&self.encrypted, &key) else {
            return Ok(None);
        };
        let blinding = merge_output_blinding(&registered.key, &self.first_nullifier)?;
        let owner_hash = Poseidon::hashv(&[&registered.member, &registered.key.pubkey()?])?;
        let Ok(utxo) = ProofInputUtxo::new(
            owner_hash,
            &plain.mint,
            plain.amount,
            &blinding,
            self.tree_id,
        ) else {
            return Ok(None);
        };
        let utxo = ProofInputUtxo {
            ring_data_hash: self.ring_data_hash,
            ring_program_id: self.ring_program_id,
            ..utxo
        };
        let Ok(expected) = utxo.hash() else {
            return Ok(None);
        };
        if expected != self.commitment {
            return Ok(None);
        }
        Ok(Some(MergeFields {
            mint: plain.mint,
            amount: plain.amount,
            blinding,
            nullifier: registered.key.nullifier(&self.commitment, &blinding)?,
        }))
    }
}

impl DisclosedMerge<'_> {
    fn open(self) -> Result<MergeOpening, AuditError> {
        let output = self.output;
        let opening = open_merge_disclosure(
            self.auditor,
            &X25519Pubkey::from_bytes(self.disclosure.eph_pk)?,
            &self.disclosure.ciphertext,
            output.salt,
            &self.disclosure.fields,
        )?;
        if opening.input_commitments.len() != output.width {
            return Err(invalid_merge());
        }
        let owner_member = Member::owner_tag(&opening.owner_key)?;
        let owner_hash = Poseidon::hashv(&[owner_member.as_bytes(), &opening.nullifier_pk])?;
        let commitment = ProofInputUtxo {
            ring_data_hash: output.ring_data_hash,
            ring_program_id: output.ring_program_id,
            ..ProofInputUtxo::new(
                owner_hash,
                &Address::new_from_array(opening.mint),
                opening.amount,
                &opening.output_blinding,
                output.tree_id,
            )?
        }
        .hash()?;
        if commitment != output.commitment {
            return Err(AuditError::MergeDisclosureMismatch);
        }
        Ok(opening)
    }
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
    use custom_ring_interface::QueueEntry;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use zolana_hasher::primitives::right_align;
    use zolana_indexer_api::{
        Base64String, GetRingMemberRecordsResponse, RingIndexedMemberRecordView,
        RingMemberRecordView, RingRecordPathView, RingRegistryRootView,
    };
    use zolana_ring_member_registry::{
        MemberRecord, MemberRegistryTree, QuadPath, RecordStore, RecordTree,
    };
    use zolana_ring_policy::ListId;

    use crate::encryption::{MergeDisclosureEncryption, MergeVector};

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

    fn record_view(record: &MemberRecord) -> RingMemberRecordView {
        RingMemberRecordView {
            member: Hash(record.member),
            next: Hash(record.next),
            lists: record.lists,
            escrow_key: Hash(record.escrow_key),
            owner_pubkey: None,
            nullifier_pk: None,
            eph_pk: None,
            ciphertext: None,
        }
    }

    fn path_view(path: &QuadPath) -> RingRecordPathView {
        RingRecordPathView {
            index: path.index,
            siblings: path.siblings.iter().map(|level| level.map(Hash)).collect(),
        }
    }

    #[tokio::test]
    async fn authenticated_opening_stops_before_unneeded_registry_pages() {
        let ring = Address::new_from_array([9; 32]);
        let auditor = X25519Keypair::new();
        let key = NullifierKey::from_secret([7; 31]);
        let envelope = crate::NullifierKeyEnvelope::new(&key, &auditor.pubkey()).unwrap();
        let escrow = EscrowKey {
            nullifier_pk: &envelope.nullifier_pk,
            ciphertext: &envelope.sealed.ciphertext,
        };
        let member = |index: u64| right_align(&index.to_be_bytes());
        let list = ListId::ALL[0].record_bit();
        let entries = (1u64..=101)
            .map(|index| match index {
                1 => QueueEntry::escrow(member(index), &escrow),
                _ => Ok(QueueEntry {
                    member: member(index),
                    mask: list,
                    value: list,
                    escrow_key: [0; 32],
                }),
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut tree = MemberRegistryTree::new().unwrap();
        tree.apply([0; 32], &entries).unwrap();
        let tip = RegistryTip {
            root: tree.root().unwrap(),
            root_index: 0,
            next_index: tree.next_index().unwrap(),
        };
        let records = (1..=100u64)
            .map(|index| {
                let record = tree.records()[index as usize];
                let sealed = (record.escrow_key != [0; 32]).then_some(&envelope.sealed);
                RingIndexedMemberRecordView {
                    record: RingMemberRecordView {
                        eph_pk: sealed
                            .map(|sealed| Base64String(sealed.eph_pk.as_bytes().to_vec())),
                        ciphertext: sealed.map(|sealed| Base64String(sealed.ciphertext.to_vec())),
                        ..record_view(&record)
                    },
                    path: path_view(&tree.path(index).unwrap()),
                }
            })
            .collect();
        let pages = RegistryPages {
            first: GetRingMemberRecordsResponse {
                context: Context::default(),
                root: RingRegistryRootView {
                    root: Hash(tip.root),
                    root_index: tip.root_index,
                    applied: 0,
                    next_index: tip.next_index,
                },
                records,
                next_leaf_index: Some(101),
            },
            requests: AtomicUsize::new(0),
        };
        MergeAudit::new(ring, &auditor)
            .scan_registry(&pages, tip, |registered| {
                assert_eq!(registered.key.secret(), key.secret());
                Ok(true)
            })
            .await
            .unwrap();
        assert_eq!(pages.requests.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn member_page_must_be_complete_and_contiguous() {
        let tip = RegistryTip {
            root: [4; 32],
            root_index: 7,
            next_index: 8,
        };
        let record = RingMemberRecordView {
            member: Hash([1; 32]),
            next: Hash([2; 32]),
            lists: 0,
            escrow_key: Hash([0; 32]),
            owner_pubkey: None,
            nullifier_pk: None,
            eph_pk: None,
            ciphertext: None,
        };
        let row = |index| RingIndexedMemberRecordView {
            record: record.clone(),
            path: RingRecordPathView {
                index,
                siblings: Vec::new(),
            },
        };
        let mut response = GetRingMemberRecordsResponse {
            context: Context {
                slot: 1,
                block_time: 0,
            },
            root: RingRegistryRootView {
                root: Hash(tip.root),
                root_index: 7,
                applied: 0,
                next_index: 8,
            },
            records: (5..8).map(row).collect(),
            next_leaf_index: None,
        };
        assert!(tip.covers(&response, 5));
        response.records[1].path.index = 8;
        assert!(!tip.covers(&response, 5));
        response.records[1].path.index = 6;
        response.records.pop();
        assert!(!tip.covers(&response, 5));
        response.records.push(row(7));
        response.next_leaf_index = Some(8);
        assert!(!tip.covers(&response, 5));
        response.next_leaf_index = None;
        response.root.root = Hash([9; 32]);
        assert!(!tip.covers(&response, 5));
    }

    struct TerminalHistory {
        scanned_through: Option<Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl AsyncRpc for TerminalHistory {
        async fn get_shielded_transactions_by_ring(
            &self,
            _options: RingHistoryOptions,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByTagsResponse, zolana_client::ClientError> {
            Ok(GetShieldedTransactionsByTagsResponse {
                context: zolana_client::Context {
                    slot: 1,
                    block_time: 0,
                },
                output_tree_id: None,
                transactions: Vec::new(),
                next_cursor: None,
                scanned_through: self.scanned_through.clone(),
            })
        }
    }

    #[tokio::test]
    async fn a_terminal_history_page_without_a_frontier_fails_the_merge_scan() {
        let auditor = X25519Keypair::new();
        let audit = MergeAudit::new(Address::new_from_array([9; 32]), &auditor);
        let indexer = TerminalHistory {
            scanned_through: None,
        };
        assert!(matches!(
            audit.read_history_page(&indexer, &Some(vec![1])).await,
            Err(AuditError::ScanFrontierMissing)
        ));
    }

    #[tokio::test]
    async fn a_terminal_history_page_with_a_frontier_ends_the_merge_scan() {
        let auditor = X25519Keypair::new();
        let audit = MergeAudit::new(Address::new_from_array([9; 32]), &auditor);
        let indexer = TerminalHistory {
            scanned_through: Some(vec![2]),
        };
        let (_, next_cursor) = audit
            .read_history_page(&indexer, &Some(vec![1]))
            .await
            .unwrap();
        assert_eq!(next_cursor, None);
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

    /// A merge row of eight spends, its output at `commitment` in tree 0.
    struct MergeRow {
        first_nullifier: [u8; 32],
        commitment: [u8; 32],
        ring_data_hash: [u8; 32],
        salt: [u8; MERGE_OUTPUT_SALT_LEN],
        ciphertext: [[u8; 32]; 3],
    }

    impl MergeRow {
        fn output(&self, ring: Address) -> Result<MergeOutput, AuditError> {
            let tx = ShieldedTransaction {
                slot: 0,
                tx_signature: Signature::default(),
                event_index: Some(0),
                tx_viewing_pk: None,
                salt: None,
                output_slots: vec![zolana_client::OutputSlot {
                    view_tag: [0; 32],
                    output_context: zolana_client::OutputContext {
                        hash: self.commitment,
                        tree_id: 0,
                        leaf_index: 0,
                    },
                    payload: zolana_event::encode_merge_output_data(
                        zolana_event::MergeOutputDataRef {
                            salt: &self.salt,
                            ciphertext: &self.ciphertext,
                            ring_data_hash: Some(&self.ring_data_hash),
                        },
                    ),
                }],
                messages: Vec::new(),
                nullifiers: vec![self.first_nullifier; 8],
                proofless: false,
                ring_config: None,
                ring_program_id: Some(ring),
            };
            MergeOutput::of(&tx, ring)
        }
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
        let blinding = merge_output_blinding(&registered.key, &first_nullifier).unwrap();
        let owner_hash =
            Poseidon::hashv(&[&registered.member, &registered.key.pubkey().unwrap()]).unwrap();
        let commitment = ProofInputUtxo::new(owner_hash, &mint, 8, &blinding, 0)
            .unwrap()
            .with_ring([1; 32], &Some(ring))
            .unwrap()
            .hash()
            .unwrap();
        let row = MergeRow {
            first_nullifier,
            commitment,
            ring_data_hash: [1; 32],
            salt,
            ciphertext,
        };
        let mut malformed = [ciphertext[0], ciphertext[1], ciphertext[2]];
        malformed[0] = [0xff; 32];
        for row in [
            MergeRow {
                ciphertext: malformed,
                ..row
            },
            MergeRow {
                ring_data_hash: [0xff; 32],
                ..row
            },
            MergeRow {
                first_nullifier: [0xff; 32],
                ..row
            },
        ] {
            assert!(matches!(
                row.output(ring),
                Err(AuditError::InvalidConfirmedEvent(_))
            ));
        }
        let output = row.output(ring).unwrap();
        let opened = output.open_candidate(&registered).unwrap().unwrap();
        assert_eq!(
            (opened.mint, opened.amount, opened.blinding),
            (mint, 8, blinding)
        );
        assert_eq!(
            opened.nullifier,
            registered.key.nullifier(&commitment, &blinding).unwrap()
        );
        let elsewhere = MergeRow {
            commitment: [2; 32],
            ..row
        };
        assert!(elsewhere
            .output(ring)
            .unwrap()
            .open_candidate(&registered)
            .unwrap()
            .is_none());
        for secret in 8..40 {
            let wrong_key = RegisteredKey {
                member: registered.member,
                owner_pubkey: None,
                key: NullifierKey::from_secret([secret; 31]),
            };
            assert!(output.open_candidate(&wrong_key).unwrap().is_none());
        }

        let wrong_key = RegisteredKey {
            member: registered.member,
            owner_pubkey: None,
            key: NullifierKey::from_secret([8; 31]),
        };
        let mut pending = PendingMerge {
            tx_signature: Signature::default(),
            event_index: 2,
            output,
            input_nullifiers: vec![first_nullifier],
            opened: None,
        };
        pending.try_open(&wrong_key).unwrap();
        assert!(pending.opened.is_none());
        pending.try_open(&registered).unwrap();
        let opened = pending.opened.as_ref().unwrap();
        assert_eq!(opened.owner_member, registered.member);
        assert_eq!(opened.output_commitment, commitment);
        assert_eq!(opened.input_nullifiers, [first_nullifier]);
        pending.try_open(&wrong_key).unwrap();
        assert_eq!(
            pending.opened.as_ref().unwrap().owner_member,
            registered.member
        );

        pending.opened = None;
        let mut pending = [pending];
        let mut search = KeySearch {
            pending: &mut pending,
            attempts: 0,
            limit: Some(NonZeroUsize::new(1).unwrap()),
        };
        assert!(!search.try_key(&wrong_key).unwrap());
        assert!(matches!(
            search.try_key(&registered),
            Err(AuditError::MergeAuditWorkBudget)
        ));
        assert!(search.pending[0].opened.is_none());
        search.limit = Some(NonZeroUsize::new(2).unwrap());
        assert!(search.try_key(&registered).unwrap());
        assert_eq!(search.attempts, 2);
    }

    /// The Go merge statement of the shared vector, opened through the audit check.
    struct VectorMerge {
        vector: MergeVector,
        auditor: X25519Keypair,
        disclosure: ConfirmedMergeDisclosure,
    }

    impl VectorMerge {
        fn load() -> Self {
            let vector = MergeVector::load();
            let auditor = X25519Keypair::from_bytes(&vector.array("auditor_sk"));
            let disclosure = ConfirmedMergeDisclosure {
                eph_pk: vector.array("eph_pk"),
                ciphertext: vector.array("envelope_ciphertext"),
                fields: vector.fields("fields"),
            };
            Self {
                vector,
                auditor,
                disclosure,
            }
        }

        fn open(
            &self,
            auditor: &X25519Keypair,
            disclosure: &ConfirmedMergeDisclosure,
        ) -> Result<MergeOpening, AuditError> {
            let tree_id = self.vector.request_array("outputTreeId");
            let output = MergeOutput {
                commitment: self.vector.request_array("outputUtxoHash"),
                tree_id: u16::from_be_bytes([tree_id[30], tree_id[31]]),
                first_nullifier: [0; 32],
                width: 8,
                ring_program_id: self.vector.request_array("ringProgramId"),
                ring_data_hash: self.vector.request_array("outputRingDataHash"),
                salt: self.vector.array("salt"),
                encrypted: Vec::new(),
            };
            output.disclose(auditor, disclosure)
        }

        fn sealed(&self, opening: &MergeOpening) -> ConfirmedMergeDisclosure {
            let sealed = MergeDisclosureEncryption::new(
                opening,
                self.vector.array("salt"),
                &self.auditor.pubkey(),
            )
            .unwrap();
            ConfirmedMergeDisclosure {
                eph_pk: *sealed.eph_pk.as_bytes(),
                ciphertext: sealed.ciphertext,
                fields: sealed.fields,
            }
        }
    }

    #[test]
    fn a_disclosed_opening_reproduces_the_settled_commitment() {
        let merge = VectorMerge::load();
        assert_eq!(
            merge.open(&merge.auditor, &merge.disclosure).unwrap(),
            merge.vector.opening()
        );
    }

    #[test]
    fn a_disclosure_of_another_amount_or_blinding_is_refused() {
        let merge = VectorMerge::load();
        let mut amount = merge.vector.opening();
        amount.amount += 1;
        let mut blinding = merge.vector.opening();
        blinding.output_blinding[31] ^= 1;
        for tampered in [amount, blinding] {
            assert!(matches!(
                merge.open(&merge.auditor, &merge.sealed(&tampered)),
                Err(AuditError::MergeDisclosureMismatch)
            ));
        }
    }

    #[test]
    fn a_disclosure_under_another_auditor_key_does_not_open() {
        let merge = VectorMerge::load();
        assert!(merge
            .open(&X25519Keypair::new(), &merge.disclosure)
            .is_err());
    }
}
