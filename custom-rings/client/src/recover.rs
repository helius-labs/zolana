//! Rebuilds a source member's unspent ring notes from the auditor's visibility.

use std::{
    collections::{HashMap, HashSet},
    num::{NonZeroU32, NonZeroUsize},
};

use custom_ring_interface::RingDepositAuditCapsule;
use solana_address::Address;
use zolana_client::Rpc;
use zolana_event::EncryptedRingDepositOutput;
use zolana_event_parser::decode_encrypted_ring_deposit_output_data;
use zolana_indexer_api::PAGE_LIMIT;
use zolana_keypair::{NullifierKey, ShieldedAddress, ViewingKey};
use zolana_ring_policy::Member;
use zolana_transaction::{
    instructions::merge::{
        merge_dummy_nullifier, merge_output_blinding, MERGE_SUPPORTED_INPUT_COUNTS,
    },
    AssetRegistry, Data, OutputContext, ShieldedTransaction, Utxo, WalletUtxo,
};

use crate::{
    decrypt::TransactionAudit,
    error::{AuditError, RecoveryError},
    origin::TransactionOrigin,
    scan::{RingEnvironment, RingScan},
    types::AuditedOutput,
    DepositOpen,
};

const DEFAULT_MAX_PAGES: NonZeroUsize = match NonZeroUsize::new(4096) {
    Some(value) => value,
    None => NonZeroUsize::MIN,
};
const DEFAULT_PAGE_SIZE: NonZeroU32 = match NonZeroU32::new(1000) {
    Some(value) => value,
    None => NonZeroU32::MIN,
};

#[must_use = "run the recovery explicitly"]
pub struct RingRecovery<'a> {
    ring_program_id: Address,
    auditor: &'a ViewingKey,
    page_size: NonZeroU32,
    max_pages: NonZeroUsize,
}

pub struct SourceMember<'a> {
    pub address: &'a ShieldedAddress,
    pub nullifier_key: &'a NullifierKey,
}

#[must_use = "run the recovery explicitly"]
pub struct MemberRecovery<'a> {
    recovery: RingRecovery<'a>,
    source: SourceMember<'a>,
    data_hashes: Option<&'a NoteHashResolver<'a>>,
}

/// Application commitments supplied by the note's protocol.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoteDataHashes {
    pub data_hash: Option<[u8; 32]>,
    pub ring_data_hash: Option<[u8; 32]>,
}

/// Supplied hashes are accepted only when they reproduce the leaf.
pub type NoteHashResolver<'a> =
    dyn Fn(&AuditedOutput, &OutputContext) -> Result<Option<NoteDataHashes>, RecoveryError> + 'a;

pub struct RecoveryEnvironment<'a, I, O, F> {
    pub ring: RingEnvironment<'a, I, O>,
    pub assets: &'a AssetRegistry,
    /// The raw id a note's leaf is committed under.
    pub tree_ids: F,
}

/// Verified unspent notes with separate unresolved coverage.
pub struct RecoveredNotes {
    pub utxos: Vec<WalletUtxo>,
    /// Audited or merge commitments without verified openings or confirmed
    /// spends.
    pub unopened: Vec<[u8; 32]>,
    /// Tagged deposits with unknown ownership and spentness.
    pub unsupported_deposits: Vec<[u8; 32]>,
}

impl<'a> RingRecovery<'a> {
    pub fn new(ring_program_id: Address, auditor: &'a ViewingKey) -> Self {
        Self {
            ring_program_id,
            auditor,
            page_size: DEFAULT_PAGE_SIZE,
            max_pages: DEFAULT_MAX_PAGES,
        }
    }

    #[must_use = "use the updated recovery"]
    pub fn with_page_size(mut self, page_size: NonZeroU32) -> Self {
        self.page_size = page_size;
        self
    }

    #[must_use = "use the updated recovery"]
    pub fn with_max_pages(mut self, max_pages: NonZeroUsize) -> Self {
        self.max_pages = max_pages;
        self
    }

    pub fn for_member(self, source: SourceMember<'a>) -> MemberRecovery<'a> {
        MemberRecovery {
            recovery: self,
            source,
            data_hashes: None,
        }
    }
}

impl SourceMember<'_> {
    fn verify(&self) -> Result<Member, RecoveryError> {
        if self.nullifier_key.pubkey()? != self.address.nullifier_pubkey {
            return Err(RecoveryError::NullifierKeyMismatch);
        }
        Ok(Member::owner_tag(&self.address.confidential_view_tag()?)?)
    }
}

impl<'a> MemberRecovery<'a> {
    #[must_use = "use the updated recovery"]
    pub fn with_data_hashes(mut self, resolver: &'a NoteHashResolver<'a>) -> Self {
        self.data_hashes = Some(resolver);
        self
    }

    pub fn run<I, O, F>(
        self,
        env: RecoveryEnvironment<'_, I, O, F>,
    ) -> Result<RecoveredNotes, RecoveryError>
    where
        I: Rpc,
        O: TransactionOrigin,
        F: FnMut(Address) -> Result<u16, RecoveryError>,
    {
        // 1. The recovered nullifier key must match the requested source
        // address.
        let source_member = self.source.verify()?;
        let RecoveryEnvironment {
            ring,
            assets,
            mut tree_ids,
        } = env;
        let auditor_pk = self.recovery.auditor.pubkey();
        let page = RingScan::new(self.recovery.ring_program_id, &auditor_pk)
            .with_page_size(self.recovery.page_size)
            .with_max_pages(self.recovery.max_pages)
            .run(ring)?;
        if page.next_cursor.is_some() {
            return Err(RecoveryError::IncompleteScan);
        }

        let mut candidates = Vec::new();
        let mut unresolved = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut known_tree_ids: HashMap<Address, u16> = HashMap::new();
        for transaction in &page.transactions {
            let audited = TransactionAudit {
                auditor: self.recovery.auditor,
                transaction,
                assets,
            }
            .run()?;
            for output in &audited.outputs {
                if output.recipient_viewing_pk != self.source.address.viewing_pubkey
                    || Member::owner_tag(&output.owner_tag)? != source_member
                    || output.ring_program_id != Some(self.recovery.ring_program_id)
                {
                    continue;
                }
                let output_context = transaction
                    .output_slots
                    .get(output.slot_index as usize)
                    .map(|slot| slot.output_context.clone())
                    .ok_or(RecoveryError::MissingOutputSlot(output.slot_index))?;
                if !seen.insert(output_context.hash) {
                    continue;
                }
                let tree_id = match known_tree_ids.get(&output_context.tree) {
                    Some(id) => *id,
                    None => {
                        let id = tree_ids(output_context.tree)?;
                        known_tree_ids.insert(output_context.tree, id);
                        id
                    }
                };
                let utxo = Utxo {
                    owner: self.source.address.signing_pubkey,
                    asset: output.asset,
                    amount: output.amount,
                    blinding: *output.blinding,
                    ring_program_id: output.ring_program_id,
                    data: output.data.clone(),
                };
                // 2. Application hashes are accepted only when the opening
                // reproduces the leaf.
                let mut hashes = NoteDataHashes::default();
                let mut commitment = utxo.hash(
                    &self.source.address.nullifier_pubkey,
                    &[0u8; 32],
                    &[0u8; 32],
                    tree_id,
                )?;
                if commitment != output_context.hash {
                    if let Some(resolver) = self.data_hashes {
                        if let Some(resolved) = resolver(output, &output_context)? {
                            hashes = resolved;
                            commitment = utxo.hash(
                                &self.source.address.nullifier_pubkey,
                                &hashes.data_hash.unwrap_or_default(),
                                &hashes.ring_data_hash.unwrap_or_default(),
                                tree_id,
                            )?;
                        }
                    }
                }
                let nullifier = utxo.nullifier(&output_context.hash, self.source.nullifier_key)?;
                if commitment != output_context.hash {
                    unresolved.push((output_context.hash, nullifier));
                    continue;
                }
                candidates.push(WalletUtxo {
                    utxo,
                    output_context,
                    nullifier,
                    data_hash: hashes.data_hash,
                    ring_data_hash: hashes.ring_data_hash,
                    tree_id,
                    spent: false,
                });
            }
        }
        // 3. Disclosed deposits are found without trusting their recipient view
        // tags.
        let mut unsupported_deposits = Vec::new();
        let source_owner_hash = self.source.address.owner_hash()?;
        let bootstrap_tag = self.source.address.viewing_pubkey.x();
        for (output_context, output, tag) in (DepositHistory {
            environment: ring,
            ring: self.recovery.ring_program_id,
            page_size: self.recovery.page_size,
            max_pages: self.recovery.max_pages,
        })
        .read()?
        {
            if seen.contains(&output_context.hash) {
                continue;
            }
            let Ok(Some(capsule)) = RingDepositAuditCapsule::parse(&output.encrypted.ciphertext)
            else {
                if tag == bootstrap_tag {
                    unsupported_deposits.push(output_context.hash);
                }
                continue;
            };
            let Ok(opening) = (DepositOpen {
                capsule,
                auditor: self.recovery.auditor,
                owner_utxo_hash: &output.owner_utxo_hash,
            })
            .open() else {
                if tag == bootstrap_tag {
                    unsupported_deposits.push(output_context.hash);
                }
                continue;
            };
            if opening.owner_hash != source_owner_hash {
                continue;
            }
            let tree_id = match known_tree_ids.get(&output_context.tree) {
                Some(id) => *id,
                None => {
                    let id = tree_ids(output_context.tree)?;
                    known_tree_ids.insert(output_context.tree, id);
                    id
                }
            };
            let utxo = Utxo {
                owner: self.source.address.signing_pubkey,
                asset: Address::new_from_array(output.asset),
                amount: output.amount,
                blinding: *opening.blinding,
                ring_program_id: Some(self.recovery.ring_program_id),
                data: Data::default(),
            };
            if utxo.hash(
                &self.source.address.nullifier_pubkey,
                &output.data_hash.unwrap_or_default(),
                &output.ring_data_hash,
                tree_id,
            )? != output_context.hash
            {
                return Err(RecoveryError::DepositOpeningMismatch);
            }
            seen.insert(output_context.hash);
            candidates.push(WalletUtxo {
                nullifier: utxo.nullifier(&output_context.hash, self.source.nullifier_key)?,
                utxo,
                output_context,
                data_hash: output.data_hash,
                ring_data_hash: Some(output.ring_data_hash),
                tree_id,
                spent: false,
            });
        }
        // 4. Every discovered merge successor must pass a fresh spentness
        // lookup.
        let mut nullifiers: Vec<_> = candidates
            .iter()
            .map(|candidate| candidate.nullifier)
            .chain(unresolved.iter().map(|(_, nullifier)| *nullifier))
            .collect();
        let mut spent = HashSet::new();
        let mut merges = Vec::new();
        let mut merge_outputs = HashSet::new();
        let mut remaining_queries = self.recovery.max_pages.get();
        loop {
            if !nullifiers.is_empty() {
                let transactions = SpendHistory {
                    indexer: ring.indexer,
                    nullifiers: &nullifiers,
                    remaining_queries: &mut remaining_queries,
                }
                .read()?;
                for transaction in transactions {
                    if !transaction
                        .nullifiers
                        .iter()
                        .any(|nullifier| nullifiers.contains(nullifier))
                    {
                        continue;
                    }
                    spent.extend(transaction.nullifiers.iter().copied());
                    if transaction.proofless
                        || transaction.tx_viewing_pk.is_some()
                        || transaction.salt.is_some()
                        || transaction.output_slots.len() != 1
                        || !MERGE_SUPPORTED_INPUT_COUNTS.contains(&transaction.nullifiers.len())
                    {
                        continue;
                    }
                    let commitment = transaction.output_slots[0].output_context.hash;
                    if merge_outputs.contains(&commitment) {
                        continue;
                    }
                    if ring
                        .origin
                        .ring_invoked(transaction.tx_signature, self.recovery.ring_program_id)
                        .map_err(AuditError::from)?
                    {
                        merge_outputs.insert(commitment);
                        merges.push(transaction);
                    }
                }
            }
            let previous_count = candidates.len();
            for transaction in &merges {
                let output = &transaction.output_slots[0].output_context;
                if seen.contains(&output.hash) {
                    continue;
                }
                let tree_id = match known_tree_ids.get(&output.tree) {
                    Some(id) => *id,
                    None => {
                        let id = tree_ids(output.tree)?;
                        known_tree_ids.insert(output.tree, id);
                        id
                    }
                };
                if let Some(candidate) = (MergeOpening {
                    source: &self.source,
                    transaction,
                    candidates: &candidates,
                    tree_id,
                })
                .rebuild()?
                {
                    seen.insert(output.hash);
                    candidates.push(candidate);
                }
            }
            if previous_count == candidates.len() {
                break;
            }
            nullifiers = candidates[previous_count..]
                .iter()
                .map(|candidate| candidate.nullifier)
                .collect();
        }
        let mut unopened: Vec<_> = unresolved
            .into_iter()
            .filter(|(_, nullifier)| !spent.contains(nullifier))
            .map(|(commitment, _)| commitment)
            .collect();
        for transaction in merges {
            let commitment = transaction.output_slots[0].output_context.hash;
            if !seen.contains(&commitment) {
                unopened.push(commitment);
            }
        }
        // 5. Missing openings remain separate from the verified unspent
        // balance.
        let utxos = candidates
            .into_iter()
            .filter(|candidate| !spent.contains(&candidate.nullifier))
            .collect();
        Ok(RecoveredNotes {
            utxos,
            unopened,
            unsupported_deposits,
        })
    }
}

struct DepositHistory<'a, I, O> {
    environment: RingEnvironment<'a, I, O>,
    ring: Address,
    page_size: NonZeroU32,
    max_pages: NonZeroUsize,
}

impl<I: Rpc, O: TransactionOrigin> DepositHistory<'_, I, O> {
    fn read(
        self,
    ) -> Result<Vec<(OutputContext, EncryptedRingDepositOutput, [u8; 32])>, RecoveryError> {
        let mut deposits = Vec::new();
        let mut seen = HashSet::new();
        let mut cursor = None;
        for _ in 0..self.max_pages.get() {
            let page = self.environment.indexer.get_shielded_transactions_by_ring(
                zolana_client::rpc::RingHistoryOptions {
                    ring_program_id: self.ring,
                    cursor: cursor.clone(),
                    limit: Some(self.page_size.get()),
                },
                None,
            )?;
            for transaction in page.transactions {
                if !transaction.proofless {
                    continue;
                }
                let tagged: Vec<_> = transaction
                    .output_slots
                    .iter()
                    .filter_map(|slot| {
                        let output =
                            decode_encrypted_ring_deposit_output_data(&slot.payload).ok()?;
                        (output.ring_program_id == self.ring.to_bytes()).then_some((
                            slot.output_context.clone(),
                            output,
                            slot.view_tag,
                        ))
                    })
                    .collect();
                if tagged.is_empty()
                    || !self
                        .environment
                        .origin
                        .ring_invoked(transaction.tx_signature, self.ring)
                        .map_err(AuditError::from)?
                {
                    continue;
                }
                for (context, output, tag) in tagged {
                    if seen.insert(context.hash) {
                        deposits.push((context, output, tag));
                    }
                }
            }
            if page.scanned_through.is_some() {
                return Ok(deposits);
            }
            let Some(next) = page.next_cursor else {
                return Ok(deposits);
            };
            if cursor.as_ref() == Some(&next) {
                return Err(AuditError::CursorNotAdvanced.into());
            }
            cursor = Some(next);
        }
        Err(RecoveryError::IncompleteScan)
    }
}

struct SpendHistory<'a, I> {
    indexer: &'a I,
    nullifiers: &'a [[u8; 32]],
    remaining_queries: &'a mut usize,
}

impl<I: Rpc> SpendHistory<'_, I> {
    fn read(self) -> Result<Vec<ShieldedTransaction>, RecoveryError> {
        let mut transactions = Vec::new();
        for batch in self.nullifiers.chunks(PAGE_LIMIT as usize) {
            let mut cursor = None;
            loop {
                *self.remaining_queries = self
                    .remaining_queries
                    .checked_sub(1)
                    .ok_or(RecoveryError::IncompleteScan)?;
                let page = self.indexer.get_shielded_transactions_by_nullifiers(
                    batch.to_vec(),
                    cursor.clone(),
                    None,
                    None,
                )?;
                transactions.extend(page.transactions);
                if page.scanned_through.is_some() {
                    break;
                }
                let Some(next) = page.next_cursor else {
                    break;
                };
                if cursor.as_ref() == Some(&next) {
                    return Err(AuditError::CursorNotAdvanced.into());
                }
                cursor = Some(next);
            }
        }
        Ok(transactions)
    }
}

struct MergeOpening<'a, 'b> {
    source: &'a SourceMember<'b>,
    transaction: &'a ShieldedTransaction,
    candidates: &'a [WalletUtxo],
    tree_id: u16,
}

impl MergeOpening<'_, '_> {
    fn rebuild(self) -> Result<Option<WalletUtxo>, RecoveryError> {
        let transaction = self.transaction;
        let Some(first_nullifier) = transaction.nullifiers.first() else {
            return Ok(None);
        };
        let Some(first) = self
            .candidates
            .iter()
            .find(|note| note.nullifier == *first_nullifier)
        else {
            return Ok(None);
        };
        let mut amount = 0u64;
        for (index, nullifier) in transaction.nullifiers.iter().enumerate() {
            if *nullifier
                == merge_dummy_nullifier(self.source.nullifier_key, first_nullifier, index as u8)?
            {
                continue;
            }
            let Some(note) = self
                .candidates
                .iter()
                .find(|note| note.nullifier == *nullifier)
            else {
                return Ok(None);
            };
            if note.utxo.asset != first.utxo.asset
                || note.utxo.ring_program_id != first.utxo.ring_program_id
                || note.data_hash.is_some_and(|hash| hash != [0; 32])
            {
                return Ok(None);
            }
            amount = amount
                .checked_add(note.utxo.amount)
                .ok_or(zolana_transaction::TransactionError::SelectedBalanceOverflow)?;
        }
        let slot = &transaction.output_slots[0];
        let Ok(ring_data_hash) = <[u8; 32]>::try_from(slot.payload.as_slice()) else {
            return Ok(None);
        };
        let utxo = Utxo {
            owner: self.source.address.signing_pubkey,
            asset: first.utxo.asset,
            amount,
            blinding: merge_output_blinding(self.source.nullifier_key, first_nullifier)?,
            ring_program_id: first.utxo.ring_program_id,
            data: Data::default(),
        };
        if utxo.hash(
            &self.source.address.nullifier_pubkey,
            &[0; 32],
            &ring_data_hash,
            self.tree_id,
        )? != slot.output_context.hash
        {
            return Ok(None);
        }
        Ok(Some(WalletUtxo {
            nullifier: utxo.nullifier(&slot.output_context.hash, self.source.nullifier_key)?,
            utxo,
            output_context: slot.output_context.clone(),
            data_hash: None,
            ring_data_hash: Some(ring_data_hash),
            tree_id: self.tree_id,
            spent: false,
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use zolana_client::{
        rpc::GetShieldedTransactionsByNullifiersResponse, ClientError, Context, IndexerRpcConfig,
    };

    use super::*;

    struct Query {
        nullifiers: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
    }

    #[derive(Default)]
    struct Paginated {
        queries: RefCell<Vec<Query>>,
        stuck: bool,
    }

    impl Rpc for Paginated {
        fn get_shielded_transactions_by_nullifiers(
            &self,
            nullifiers: Vec<[u8; 32]>,
            cursor: Option<Vec<u8>>,
            _limit: Option<u32>,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
            assert!(nullifiers.len() <= PAGE_LIMIT as usize);
            self.queries.borrow_mut().push(Query {
                nullifiers,
                cursor: cursor.clone(),
            });
            Ok(GetShieldedTransactionsByNullifiersResponse {
                context: Context {
                    block_time: 0,
                    slot: 1,
                },
                transactions: Vec::new(),
                next_cursor: Some(vec![1]),
                scanned_through: (cursor.is_some() && !self.stuck).then(|| vec![1]),
            })
        }
    }

    #[test]
    fn batches_history_keys_and_resets_pagination_for_each_batch() {
        let indexer = Paginated::default();
        let nullifiers: Vec<_> = (0..PAGE_LIMIT + 1)
            .map(|value| {
                let mut hash = [0; 32];
                hash[24..].copy_from_slice(&value.to_be_bytes());
                hash
            })
            .collect();
        let mut remaining_queries = 4;
        SpendHistory {
            indexer: &indexer,
            nullifiers: &nullifiers,
            remaining_queries: &mut remaining_queries,
        }
        .read()
        .expect("history");
        let queries = indexer.queries.borrow();
        assert_eq!(
            queries
                .iter()
                .map(|query| query.nullifiers.len())
                .collect::<Vec<_>>(),
            vec![1000, 1000, 1, 1]
        );
        assert_eq!(
            queries
                .iter()
                .map(|query| query.cursor.clone())
                .collect::<Vec<_>>(),
            vec![None, Some(vec![1]), None, Some(vec![1])]
        );
        assert_eq!(queries[2].nullifiers, nullifiers[1000..]);
        assert_eq!(remaining_queries, 0);
    }

    #[test]
    fn refuses_a_cursor_that_does_not_advance() {
        let indexer = Paginated {
            stuck: true,
            ..Default::default()
        };
        let mut remaining_queries = 3;
        assert!(matches!(
            SpendHistory {
                indexer: &indexer,
                nullifiers: &[[1; 32]],
                remaining_queries: &mut remaining_queries
            }
            .read(),
            Err(RecoveryError::Audit(AuditError::CursorNotAdvanced))
        ));
    }
}
