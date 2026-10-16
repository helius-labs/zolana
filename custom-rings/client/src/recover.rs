//! Rebuilds a source member's unspent ring notes from what the auditor sees.

use std::{
    collections::HashSet,
    num::{NonZeroU32, NonZeroUsize},
};

use custom_ring_interface::RingDepositAuditCapsule;
use solana_address::Address;
use zolana_client::{AsyncRpc, IndexerRpcConfig, RingHistoryOptions};
use zolana_event::EncryptedRingDepositOutput;
use zolana_event_parser::decode_encrypted_ring_deposit_output_data;
use zolana_indexer_api::PAGE_LIMIT;
use zolana_keypair::{NullifierKey, ShieldedAddress, X25519Secret};
use zolana_ring_policy::Member;
use zolana_transaction::{
    instructions::merge::{merge_circuit_width, merge_dummy_nullifier, merge_output_blinding},
    AssetRegistry, Data, OutputContext, OutputSlot, ShieldedTransaction, TransactionError, Utxo,
    WalletUtxo,
};

use crate::{
    decrypt::TransactionAudit,
    encryption::open_deposit,
    origin::TransactionOrigin,
    scan::{pages, RingScan},
    types::AuditedOutput,
    AuditError,
};

const DEFAULT_MAX_PAGES: NonZeroUsize = NonZeroUsize::new(4096).unwrap();
const DEFAULT_PAGE_SIZE: NonZeroU32 = NonZeroU32::new(1000).unwrap();

#[must_use = "run the recovery explicitly"]
pub struct RingRecovery<'a> {
    ring_program_id: Address,
    auditor: &'a X25519Secret,
    page_size: NonZeroU32,
    max_pages: NonZeroUsize,
    indexer_config: Option<IndexerRpcConfig>,
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
pub type NoteHashResolver<'a> = dyn Fn(&AuditedOutput, &OutputContext) -> Result<Option<NoteDataHashes>, AuditError>
    + Sync
    + 'a;

/// Verified unspent notes with the coverage left unresolved.
pub struct RecoveredNotes {
    pub utxos: Vec<WalletUtxo>,
    /// Audited or merge commitments without a verified opening or a confirmed spend.
    pub unopened: Vec<[u8; 32]>,
    /// Tagged deposits whose ownership and spentness are unknown.
    pub unsupported_deposits: Vec<[u8; 32]>,
}

impl<'a> RingRecovery<'a> {
    pub fn new(ring_program_id: Address, auditor: &'a X25519Secret) -> Self {
        Self {
            ring_program_id,
            auditor,
            page_size: DEFAULT_PAGE_SIZE,
            max_pages: DEFAULT_MAX_PAGES,
            indexer_config: None,
        }
    }

    pub fn with_page_size(mut self, page_size: NonZeroU32) -> Self {
        self.page_size = page_size;
        self
    }

    /// Bounds each history scan and all spentness queries together.
    pub fn with_max_pages(mut self, max_pages: NonZeroUsize) -> Self {
        self.max_pages = max_pages;
        self
    }

    /// An indexer behind `config.require_slot` would report a spent note as unspent.
    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.indexer_config = Some(config);
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
    /// The note at `context` and whether it reproduces the leaf there.
    fn note(
        &self,
        utxo: Utxo,
        context: &OutputContext,
        hashes: NoteDataHashes,
        tx: &ShieldedTransaction,
        slot_index: u32,
    ) -> Result<(WalletUtxo, bool), AuditError> {
        let commitment = utxo.hash(
            &self.address.nullifier_pubkey,
            &hashes.data_hash.unwrap_or_default(),
            &hashes.ring_data_hash.unwrap_or_default(),
            context.tree_id,
        )?;
        let note = WalletUtxo {
            nullifier: utxo.nullifier(&context.hash, self.nullifier_key)?,
            utxo,
            nullifier_pubkey: self.address.nullifier_pubkey,
            utxo_hash: context.hash,
            data_hash: hashes.data_hash,
            ring_data_hash: hashes.ring_data_hash,
            tree_id: context.tree_id,
            leaf_index: context.leaf_index,
            slot: tx.slot,
            tx_signature: tx.tx_signature,
            slot_index,
        };
        Ok((note, commitment == context.hash))
    }

    fn utxo(&self, asset: zolana_transaction::Mint, amount: u64, blinding: [u8; 32]) -> Utxo {
        Utxo {
            owner: self.address.signing_pubkey,
            asset,
            amount,
            blinding,
            ring_program_id: None,
            data: Data::default(),
        }
    }
}

/// Notes found so far, by the commitments already claimed.
#[derive(Default)]
struct Found {
    candidates: Vec<WalletUtxo>,
    /// Commitments without a verified opening, with their nullifiers.
    unresolved: Vec<([u8; 32], [u8; 32])>,
    seen: HashSet<[u8; 32]>,
}

impl<'a> MemberRecovery<'a> {
    pub fn with_data_hashes(mut self, resolver: &'a NoteHashResolver<'a>) -> Self {
        self.data_hashes = Some(resolver);
        self
    }

    pub async fn run<I: AsyncRpc, O: TransactionOrigin>(
        self,
        indexer: &I,
        origin: &O,
        assets: &AssetRegistry,
    ) -> Result<RecoveredNotes, AuditError> {
        // The nullifier key must derive the requested address.
        if self.source.nullifier_key.pubkey()? != self.source.address.nullifier_pubkey {
            return Err(AuditError::NullifierKeyMismatch);
        }
        let member = Member::owner_tag(&self.source.address.confidential_view_tag()?)?;
        let recovery = &self.recovery;
        let page = RingScan::new(recovery.ring_program_id, recovery.auditor.pubkey())
            .with_page_size(recovery.page_size)
            .with_max_pages(recovery.max_pages)
            .indexer_config(recovery.indexer_config)
            .run(indexer, origin)
            .await?;
        if page.next_cursor.is_some() {
            return Err(AuditError::IncompleteScan);
        }
        let mut found = Found::default();
        for transaction in &page.transactions {
            self.audited_notes(transaction, member, assets, &mut found)?;
        }
        let deposits = self.deposit_history(indexer, origin).await?;
        let unsupported_deposits = self.deposited_notes(&deposits, assets, &mut found)?;
        let (spent, merges) = self.follow_spends(indexer, origin, &mut found).await?;
        let mut unopened: Vec<_> = found
            .unresolved
            .into_iter()
            .filter(|(_, nullifier)| !spent.contains(nullifier))
            .map(|(commitment, _)| commitment)
            .collect();
        unopened.extend(
            merges
                .iter()
                .map(|merge| merge.output_slots[0].output_context.hash)
                .filter(|commitment| !found.seen.contains(commitment)),
        );
        Ok(RecoveredNotes {
            utxos: found
                .candidates
                .into_iter()
                .filter(|candidate| !spent.contains(&candidate.nullifier))
                .collect(),
            unopened,
            unsupported_deposits,
        })
    }

    /// The source's outputs in one audited transaction, proof-bound hashes first.
    fn audited_notes(
        &self,
        transaction: &ShieldedTransaction,
        member: Member,
        assets: &AssetRegistry,
        found: &mut Found,
    ) -> Result<(), AuditError> {
        let audited = TransactionAudit {
            auditor: self.recovery.auditor,
            transaction,
            assets,
        }
        .run()?;
        for output in &audited.outputs {
            if output.recipient_viewing_pk != self.source.address.viewing_pubkey
                || Member::owner_tag(&output.owner_tag)? != member
                || output.ring_program_id != Some(self.recovery.ring_program_id)
            {
                continue;
            }
            let context = &transaction
                .output_slots
                .get(output.slot_index as usize)
                .ok_or(AuditError::MissingOutputSlot(output.slot_index))?
                .output_context;
            if !found.seen.insert(context.hash) {
                continue;
            }
            let disclosed =
                audited
                    .output_openings
                    .get(output.slot_index as usize)
                    .map(|opening| NoteDataHashes {
                        data_hash: Some(opening.data_hash).filter(|hash| *hash != [0; 32]),
                        ring_data_hash: Some(opening.ring_data_hash)
                            .filter(|hash| *hash != [0; 32]),
                    });
            let hashes = match (disclosed, self.data_hashes) {
                (Some(disclosed), _) => disclosed,
                (None, Some(resolver)) => resolver(output, context)?.unwrap_or_default(),
                (None, None) => NoteDataHashes::default(),
            };
            let utxo = Utxo {
                ring_program_id: output.ring_program_id,
                data: output.data.clone(),
                ..self
                    .source
                    .utxo(assets.mint(&output.asset)?, output.amount, *output.blinding)
            };
            match self
                .source
                .note(utxo, context, hashes, transaction, output.slot_index)?
            {
                (note, true) => found.candidates.push(note),
                (note, false) => found.unresolved.push((context.hash, note.nullifier)),
            }
        }
        Ok(())
    }

    /// Proofless ring transactions the ring invoked, the deposits among them.
    async fn deposit_history<I: AsyncRpc, O: TransactionOrigin>(
        &self,
        indexer: &I,
        origin: &O,
    ) -> Result<Vec<ShieldedTransaction>, AuditError> {
        let RingRecovery {
            ring_program_id,
            page_size,
            max_pages,
            indexer_config,
            ..
        } = self.recovery;
        let (page, _) = pages(None, max_pages, |cursor| async move {
            let options = RingHistoryOptions {
                ring_program_id,
                cursor,
                limit: Some(page_size.get()),
            };
            let page = indexer
                .get_shielded_transactions_by_ring(options, indexer_config)
                .await?;
            Ok((page.transactions, page.next_cursor, page.scanned_through))
        })
        .await?;
        if page.next_cursor.is_some() {
            return Err(AuditError::IncompleteScan);
        }
        let mut deposits = Vec::new();
        for transaction in page.transactions {
            if !transaction.proofless
                || !transaction
                    .output_slots
                    .iter()
                    .any(|slot| deposit_output(slot, ring_program_id).is_some())
            {
                continue;
            }
            let event_index = transaction
                .event_index
                .ok_or(AuditError::MissingEventIndex)?;
            if origin
                .origin(transaction.tx_signature, event_index, ring_program_id)
                .await?
                .ring_invoked
            {
                deposits.push(transaction);
            }
        }
        Ok(deposits)
    }

    /// Disclosed deposits are found without trusting their recipient view tags.
    fn deposited_notes(
        &self,
        deposits: &[ShieldedTransaction],
        assets: &AssetRegistry,
        found: &mut Found,
    ) -> Result<Vec<[u8; 32]>, AuditError> {
        let ring = self.recovery.ring_program_id;
        let owner_hash = self.source.address.owner_hash()?;
        let bootstrap_tag = self.source.address.viewing_pubkey.x();
        let mut processed = HashSet::new();
        let mut unsupported = Vec::new();
        for transaction in deposits {
            for (slot_index, slot) in transaction.output_slots.iter().enumerate() {
                let Some(output) = deposit_output(slot, ring) else {
                    continue;
                };
                let context = &slot.output_context;
                if !processed.insert(context.hash) || found.seen.contains(&context.hash) {
                    continue;
                }
                let opening = RingDepositAuditCapsule::parse(&output.encrypted.ciphertext)
                    .ok()
                    .flatten()
                    .and_then(|capsule| {
                        open_deposit(&capsule, self.recovery.auditor, &output.owner_utxo_hash).ok()
                    });
                let Some(opening) = opening else {
                    if slot.view_tag == bootstrap_tag {
                        unsupported.push(context.hash);
                    }
                    continue;
                };
                if opening.owner_hash != owner_hash {
                    continue;
                }
                let utxo = Utxo {
                    ring_program_id: Some(ring),
                    ..self.source.utxo(
                        assets.mint(&Address::new_from_array(output.asset))?,
                        output.amount,
                        *opening.blinding,
                    )
                };
                let hashes = NoteDataHashes {
                    data_hash: output.data_hash,
                    ring_data_hash: Some(output.ring_data_hash),
                };
                let (note, opens) =
                    self.source
                        .note(utxo, context, hashes, transaction, slot_index as u32)?;
                if !opens {
                    return Err(AuditError::DepositOpeningMismatch);
                }
                found.seen.insert(context.hash);
                found.candidates.push(note);
            }
        }
        Ok(unsupported)
    }

    /// Spent nullifiers and the ring merges that spent the source's notes, every rebuilt
    /// merge successor checked for its own spend.
    async fn follow_spends<I: AsyncRpc, O: TransactionOrigin>(
        &self,
        indexer: &I,
        origin: &O,
        found: &mut Found,
    ) -> Result<(HashSet<[u8; 32]>, Vec<ShieldedTransaction>), AuditError> {
        let ring = self.recovery.ring_program_id;
        let mut nullifiers: Vec<_> = found
            .candidates
            .iter()
            .map(|candidate| candidate.nullifier)
            .chain(found.unresolved.iter().map(|(_, nullifier)| *nullifier))
            .collect();
        let mut spent = HashSet::new();
        let mut merges: Vec<ShieldedTransaction> = Vec::new();
        let mut merge_outputs = HashSet::new();
        let mut remaining = self.recovery.max_pages.get();
        loop {
            for transaction in self
                .spend_history(indexer, &nullifiers, &mut remaining)
                .await?
            {
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
                    || merge_circuit_width(transaction.nullifiers.len()).is_none()
                    || merge_outputs.contains(&transaction.output_slots[0].output_context.hash)
                {
                    continue;
                }
                let event_index = transaction
                    .event_index
                    .ok_or(AuditError::MissingEventIndex)?;
                if origin
                    .origin(transaction.tx_signature, event_index, ring)
                    .await?
                    .ring_invoked
                {
                    merge_outputs.insert(transaction.output_slots[0].output_context.hash);
                    merges.push(transaction);
                }
            }
            let previous = found.candidates.len();
            for transaction in &merges {
                let output = &transaction.output_slots[0].output_context;
                if found.seen.contains(&output.hash) {
                    continue;
                }
                if let Some(successor) =
                    merge_successor(&self.source, transaction, &found.candidates)?
                {
                    found.seen.insert(output.hash);
                    found.candidates.push(successor);
                }
            }
            if previous == found.candidates.len() {
                return Ok((spent, merges));
            }
            nullifiers = found.candidates[previous..]
                .iter()
                .map(|candidate| candidate.nullifier)
                .collect();
        }
    }

    /// Every transaction spending one of `nullifiers`, `remaining` bounds the queries.
    async fn spend_history<I: AsyncRpc>(
        &self,
        indexer: &I,
        nullifiers: &[[u8; 32]],
        remaining: &mut usize,
    ) -> Result<Vec<ShieldedTransaction>, AuditError> {
        let config = self.recovery.indexer_config;
        let mut transactions = Vec::new();
        for batch in nullifiers.chunks(PAGE_LIMIT as usize) {
            let budget = NonZeroUsize::new(*remaining).ok_or(AuditError::IncompleteScan)?;
            let (page, read) = pages(None, budget, |cursor| async move {
                let page = indexer
                    .get_shielded_transactions_by_nullifiers(batch.to_vec(), cursor, None, config)
                    .await?;
                Ok((page.transactions, page.next_cursor, page.scanned_through))
            })
            .await?;
            *remaining -= read;
            if page.next_cursor.is_some() {
                return Err(AuditError::IncompleteScan);
            }
            transactions.extend(page.transactions);
        }
        Ok(transactions)
    }
}

fn deposit_output(slot: &OutputSlot, ring: Address) -> Option<EncryptedRingDepositOutput> {
    decode_encrypted_ring_deposit_output_data(&slot.payload)
        .ok()
        .filter(|output| output.ring_program_id == ring.to_bytes())
}

/// The merge output rebuilt from its known inputs, `None` unless it reproduces the leaf.
fn merge_successor(
    source: &SourceMember<'_>,
    transaction: &ShieldedTransaction,
    candidates: &[WalletUtxo],
) -> Result<Option<WalletUtxo>, AuditError> {
    let known = |nullifier: &[u8; 32]| candidates.iter().find(|note| note.nullifier == *nullifier);
    let Some((first_nullifier, first)) = transaction
        .nullifiers
        .first()
        .and_then(|nullifier| Some((nullifier, known(nullifier)?)))
    else {
        return Ok(None);
    };
    let mut amount = 0u64;
    for (index, nullifier) in transaction.nullifiers.iter().enumerate() {
        if *nullifier == merge_dummy_nullifier(source.nullifier_key, first_nullifier, index as u8)?
        {
            continue;
        }
        let Some(note) = known(nullifier).filter(|note| {
            note.utxo.asset == first.utxo.asset
                && note.utxo.ring_program_id == first.utxo.ring_program_id
                && note.data_hash.is_none_or(|hash| hash == [0; 32])
        }) else {
            return Ok(None);
        };
        amount = amount
            .checked_add(note.utxo.amount)
            .ok_or(TransactionError::SelectedBalanceOverflow)?;
    }
    let slot = &transaction.output_slots[0];
    let Ok(ring_data_hash) = <[u8; 32]>::try_from(slot.payload.as_slice()) else {
        return Ok(None);
    };
    let utxo = Utxo {
        ring_program_id: first.utxo.ring_program_id,
        ..source.utxo(
            first.utxo.asset,
            amount,
            merge_output_blinding(source.nullifier_key, first_nullifier)?,
        )
    };
    let hashes = NoteDataHashes {
        data_hash: None,
        ring_data_hash: Some(ring_data_hash),
    };
    let context = &slot.output_context;
    let (successor, opens) = source.note(utxo, context, hashes, transaction, 0)?;
    Ok(opens.then_some(successor))
}
