//! Rebuilds a source member's unspent ring notes from what the auditor sees.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    num::{NonZeroU32, NonZeroUsize},
};

use custom_ring_interface::{RingDepositAuditCapsule, RingMode};
use solana_address::Address;
use zolana_client::{AsyncRpc, IndexerRpcConfig, RingHistoryOptions};
use zolana_event::{
    split_merge_output_body, EncryptedRingDepositOutput, OutputDataEncoding, MERGE_OUTPUT_SCHEME,
};
use zolana_event_parser::decode_encrypted_ring_deposit_output_data;
use zolana_indexer_api::PAGE_LIMIT;
use zolana_keypair::{NullifierKey, ShieldedAddress, X25519Keypair};
use zolana_transaction::{
    instructions::merge::{
        merge_circuit_width, merge_output_blinding, merge_output_key, MergeOutputPlaintext,
    },
    AssetRegistry, Data, OutputContext, OutputSlot, ShieldedTransaction, TransactionError, Utxo,
    WalletUtxo,
};

use crate::{
    decrypt::TransactionAudit,
    encryption::open_deposit,
    origin::{RingOrigin, TransactionOrigin},
    scan::{pages, RingScan},
    types::{OutputOpening, OutputPayloadErrorKind},
    AuditError,
};

const DEFAULT_MAX_PAGES: NonZeroUsize = NonZeroUsize::new(4096).unwrap();
const DEFAULT_PAGE_SIZE: NonZeroU32 = NonZeroU32::new(1000).unwrap();

#[must_use = "run the recovery explicitly"]
pub struct RingRecovery<'a> {
    ring_program_id: Address,
    auditor: &'a X25519Keypair,
    mode: RingMode,
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
}

/// Application commitments supplied by the note's protocol.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NoteDataHashes {
    pub data_hash: Option<[u8; 32]>,
    pub ring_data_hash: Option<[u8; 32]>,
}

/// Verified unspent notes with the coverage left unresolved.
pub struct RecoveredNotes {
    pub utxos: Vec<WalletUtxo>,
    /// Commitments that cannot yet become spendable notes, including unknown mints.
    pub unopened: Vec<[u8; 32]>,
    /// Tagged deposits whose ownership and spentness are unknown.
    pub unsupported_deposits: Vec<[u8; 32]>,
    /// Verified merge mints the asset registry lacks, their notes stay unresolved.
    pub unknown_mints: BTreeSet<Address>,
}

impl<'a> RingRecovery<'a> {
    pub fn new(ring_program_id: Address, auditor: &'a X25519Keypair) -> Self {
        Self {
            ring_program_id,
            auditor,
            mode: RingMode::Off,
            page_size: DEFAULT_PAGE_SIZE,
            max_pages: DEFAULT_MAX_PAGES,
            indexer_config: None,
        }
    }

    pub fn with_page_size(mut self, page_size: NonZeroU32) -> Self {
        self.page_size = page_size;
        self
    }

    /// The rail a ring `Transact` frame parses under.
    pub fn with_mode(mut self, mode: RingMode) -> Self {
        self.mode = mode;
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
            tx_viewing_key: None,
            data_hash: hashes.data_hash,
            ring_data_hash: hashes.ring_data_hash,
            tree_id: context.tree_id,
            leaf_index: context.leaf_index,
            latest_tree_id: None,
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
    unknown_mints: BTreeSet<Address>,
}

impl<'a> MemberRecovery<'a> {
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
        let owner_hash = self.source.address.owner_hash()?;
        let recovery = &self.recovery;
        let page = RingScan::new(recovery.ring_program_id, recovery.auditor.pubkey())
            .with_page_size(recovery.page_size)
            .with_max_pages(recovery.max_pages)
            .indexer_config(recovery.indexer_config)
            .confirmed(indexer, origin)
            .await?;
        if page.next_cursor.is_some() {
            return Err(AuditError::IncompleteScan);
        }
        let mut found = Found::default();
        for confirmed in &page.transactions {
            self.audited_notes(confirmed, owner_hash, assets, &mut found)?;
        }
        let deposits = self.deposit_history(indexer, origin).await?;
        let unsupported_deposits = self.deposited_notes(&deposits, assets, &mut found)?;
        let (spent, merges) = self
            .follow_spends(indexer, origin, assets, &mut found)
            .await?;
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
            unknown_mints: found.unknown_mints,
        })
    }

    /// The source's ring outputs in one audited transaction, every opening already proof-bound.
    fn audited_notes(
        &self,
        (transaction, origin): &(ShieldedTransaction, RingOrigin),
        owner_hash: [u8; 32],
        assets: &AssetRegistry,
        found: &mut Found,
    ) -> Result<(), AuditError> {
        let layout = origin.disclosure_layout(self.recovery.mode)?;
        let source_key = HashMap::from([(
            self.source.address.signing_pubkey.confidential_view_tag()?,
            self.source.address.nullifier_pubkey,
        )]);
        let audited = TransactionAudit::new(transaction, layout)
            .with_escrowed_keys(&source_key)
            .run(self.recovery.auditor, assets)?;
        // Any unopened slot but another owner's escrow miss could hide a source note.
        if let Some(error) = audited
            .payload_errors
            .iter()
            .find(|error| error.kind != OutputPayloadErrorKind::EscrowUnknown)
        {
            return Err(AuditError::UnopenedOutput {
                slot: error.slot_index,
                kind: error.kind,
            });
        }
        for output in &audited.outputs {
            let OutputOpening::Ring { note, .. } = &output.opening else {
                continue;
            };
            let context = &output.context;
            if note.owner_hash()? != owner_hash || !found.seen.insert(context.hash) {
                continue;
            }
            let mint = match note.mint.map(|mint| assets.mint(&mint)).transpose() {
                Ok(mint) => mint,
                Err(TransactionError::UnknownMint(mint)) => {
                    found.unknown_mints.insert(mint);
                    None
                }
                Err(error) => return Err(error.into()),
            };
            let Some(mint) = mint else {
                // Ownership and spentness remain known even without the asset preimage.
                found.unresolved.push((
                    context.hash,
                    self.source
                        .nullifier_key
                        .nullifier(&context.hash, &note.blinding)?,
                ));
                continue;
            };
            let hashes = NoteDataHashes {
                data_hash: Some(note.data_hash).filter(|hash| *hash != [0; 32]),
                ring_data_hash: Some(note.ring_data_hash).filter(|hash| *hash != [0; 32]),
            };
            let utxo = Utxo {
                ring_program_id: Some(self.recovery.ring_program_id),
                ..self.source.utxo(mint, note.amount, note.blinding)
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
    ) -> Result<Vec<(ShieldedTransaction, Vec<crate::ConfirmedDeposit>)>, AuditError> {
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
        for mut transaction in page.transactions {
            let event_index = transaction
                .event_index
                .ok_or(AuditError::MissingEventIndex)?;
            let confirmed = origin
                .origin(transaction.tx_signature, event_index, ring_program_id)
                .await?;
            if confirmed.ring_invoked
                && confirmed.event.kind() == crate::ConfirmedEventKind::Deposit
            {
                confirmed.bind_transaction(&mut transaction, ring_program_id)?;
                deposits.push((transaction, confirmed.deposits));
            }
        }
        Ok(deposits)
    }

    /// Disclosed deposits are found without trusting their recipient view tags.
    fn deposited_notes(
        &self,
        deposits: &[(ShieldedTransaction, Vec<crate::ConfirmedDeposit>)],
        assets: &AssetRegistry,
        found: &mut Found,
    ) -> Result<Vec<[u8; 32]>, AuditError> {
        let ring = self.recovery.ring_program_id;
        let owner_hash = self.source.address.owner_hash()?;
        let mut processed = HashSet::new();
        let mut unsupported = Vec::new();
        for (transaction, confirmed) in deposits {
            for (slot_index, slot) in transaction.output_slots.iter().enumerate() {
                let Some(output) = deposit_output(slot, ring) else {
                    continue;
                };
                let context = &slot.output_context;
                if !processed.insert(context.hash) || found.seen.contains(&context.hash) {
                    continue;
                }
                let Some(binding) = confirmed
                    .iter()
                    .find(|binding| usize::from(binding.slot_index()) == slot_index)
                else {
                    unsupported.push(context.hash);
                    continue;
                };
                let capsule = RingDepositAuditCapsule::parse(&output.encrypted.ciphertext)
                    .map_err(|_| AuditError::DepositOpeningMismatch)?
                    .ok_or(AuditError::DepositOpeningMismatch)?;
                let Ok(opening) = open_deposit(
                    &capsule,
                    self.recovery.auditor,
                    &output.owner_utxo_hash,
                    binding,
                ) else {
                    unsupported.push(context.hash);
                    continue;
                };
                if opening.owner_hash != owner_hash {
                    continue;
                }
                let asset = Address::new_from_array(output.asset);
                // The deposit proof binds the raw mint, the commitment verifies without a registry id.
                let mint = match assets.mint(&asset) {
                    Ok(mint) => Some(mint),
                    Err(TransactionError::UnknownMint(_)) => None,
                    Err(error) => return Err(error.into()),
                };
                let utxo = Utxo {
                    ring_program_id: Some(ring),
                    ..self.source.utxo(
                        mint.unwrap_or_else(|| zolana_transaction::Mint::new(asset, 0)),
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
                if mint.is_some() {
                    found.candidates.push(note);
                } else {
                    found.unknown_mints.insert(asset);
                    found.unresolved.push((context.hash, note.nullifier));
                }
            }
        }
        Ok(unsupported)
    }

    /// Spent nullifiers and the merges that spent the source's notes, each successor checked too.
    async fn follow_spends<I: AsyncRpc, O: TransactionOrigin>(
        &self,
        indexer: &I,
        origin: &O,
        assets: &AssetRegistry,
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
            for mut transaction in self
                .spend_history(indexer, &nullifiers, &mut remaining)
                .await?
            {
                let event_index = transaction
                    .event_index
                    .ok_or(AuditError::MissingEventIndex)?;
                let confirmed = origin
                    .origin(transaction.tx_signature, event_index, ring)
                    .await?;
                if !confirmed.ring_invoked {
                    continue;
                }
                confirmed.bind_transaction(&mut transaction, ring)?;
                if !transaction
                    .nullifiers
                    .iter()
                    .any(|nullifier| nullifiers.contains(nullifier))
                {
                    continue;
                }
                spent.extend(transaction.nullifiers.iter().copied());
                if confirmed.event.kind() != crate::ConfirmedEventKind::Merge
                    || transaction.output_slots.len() != 1
                    || merge_circuit_width(transaction.nullifiers.len()).is_none()
                    || merge_outputs.contains(&transaction.output_slots[0].output_context.hash)
                {
                    continue;
                }
                merge_outputs.insert(transaction.output_slots[0].output_context.hash);
                merges.push(transaction);
            }
            let previous = found.candidates.len();
            let previous_unresolved = found.unresolved.len();
            for transaction in &merges {
                let output = &transaction.output_slots[0].output_context;
                if found.seen.contains(&output.hash) {
                    continue;
                }
                let Some(mut successor) = merge_successor(&self.source, transaction, ring)? else {
                    continue;
                };
                found.seen.insert(output.hash);
                match assets.mint(&successor.utxo.asset.asset) {
                    Ok(mint) => {
                        successor.utxo.asset = mint;
                        found.candidates.push(successor);
                    }
                    Err(TransactionError::UnknownMint(mint)) => {
                        found.unknown_mints.insert(mint);
                        found
                            .unresolved
                            .push((successor.utxo_hash, successor.nullifier));
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            if previous == found.candidates.len() && previous_unresolved == found.unresolved.len() {
                return Ok((spent, merges));
            }
            nullifiers = found.candidates[previous..]
                .iter()
                .map(|candidate| candidate.nullifier)
                .chain(
                    found.unresolved[previous_unresolved..]
                        .iter()
                        .map(|(_, nullifier)| *nullifier),
                )
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

pub(crate) fn deposit_output(
    slot: &OutputSlot,
    ring: Address,
) -> Option<EncryptedRingDepositOutput> {
    decode_encrypted_ring_deposit_output_data(&slot.payload)
        .ok()
        .filter(|output| output.ring_program_id == ring.to_bytes())
}

/// A temporary asset id verifies the commitment before the registry lookup.
fn merge_successor(
    source: &SourceMember<'_>,
    transaction: &ShieldedTransaction,
    ring: Address,
) -> Result<Option<WalletUtxo>, AuditError> {
    let Some(first_nullifier) = transaction.nullifiers.first() else {
        return Ok(None);
    };
    let Some(slot) = transaction.output_slots.first() else {
        return Ok(None);
    };
    let Some(OutputDataEncoding::VerifiablyEncrypted(blob)) = slot.output_data() else {
        return Ok(None);
    };
    let Some((&MERGE_OUTPUT_SCHEME, body)) = blob.split_first() else {
        return Ok(None);
    };
    let Some((Some(&ring_data_hash), encrypted)) = split_merge_output_body(body) else {
        return Ok(None);
    };
    let key = merge_output_key(source.nullifier_key, first_nullifier)?;
    let Ok(plaintext) = MergeOutputPlaintext::decrypt(encrypted, &key) else {
        return Ok(None);
    };
    let utxo = plaintext.into_utxo(
        source.address.signing_pubkey,
        zolana_transaction::Mint::new(plaintext.mint, 0),
        merge_output_blinding(source.nullifier_key, first_nullifier)?,
        Some(ring),
    );
    let hashes = NoteDataHashes {
        data_hash: None,
        ring_data_hash: Some(ring_data_hash),
    };
    let (successor, opens) = source.note(utxo, &slot.output_context, hashes, transaction, 0)?;
    Ok(opens.then_some(successor))
}
