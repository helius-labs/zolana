//! Ring notes of deposits and anonymous merges, a commitment layout spends them by hash alone.

use std::num::{NonZeroU32, NonZeroUsize};

use custom_ring_interface::RingDepositAuditCapsule;
use solana_address::Address;
use zolana_client::{
    AsyncRpc, IndexerRpcConfig, ProofInputUtxo, RingHistoryOptions, ShieldedTransaction,
};
use zolana_hasher::primitives::hash_bytes;
use zolana_keypair::X25519Keypair;

use crate::{
    encryption::open_deposit,
    merge_audit::MergeOutput,
    origin::{ConfirmedEventKind, RingOrigin, TransactionOrigin},
    recover::deposit_output,
    scan::{pages, DEFAULT_MAX_PAGES, DEFAULT_PAGE_SIZE},
    types::KnownNote,
    AuditError,
};

/// `transaction` is bound to `origin` through [`RingOrigin::bind_transaction`].
#[must_use = "open the notes explicitly"]
pub struct CreatedNotes<'a> {
    pub transaction: &'a ShieldedTransaction,
    pub origin: &'a RingOrigin,
    pub ring: Address,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreatedNote {
    pub commitment: [u8; 32],
    pub slot_index: u32,
    pub note: KnownNote,
}

#[must_use = "run or discard the scan explicitly"]
pub struct CreatedNoteScan {
    ring: Address,
    cursor: Option<Vec<u8>>,
    page_size: NonZeroU32,
    max_pages: NonZeroUsize,
    indexer_config: Option<IndexerRpcConfig>,
}

/// `next_cursor` is live only when the page cap stopped the read.
pub struct CreatedNotePage {
    pub notes: Vec<CreatedNote>,
    pub next_cursor: Option<Vec<u8>>,
}

impl CreatedNoteScan {
    pub fn new(ring: Address) -> Self {
        Self {
            ring,
            cursor: None,
            page_size: DEFAULT_PAGE_SIZE,
            max_pages: DEFAULT_MAX_PAGES,
            indexer_config: None,
        }
    }

    pub fn with_cursor(mut self, cursor: Vec<u8>) -> Self {
        self.cursor = Some(cursor);
        self
    }

    pub fn with_page_size(mut self, page_size: NonZeroU32) -> Self {
        self.page_size = page_size;
        self
    }

    pub fn with_max_pages(mut self, max_pages: NonZeroUsize) -> Self {
        self.max_pages = max_pages;
        self
    }

    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.indexer_config = Some(config);
        self
    }

    pub async fn run<I: AsyncRpc, O: TransactionOrigin>(
        self,
        auditor: &X25519Keypair,
        indexer: &I,
        origin: &O,
    ) -> Result<CreatedNotePage, AuditError> {
        let Self {
            ring,
            cursor,
            page_size,
            max_pages,
            indexer_config,
        } = self;
        let (page, _) = pages(cursor, max_pages, |cursor| async move {
            let options = RingHistoryOptions {
                ring_program_id: ring,
                cursor,
                limit: Some(page_size.get()),
            };
            let page = indexer
                .get_shielded_transactions_by_ring(options, indexer_config)
                .await?;
            Ok((page.transactions, page.next_cursor, page.scanned_through))
        })
        .await?;
        let mut notes = Vec::new();
        for mut transaction in page.transactions {
            let event_index = transaction
                .event_index
                .ok_or(AuditError::MissingEventIndex)?;
            let confirmed = origin
                .origin(transaction.tx_signature, event_index, ring)
                .await?;
            if !confirmed.ring_invoked || confirmed.event.kind() == ConfirmedEventKind::Transfer {
                continue;
            }
            confirmed.bind_transaction(&mut transaction, ring)?;
            notes.extend(
                CreatedNotes {
                    transaction: &transaction,
                    origin: &confirmed,
                    ring,
                }
                .open(auditor)?,
            );
        }
        Ok(CreatedNotePage {
            notes,
            next_cursor: page.next_cursor,
        })
    }
}

impl CreatedNotes<'_> {
    /// Empty for a transfer and for a confidential ring's deposit or merge.
    pub fn open(self, auditor: &X25519Keypair) -> Result<Vec<CreatedNote>, AuditError> {
        if !self.origin.ring_invoked {
            return Ok(Vec::new());
        }
        match self.origin.event.kind() {
            ConfirmedEventKind::Deposit => self.deposits(auditor),
            ConfirmedEventKind::Merge => self.merge(auditor),
            ConfirmedEventKind::Transfer => Ok(Vec::new()),
        }
    }

    fn deposits(&self, auditor: &X25519Keypair) -> Result<Vec<CreatedNote>, AuditError> {
        let mut notes = Vec::new();
        for (slot_index, slot) in (0u32..).zip(&self.transaction.output_slots) {
            let Some(output) = deposit_output(slot, self.ring) else {
                continue;
            };
            let Some(binding) = self
                .origin
                .deposits
                .iter()
                .find(|binding| u32::from(binding.slot_index()) == slot_index)
            else {
                continue;
            };
            let capsule = RingDepositAuditCapsule::parse(&output.encrypted.ciphertext)
                .ok()
                .flatten()
                .ok_or(AuditError::DepositOpeningMismatch)?;
            let opening = open_deposit(&capsule, auditor, &output.owner_utxo_hash, binding)?;
            // Only an anonymous ring's capsule names the owner key.
            let Some(owner_key) = opening.owner_key else {
                continue;
            };
            let mint = Address::new_from_array(output.asset);
            let data_hash = output.data_hash.unwrap_or_default();
            let context = &slot.output_context;
            let commitment = ProofInputUtxo::new(
                opening.owner_hash,
                &mint,
                output.amount,
                &opening.blinding,
                context.tree_id,
            )?
            .with_data_hash(data_hash)
            .with_ring(output.ring_data_hash, &Some(self.ring))?
            .hash()?;
            if commitment != context.hash {
                return Err(AuditError::DepositOpeningMismatch);
            }
            notes.push(CreatedNote {
                commitment,
                slot_index,
                note: KnownNote {
                    owner_key,
                    nullifier_pk: None,
                    asset: hash_bytes(mint.as_array())?,
                    mint: Some(mint),
                    amount: output.amount,
                    blinding: *opening.blinding,
                    data_hash,
                    ring_data_hash: output.ring_data_hash,
                },
            });
        }
        Ok(notes)
    }

    fn merge(&self, auditor: &X25519Keypair) -> Result<Vec<CreatedNote>, AuditError> {
        let Some(disclosure) = &self.origin.merge_disclosure else {
            return Ok(Vec::new());
        };
        let output = MergeOutput::of(self.transaction)?;
        let opening = output.disclose(auditor, disclosure, self.ring)?;
        let mint = Address::new_from_array(opening.mint);
        Ok(vec![CreatedNote {
            commitment: output.commitment,
            slot_index: 0,
            note: KnownNote {
                owner_key: opening.owner_key,
                nullifier_pk: Some(opening.nullifier_pk),
                asset: hash_bytes(mint.as_array())?,
                mint: Some(mint),
                amount: opening.amount,
                blinding: opening.output_blinding,
                data_hash: [0; 32],
                ring_data_hash: output.ring_data_hash,
            },
        }])
    }
}
