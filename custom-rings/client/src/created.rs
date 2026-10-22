//! Ring notes of deposits and anonymous merges, a commitment layout spends them by hash alone.

use std::num::{NonZeroU32, NonZeroUsize};

use custom_ring_interface::RingDepositAuditCapsule;
use solana_address::Address;
use zolana_client::{AsyncRpc, IndexerRpcConfig, ProofInputUtxo, ShieldedTransaction};
use zolana_event::EncryptedRingDepositOutput;
use zolana_hasher::primitives::hash_bytes;
use zolana_keypair::X25519Keypair;

use crate::{
    encryption::{open_deposit, DepositOpening},
    merge_audit::MergeOutput,
    origin::{ConfirmedDeposit, ConfirmedEventKind, RingOrigin, TransactionOrigin},
    recover::deposit_output,
    scan::{RingHistory, RING_HISTORY_MAX_PAGES, RING_HISTORY_PAGE_SIZE},
    types::{CreatedUtxo, KnownUtxo, UtxoOwner},
    AuditError,
};

/// `transaction` is bound to `origin` through [`RingOrigin::bind_transaction`].
#[must_use = "open the notes explicitly"]
pub struct CreatedUtxos<'a> {
    pub transaction: &'a ShieldedTransaction,
    pub origin: &'a RingOrigin,
    pub ring: Address,
}

#[must_use = "run or discard the scan explicitly"]
pub struct CreatedUtxoScan<'a> {
    ring: Address,
    auditor: &'a X25519Keypair,
    cursor: Option<Vec<u8>>,
    page_size: NonZeroU32,
    max_pages: NonZeroUsize,
    indexer_config: Option<IndexerRpcConfig>,
}

/// `next_cursor` is live only when the page cap stopped the read.
pub struct CreatedUtxoPage {
    pub utxos: Vec<CreatedUtxo>,
    pub next_cursor: Option<Vec<u8>>,
}

/// A deposit output beside the confirmed bindings of its transaction.
pub(crate) struct DepositSlot<'a> {
    pub output: &'a EncryptedRingDepositOutput,
    pub bindings: &'a [ConfirmedDeposit],
    pub slot_index: u32,
}

impl<'a> CreatedUtxoScan<'a> {
    pub fn new(ring: Address, auditor: &'a X25519Keypair) -> Self {
        Self {
            ring,
            auditor,
            cursor: None,
            page_size: RING_HISTORY_PAGE_SIZE,
            max_pages: RING_HISTORY_MAX_PAGES,
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
        indexer: &I,
        origin: &O,
    ) -> Result<CreatedUtxoPage, AuditError> {
        let Self {
            ring,
            auditor,
            cursor,
            page_size,
            max_pages,
            indexer_config,
        } = self;
        let page = RingHistory {
            ring,
            kinds: &[ConfirmedEventKind::Deposit, ConfirmedEventKind::Merge],
            cursor,
            page_size,
            max_pages,
            indexer_config,
        }
        .bound(indexer, origin)
        .await?;
        let mut utxos = Vec::new();
        for (transaction, confirmed) in &page.transactions {
            utxos.extend(
                CreatedUtxos {
                    transaction,
                    origin: confirmed,
                    ring,
                }
                .open(auditor)?,
            );
        }
        Ok(CreatedUtxoPage {
            utxos,
            next_cursor: page.next_cursor,
        })
    }
}

impl CreatedUtxos<'_> {
    /// Empty for a transfer and for a confidential ring's deposit or merge.
    pub fn open(self, auditor: &X25519Keypair) -> Result<Vec<CreatedUtxo>, AuditError> {
        match self.origin.event.kind() {
            ConfirmedEventKind::Deposit => self.deposits(auditor),
            ConfirmedEventKind::Merge => self.merge(auditor),
            ConfirmedEventKind::Transfer => Ok(Vec::new()),
        }
    }

    fn deposits(&self, auditor: &X25519Keypair) -> Result<Vec<CreatedUtxo>, AuditError> {
        let mut utxos = Vec::new();
        for (slot_index, slot) in (0u32..).zip(&self.transaction.output_slots) {
            let Some(output) = deposit_output(slot, self.ring) else {
                continue;
            };
            let Some(opening) = (DepositSlot {
                output: &output,
                bindings: &self.origin.deposits,
                slot_index,
            })
            .open(auditor)?
            else {
                continue;
            };
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
            utxos.push(CreatedUtxo {
                commitment,
                slot_index,
                utxo: KnownUtxo {
                    owner_key,
                    owner: UtxoOwner::Deposited {
                        owner_hash: opening.owner_hash,
                    },
                    asset: hash_bytes(mint.as_array())?,
                    mint: Some(mint),
                    amount: output.amount,
                    blinding: *opening.blinding,
                    data_hash,
                    ring_data_hash: output.ring_data_hash,
                    tree_id: context.tree_id,
                },
            });
        }
        Ok(utxos)
    }

    fn merge(&self, auditor: &X25519Keypair) -> Result<Vec<CreatedUtxo>, AuditError> {
        let Some(disclosure) = &self.origin.merge_disclosure else {
            return Ok(Vec::new());
        };
        let output = MergeOutput::of(self.transaction, self.ring)?;
        let opening = output.disclose(auditor, disclosure)?;
        let mint = Address::new_from_array(opening.mint);
        Ok(vec![CreatedUtxo {
            commitment: output.commitment,
            slot_index: 0,
            utxo: KnownUtxo {
                owner_key: opening.owner_key,
                owner: UtxoOwner::Keyed {
                    nullifier_pk: opening.nullifier_pk,
                },
                asset: hash_bytes(mint.as_array())?,
                mint: Some(mint),
                amount: opening.amount,
                blinding: opening.output_blinding,
                data_hash: [0; 32],
                ring_data_hash: output.ring_data_hash,
                tree_id: output.tree_id,
            },
        }])
    }
}

impl DepositSlot<'_> {
    /// `None` without a binding, the capsule proof covers a bound slot alone.
    pub(crate) fn open(
        self,
        auditor: &X25519Keypair,
    ) -> Result<Option<DepositOpening>, AuditError> {
        let Some(binding) = self
            .bindings
            .iter()
            .find(|binding| u32::from(binding.slot_index()) == self.slot_index)
        else {
            return Ok(None);
        };
        let capsule = RingDepositAuditCapsule::parse(&self.output.encrypted.ciphertext)
            .ok()
            .flatten()
            .ok_or(AuditError::DepositOpeningMismatch)?;
        open_deposit(&capsule, auditor, &self.output.owner_utxo_hash, binding).map(Some)
    }
}
