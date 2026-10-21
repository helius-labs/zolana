//! The notes a ring's auditor opened and the nullifier keys its registry escrows.

use std::{
    collections::{hash_map::Entry, HashMap},
    sync::{PoisonError, RwLock},
    time::Duration,
};

use solana_signature::Signature;
use tokio::sync::Mutex as AsyncMutex;
use zolana_client::ShieldedTransaction;
use zolana_indexer_api::{Context, Hash};
use zolana_ring_client::{
    rpc::AuditedNoteView, AuditedTransaction, CreatedNote, EscrowedKeys, KnownNote, KnownNotes,
};

pub const NOTE_BACKFILL_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StoredNote {
    note: KnownNote,
    slot: u64,
    tx_signature: Signature,
    event_index: u16,
    slot_index: u32,
}

#[derive(Default)]
struct EscrowMap {
    root: Option<[u8; 32]>,
    keys: HashMap<[u8; 32], [u8; 32]>,
}

/// The guards are never held across an await, the audit reads them synchronously.
#[derive(Default)]
pub(crate) struct AuditStore {
    notes: RwLock<HashMap<[u8; 32], StoredNote>>,
    escrow: RwLock<EscrowMap>,
    /// The indexer context of the backfill's newest page.
    context: RwLock<Context>,
    /// The ring history position the next backfill resumes from, one backfill at a time.
    pub(crate) backfill: AsyncMutex<Option<Vec<u8>>>,
}

impl AuditStore {
    pub(crate) fn record(&self, audited: &AuditedTransaction, event_index: u16) {
        self.insert(audited.outputs.iter().filter_map(|output| {
            let note = output.opening.note()?;
            Some((
                output.context.hash,
                StoredNote {
                    note: KnownNote::from(*note),
                    slot: audited.slot,
                    tx_signature: audited.tx_signature,
                    event_index,
                    slot_index: output.slot_index,
                },
            ))
        }));
    }

    /// `transaction` is the confirmed deposit or merge that created `created`.
    pub(crate) fn record_created(
        &self,
        transaction: &ShieldedTransaction,
        event_index: u16,
        created: &[CreatedNote],
    ) {
        self.insert(created.iter().map(|created| {
            (
                created.commitment,
                StoredNote {
                    note: created.note,
                    slot: transaction.slot,
                    tx_signature: transaction.tx_signature,
                    event_index,
                    slot_index: created.slot_index,
                },
            )
        }));
    }

    /// A page older than the newest absorbed leaves the context.
    pub(crate) fn absorbed(&self, context: Context) {
        let mut newest = self.context.write().unwrap_or_else(PoisonError::into_inner);
        if context.slot >= newest.slot {
            *newest = context;
        }
    }

    pub(crate) fn context(&self) -> Context {
        self.context
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn view(&self, utxo_hash: &Hash) -> Option<AuditedNoteView> {
        let stored = self.stored(&utxo_hash.0)?;
        Some(AuditedNoteView {
            utxo_hash: Hash(utxo_hash.0),
            note: stored.note.into(),
            slot: stored.slot,
            tx_signature: stored.tx_signature.into(),
            event_index: stored.event_index,
            slot_index: stored.slot_index,
        })
    }

    pub(crate) fn escrow_root(&self) -> Option<[u8; 32]> {
        self.escrow
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .root
    }

    /// Every key the registry escrows under `root`, the map read under an older root goes.
    pub(crate) fn replace_escrow(&self, root: [u8; 32], keys: HashMap<[u8; 32], [u8; 32]>) {
        *self.escrow.write().unwrap_or_else(PoisonError::into_inner) = EscrowMap {
            root: Some(root),
            keys,
        };
    }

    /// The hash binds every opened field, a later opening replaces an entry only to add its mint.
    fn insert(&self, opened: impl Iterator<Item = ([u8; 32], StoredNote)>) {
        let mut notes = self.notes.write().unwrap_or_else(PoisonError::into_inner);
        for (utxo_hash, stored) in opened {
            match notes.entry(utxo_hash) {
                Entry::Occupied(mut kept) if kept.get().note.mint.is_none() => {
                    kept.insert(stored);
                }
                Entry::Occupied(_) => {}
                Entry::Vacant(free) => {
                    free.insert(stored);
                }
            }
        }
    }

    fn stored(&self, utxo_hash: &[u8; 32]) -> Option<StoredNote> {
        self.notes
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(utxo_hash)
            .copied()
    }
}

impl KnownNotes for AuditStore {
    fn note(&self, commitment: &[u8; 32]) -> Option<KnownNote> {
        self.stored(commitment).map(|stored| stored.note)
    }
}

impl EscrowedKeys for AuditStore {
    fn nullifier_pk(&self, owner_key: &[u8; 32]) -> Option<[u8; 32]> {
        self.escrow
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .keys
            .get(owner_key)
            .copied()
    }
}
