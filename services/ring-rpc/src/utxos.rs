//! The UTXOs a ring's auditor opened and the nullifier keys its registry escrows.

use std::{
    borrow::Borrow,
    collections::{BTreeMap, HashMap},
    ops::Range,
    sync::{PoisonError, RwLock, RwLockReadGuard},
    time::Duration,
};

use solana_signature::Signature;
use tokio::sync::Mutex as AsyncMutex;
use zolana_indexer_api::{Context, Hash, RingQueueEntryView};
use zolana_ring_client::{
    rpc::AuditedUtxoView, CreatedUtxo, EscrowedKeys, KnownUtxo, KnownUtxoIndex,
};

pub const UTXO_BACKFILL_INTERVAL: Duration = Duration::from_secs(30);

/// Pages one backfill run reads, the next run resumes from its cursor.
pub(crate) const MAX_BACKFILL_PAGES: usize = 64;

/// The guards are never held across an await, the audit reads them synchronously.
#[derive(Default)]
pub(crate) struct AuditStore {
    utxos: RwLock<KnownUtxoIndex<StoredUtxo>>,
    escrow: RwLock<EscrowMap>,
    /// The indexer context when the backfill last reached the scan frontier.
    context: RwLock<Context>,
    /// The ring history position the next backfill resumes from, one backfill and escrow
    /// refresh at a time.
    pub(crate) backfill: AsyncMutex<Option<Vec<u8>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CreatedIn {
    pub slot: u64,
    pub tx_signature: Signature,
    pub event_index: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EscrowRoot {
    pub root: [u8; 32],
    /// The queue head right after the application that pushed `root`.
    pub applied: u64,
}

/// Verified under the registry root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EscrowedOwner {
    pub owner_key: [u8; 32],
    pub nullifier_pk: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StoredUtxo {
    utxo: KnownUtxo,
    created_in: CreatedIn,
    slot_index: u32,
}

#[derive(Default)]
struct EscrowMap {
    root: Option<EscrowRoot>,
    keys: HashMap<[u8; 32], [u8; 32]>,
    /// A rewritten member drops the key it escrowed before.
    owners: HashMap<[u8; 32], [u8; 32]>,
    pending: BTreeMap<u64, [u8; 32]>,
}

impl AuditStore {
    pub(crate) fn record(
        &self,
        created_in: CreatedIn,
        utxos: impl IntoIterator<Item = CreatedUtxo>,
    ) {
        let mut stored = self.utxos.write().unwrap_or_else(PoisonError::into_inner);
        for created in utxos {
            stored.insert(
                created.commitment,
                StoredUtxo {
                    utxo: created.utxo,
                    created_in,
                    slot_index: created.slot_index,
                },
            );
        }
    }

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

    pub(crate) fn view(&self, utxo_hash: &Hash) -> Option<AuditedUtxoView> {
        let stored = self.stored(&utxo_hash.0)?;
        Some(AuditedUtxoView {
            utxo_hash: Hash(utxo_hash.0),
            utxo: stored.utxo.into(),
            slot: stored.created_in.slot,
            tx_signature: stored.created_in.tx_signature.into(),
            event_index: stored.created_in.event_index,
            slot_index: stored.slot_index,
        })
    }

    pub(crate) fn escrow_root(&self) -> Option<EscrowRoot> {
        self.escrow
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .root
    }

    /// Only positions the chain holds pending, `window`, enter the map.
    pub(crate) fn remember_pending(&self, window: Range<u64>, entries: &[RingQueueEntryView]) {
        let mut escrow = self.escrow.write().unwrap_or_else(PoisonError::into_inner);
        for entry in entries
            .iter()
            .filter(|entry| window.contains(&entry.position))
        {
            escrow.pending.insert(entry.position, entry.member.0);
        }
    }

    /// `None` unless every position of `applied` was seen pending.
    pub(crate) fn applied_members(&self, applied: Range<u64>) -> Option<Vec<[u8; 32]>> {
        if applied.start > applied.end {
            return None;
        }
        let escrow = self.escrow.read().unwrap_or_else(PoisonError::into_inner);
        let members: Vec<[u8; 32]> = escrow
            .pending
            .range(applied.clone())
            .map(|(_, member)| *member)
            .collect();
        (members.len() as u64 == applied.end.saturating_sub(applied.start)).then_some(members)
    }

    /// Every key the registry escrows under `root`, the map read under an older root goes.
    pub(crate) fn replace_escrow(
        &self,
        root: EscrowRoot,
        owners: HashMap<[u8; 32], EscrowedOwner>,
    ) {
        let mut escrow = self.escrow.write().unwrap_or_else(PoisonError::into_inner);
        escrow.keys = owners
            .values()
            .map(|owner| (owner.owner_key, owner.nullifier_pk))
            .collect();
        escrow.owners = owners
            .into_iter()
            .map(|(member, owner)| (member, owner.owner_key))
            .collect();
        escrow.advance(root);
    }

    /// The members an application named, each `None` once it escrows no key.
    pub(crate) fn update_escrow(
        &self,
        root: EscrowRoot,
        members: impl IntoIterator<Item = ([u8; 32], Option<EscrowedOwner>)>,
    ) {
        let mut escrow = self.escrow.write().unwrap_or_else(PoisonError::into_inner);
        for (member, owner) in members {
            if let Some(previous) = escrow.owners.remove(&member) {
                escrow.keys.remove(&previous);
            }
            if let Some(owner) = owner {
                escrow.keys.insert(owner.owner_key, owner.nullifier_pk);
                escrow.owners.insert(member, owner.owner_key);
            }
        }
        escrow.advance(root);
    }

    /// An audit holds the guard for its full run, no UTXO enters between two of its lookups.
    pub(crate) fn known(&self) -> RwLockReadGuard<'_, KnownUtxoIndex<StoredUtxo>> {
        self.utxos.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn stored(&self, utxo_hash: &[u8; 32]) -> Option<StoredUtxo> {
        self.known().get(utxo_hash).copied()
    }
}

impl EscrowMap {
    fn advance(&mut self, root: EscrowRoot) {
        self.pending = self.pending.split_off(&root.applied);
        self.root = Some(root);
    }
}

impl Borrow<KnownUtxo> for StoredUtxo {
    fn borrow(&self) -> &KnownUtxo {
        &self.utxo
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

#[cfg(test)]
mod tests {
    use solana_address::Address;
    use zolana_ring_client::UtxoOwner;

    use super::*;

    fn created(mint: Option<Address>) -> CreatedUtxo {
        CreatedUtxo {
            commitment: [1; 32],
            slot_index: 0,
            utxo: KnownUtxo {
                owner_key: [2; 32],
                owner: UtxoOwner::Keyed {
                    nullifier_pk: [3; 32],
                },
                asset: [4; 32],
                mint,
                amount: 10,
                blinding: [5; 32],
                data_hash: [0; 32],
                ring_data_hash: [0; 32],
                tree_id: 1,
            },
        }
    }

    #[test]
    fn a_stored_utxo_changes_only_to_gain_its_mint() {
        let store = AuditStore::default();
        let created_in = CreatedIn {
            slot: 1,
            tx_signature: Signature::from([7; 64]),
            event_index: 0,
        };
        let mint = Some(Address::new_from_array([6; 32]));
        let stored_mint = || store.stored(&[1; 32]).map(|stored| stored.utxo.mint);
        store.record(created_in, [created(None)]);
        store.record(created_in, [created(mint)]);
        assert_eq!(stored_mint(), Some(mint));
        store.record(created_in, [created(None)]);
        assert_eq!(stored_mint(), Some(mint));
    }

    #[test]
    fn applied_members_need_every_position_seen_pending() {
        let store = AuditStore::default();
        let entry = |position: u64| RingQueueEntryView {
            position,
            member: Hash([position as u8; 32]),
            mask: 0,
            value: 0,
            escrow_key: Hash([0; 32]),
            slot: 0,
        };
        store.remember_pending(0..3, &[entry(0), entry(2), entry(5)]);
        assert_eq!(store.applied_members(0..1), Some(vec![[0; 32]]));
        assert_eq!(store.applied_members(0..3), None);
        assert_eq!(store.applied_members(5..6), None);
        assert_eq!(store.applied_members(Range { start: 2, end: 1 }), None);
    }
}
