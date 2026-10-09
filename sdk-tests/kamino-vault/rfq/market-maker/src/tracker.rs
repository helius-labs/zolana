use dashmap::{mapref::entry::Entry, DashMap, DashSet};
use solana_address::Address;
use zolana_transaction::WalletUtxo;

use super::{error::MakerError, step::StepId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CacheSlot {
    pub cache: Address,
    pub index: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lane {
    pub asset: Address,
    pub utxo_hash: [u8; 32],
    pub nullifier: [u8; 32],
    pub amount: u64,
    pub cache_slot: Option<CacheSlot>,
    pub predicted: bool,
    pub reserved: bool,
}

#[derive(Clone)]
pub struct TrackedUtxo {
    pub wallet: WalletUtxo,
    pub source: Option<StepId>,
    pub leaf_index: Option<u64>,
    pub cache_slot: Option<CacheSlot>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpendPath {
    CachedRead(CacheSlot),
    MerklePath(u64),
}

impl TrackedUtxo {
    pub fn utxo_hash(&self) -> [u8; 32] {
        self.wallet.utxo_hash
    }

    pub fn asset(&self) -> Address {
        self.wallet.utxo.asset.asset
    }

    pub fn amount(&self) -> u64 {
        self.wallet.utxo.amount
    }

    pub fn spend_path(&self, read_cache: Option<Address>) -> Option<SpendPath> {
        match (self.cache_slot, self.leaf_index) {
            (Some(slot), _) if read_cache.is_none_or(|cache| cache == slot.cache) => {
                Some(SpendPath::CachedRead(slot))
            }
            (_, Some(leaf_index)) => Some(SpendPath::MerklePath(leaf_index)),
            _ => None,
        }
    }

    fn lane(&self, reserved: bool) -> Lane {
        Lane {
            asset: self.asset(),
            utxo_hash: self.utxo_hash(),
            nullifier: self.wallet.nullifier,
            amount: self.amount(),
            cache_slot: self.cache_slot,
            predicted: self.source.is_some(),
            reserved,
        }
    }
}

#[derive(Default)]
pub struct UtxoTracker {
    utxos: DashMap<[u8; 32], TrackedUtxo>,
    reserved: DashMap<[u8; 32], StepId>,
    spent_nullifiers: DashSet<[u8; 32]>,
}

impl UtxoTracker {
    pub fn insert(&self, utxo: TrackedUtxo) -> bool {
        if self.spent_nullifiers.contains(&utxo.wallet.nullifier) {
            return false;
        }
        match self.utxos.entry(utxo.utxo_hash()) {
            Entry::Occupied(mut existing) => {
                let existing = existing.get_mut();
                existing.leaf_index = existing.leaf_index.or(utxo.leaf_index);
                false
            }
            Entry::Vacant(vacant) => {
                vacant.insert(utxo);
                true
            }
        }
    }

    pub fn get(&self, utxo_hash: &[u8; 32]) -> Option<TrackedUtxo> {
        self.utxos.get(utxo_hash).map(|entry| entry.value().clone())
    }

    pub fn clear_source(&self, utxo_hash: &[u8; 32]) {
        if let Some(mut entry) = self.utxos.get_mut(utxo_hash) {
            entry.source = None;
        }
    }

    pub fn set_cache_slot(&self, utxo_hash: &[u8; 32], cache_slot: Option<CacheSlot>) {
        if let Some(mut entry) = self.utxos.get_mut(utxo_hash) {
            entry.cache_slot = cache_slot;
        }
    }

    pub fn clear_cache(&self, cache: &Address) {
        for mut entry in self.utxos.iter_mut() {
            if entry.cache_slot.is_some_and(|slot| slot.cache == *cache) {
                entry.cache_slot = None;
            }
        }
    }

    pub fn reserve(&self, step: StepId, utxo_hashes: &[[u8; 32]]) -> Result<(), MakerError> {
        for hash in utxo_hashes {
            if !self.utxos.contains_key(hash) {
                return Err(MakerError::UtxoNotTracked(*hash));
            }
            if self
                .reserved
                .get(hash)
                .is_some_and(|holder| *holder != step)
            {
                return Err(MakerError::UtxoReserved(*hash));
            }
        }
        for hash in utxo_hashes {
            self.reserved.insert(*hash, step);
        }
        Ok(())
    }

    pub fn release(&self, step: StepId) {
        self.reserved.retain(|_, holder| *holder != step);
    }

    pub fn reserved_by(&self, utxo_hash: &[u8; 32]) -> Option<StepId> {
        self.reserved.get(utxo_hash).map(|holder| *holder)
    }

    pub fn remove(&self, utxo_hash: &[u8; 32]) {
        self.utxos.remove(utxo_hash);
        self.reserved.remove(utxo_hash);
    }

    pub fn remove_spent(&self, utxo_hashes: &[[u8; 32]]) {
        for hash in utxo_hashes {
            if let Some((_, utxo)) = self.utxos.remove(hash) {
                self.spent_nullifiers.insert(utxo.wallet.nullifier);
            }
            self.reserved.remove(hash);
        }
    }

    pub fn remove_spent_nullifiers(&self, is_spent: impl Fn(&[u8; 32]) -> bool) -> usize {
        let spent: Vec<[u8; 32]> = self
            .utxos
            .iter()
            .filter(|entry| entry.source.is_none() && is_spent(&entry.wallet.nullifier))
            .map(|entry| *entry.key())
            .collect();
        self.remove_spent(&spent);
        spent.len()
    }

    pub fn available(&self, asset: &Address) -> Vec<TrackedUtxo> {
        self.utxos
            .iter()
            .filter(|entry| entry.asset() == *asset && entry.source.is_none())
            .filter(|entry| !self.reserved.contains_key(entry.key()))
            .filter(|entry| entry.spend_path(None).is_some())
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn in_flight(&self, asset: &Address) -> bool {
        self.utxos.iter().any(|entry| {
            entry.asset() == *asset
                && (entry.source.is_some() || self.reserved.contains_key(entry.key()))
        })
    }

    pub fn unindexed(&self, asset: &Address) -> bool {
        self.utxos.iter().any(|entry| {
            entry.asset() == *asset && entry.source.is_none() && entry.spend_path(None).is_none()
        })
    }

    pub fn unreserved_balance(&self, asset: &Address) -> u64 {
        self.utxos
            .iter()
            .filter(|entry| entry.asset() == *asset)
            .filter(|entry| !self.reserved.contains_key(entry.key()))
            .map(|entry| entry.amount())
            .sum()
    }

    pub fn balance(&self, asset: &Address) -> u64 {
        self.utxos
            .iter()
            .filter(|entry| entry.asset() == *asset && entry.source.is_none())
            .map(|entry| entry.amount())
            .sum()
    }

    pub fn lane_count(&self, asset: &Address) -> usize {
        self.utxos
            .iter()
            .filter(|entry| entry.asset() == *asset)
            .count()
    }

    pub fn lanes(&self, asset: &Address) -> Vec<Lane> {
        let mut lanes: Vec<Lane> = self
            .utxos
            .iter()
            .filter(|entry| entry.asset() == *asset)
            .map(|entry| entry.lane(self.reserved.contains_key(entry.key())))
            .collect();
        lanes.sort_by_key(|lane| (std::cmp::Reverse(lane.amount), lane.utxo_hash));
        lanes
    }

    pub fn slots_in(&self, cache: &Address) -> Vec<u8> {
        self.utxos
            .iter()
            .filter_map(|entry| entry.cache_slot)
            .filter(|slot| slot.cache == *cache)
            .map(|slot| slot.index)
            .collect()
    }

    pub fn expected_contents(&self, cache: &Address) -> Vec<(u8, [u8; 32])> {
        self.utxos
            .iter()
            .filter(|entry| entry.source.is_none())
            .filter_map(|entry| {
                entry
                    .cache_slot
                    .filter(|slot| slot.cache == *cache)
                    .map(|slot| (slot.index, entry.utxo_hash()))
            })
            .collect()
    }
}
