use dashmap::{mapref::entry::Entry, DashMap, DashSet};
use solana_address::Address;
use zolana_transaction::WalletUtxo;

use crate::{error::MakerError, transactions::steps::StepId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InventoryUtxo {
    pub asset: Address,
    pub utxo_hash: [u8; 32],
    pub nullifier: [u8; 32],
    pub amount: u64,
    pub reserved: bool,
}

#[derive(Clone)]
pub struct TrackedUtxo {
    pub wallet: WalletUtxo,
    pub leaf_index: Option<u64>,
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

    fn inventory_utxo(&self, reserved: bool) -> InventoryUtxo {
        InventoryUtxo {
            asset: self.asset(),
            utxo_hash: self.utxo_hash(),
            nullifier: self.wallet.nullifier,
            amount: self.amount(),
            reserved,
        }
    }
}

#[derive(Default)]
pub struct Reservations {
    utxos: DashMap<[u8; 32], TrackedUtxo>,
    reserved: DashMap<[u8; 32], StepId>,
    spent_nullifiers: DashSet<[u8; 32]>,
}

impl Reservations {
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
            .filter(|entry| is_spent(&entry.wallet.nullifier))
            .map(|entry| *entry.key())
            .collect();
        self.remove_spent(&spent);
        spent.len()
    }

    pub fn nullifiers(&self) -> Vec<[u8; 32]> {
        self.utxos
            .iter()
            .map(|entry| entry.wallet.nullifier)
            .collect()
    }

    pub fn spendable(&self, asset: &Address) -> Vec<WalletUtxo> {
        self.utxos
            .iter()
            .filter(|entry| entry.asset() == *asset)
            .filter_map(|entry| {
                let leaf_index = entry.leaf_index?;
                let mut wallet = entry.wallet.clone();
                wallet.leaf_index = leaf_index;
                Some(wallet)
            })
            .collect()
    }

    pub fn available(&self, asset: &Address) -> Vec<TrackedUtxo> {
        self.utxos
            .iter()
            .filter(|entry| entry.asset() == *asset)
            .filter(|entry| !self.reserved.contains_key(entry.key()))
            .filter(|entry| entry.leaf_index.is_some())
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn in_flight(&self, asset: &Address) -> bool {
        self.utxos
            .iter()
            .any(|entry| entry.asset() == *asset && self.reserved.contains_key(entry.key()))
    }

    pub fn unindexed(&self, asset: &Address) -> bool {
        self.utxos
            .iter()
            .any(|entry| entry.asset() == *asset && entry.leaf_index.is_none())
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
            .filter(|entry| entry.asset() == *asset)
            .map(|entry| entry.amount())
            .sum()
    }

    pub fn utxos(&self, asset: &Address) -> Vec<InventoryUtxo> {
        let mut utxos: Vec<InventoryUtxo> = self
            .utxos
            .iter()
            .filter(|entry| entry.asset() == *asset)
            .map(|entry| entry.inventory_utxo(self.reserved.contains_key(entry.key())))
            .collect();
        utxos.sort_by_key(|utxo| (std::cmp::Reverse(utxo.amount), utxo.utxo_hash));
        utxos
    }
}
