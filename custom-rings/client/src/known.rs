//! The notes an auditor opened, by commitment and by owner key and spent-hash prefix.

use std::{
    borrow::Borrow,
    collections::{hash_map::Entry, HashMap},
};

use custom_ring_interface::InputPrefix;

use crate::types::KnownUtxo;

#[derive(Clone, Debug)]
pub struct KnownUtxoIndex<T = KnownUtxo> {
    utxos: HashMap<[u8; 32], T>,
    owned: HashMap<([u8; 32], InputPrefix), Vec<[u8; 32]>>,
}

impl<T> Default for KnownUtxoIndex<T> {
    fn default() -> Self {
        Self {
            utxos: HashMap::new(),
            owned: HashMap::new(),
        }
    }
}

impl<T: Borrow<KnownUtxo>> KnownUtxoIndex<T> {
    /// A later opening of a known commitment replaces it only to name its mint.
    pub fn insert(&mut self, commitment: [u8; 32], record: T) {
        match self.utxos.entry(commitment) {
            Entry::Occupied(mut kept) => {
                if kept.get().borrow().mint.is_none() && record.borrow().mint.is_some() {
                    kept.insert(record);
                }
            }
            Entry::Vacant(free) => {
                if let Some(prefix) = InputPrefix::of(&commitment) {
                    self.owned
                        .entry((record.borrow().owner_key, prefix))
                        .or_default()
                        .push(commitment);
                }
                free.insert(record);
            }
        }
    }

    pub fn get(&self, commitment: &[u8; 32]) -> Option<&T> {
        self.utxos.get(commitment)
    }

    pub fn prefixed(&self, owner_key: &[u8; 32], prefix: InputPrefix) -> &[[u8; 32]] {
        self.owned
            .get(&(*owner_key, prefix))
            .map_or(&[], Vec::as_slice)
    }

    pub fn len(&self) -> usize {
        self.utxos.len()
    }

    pub fn is_empty(&self) -> bool {
        self.utxos.is_empty()
    }
}

impl<T: Borrow<KnownUtxo>> Extend<([u8; 32], T)> for KnownUtxoIndex<T> {
    fn extend<I: IntoIterator<Item = ([u8; 32], T)>>(&mut self, records: I) {
        for (commitment, record) in records {
            self.insert(commitment, record);
        }
    }
}

impl<T: Borrow<KnownUtxo>> FromIterator<([u8; 32], T)> for KnownUtxoIndex<T> {
    fn from_iter<I: IntoIterator<Item = ([u8; 32], T)>>(records: I) -> Self {
        let mut index = Self::default();
        index.extend(records);
        index
    }
}
