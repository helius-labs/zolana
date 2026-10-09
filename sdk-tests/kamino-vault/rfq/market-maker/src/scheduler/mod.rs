pub mod growth;
pub mod payment;
pub mod upkeep;

use std::cmp::Reverse;

use solana_address::Address;
use zolana_client::SPP_SUPPORTED_SHAPES;
use zolana_transaction::WalletUtxo;

use super::tracker::{SpendPath, TrackedUtxo};

#[derive(Clone)]
pub struct SelectedInput {
    pub utxo: TrackedUtxo,
    pub path: SpendPath,
}

impl SelectedInput {
    pub fn wallet(&self) -> WalletUtxo {
        let mut wallet = self.utxo.wallet.clone();
        if let SpendPath::MerklePath(leaf_index) = self.path {
            wallet.leaf_index = leaf_index;
        }
        wallet
    }

    pub fn cache_index(&self) -> Option<u8> {
        match self.path {
            SpendPath::CachedRead(slot) => Some(slot.index),
            SpendPath::MerklePath(_) => None,
        }
    }
}

#[derive(Clone, Default)]
pub struct Selection {
    pub inputs: Vec<SelectedInput>,
    pub read_cache: Option<Address>,
    pub total: u64,
}

impl Selection {
    pub fn single(utxo: &TrackedUtxo) -> Option<Self> {
        let mut selection = Self::default();
        selection.push(utxo).then_some(selection)
    }

    fn push(&mut self, utxo: &TrackedUtxo) -> bool {
        let Some(path) = utxo.spend_path(self.read_cache) else {
            return false;
        };
        if let SpendPath::CachedRead(slot) = path {
            self.read_cache = Some(slot.cache);
        }
        self.total = self.total.saturating_add(utxo.amount());
        self.inputs.push(SelectedInput {
            utxo: utxo.clone(),
            path,
        });
        true
    }

    pub fn hashes(&self) -> Vec<[u8; 32]> {
        self.inputs
            .iter()
            .map(|input| input.utxo.utxo_hash())
            .collect()
    }

    pub fn cached_slots(&self) -> Vec<(Address, u8)> {
        self.inputs
            .iter()
            .filter_map(|input| match input.path {
                SpendPath::CachedRead(slot) => Some((slot.cache, slot.index)),
                SpendPath::MerklePath(_) => None,
            })
            .collect()
    }
}

pub fn max_outputs_for(inputs: usize) -> usize {
    SPP_SUPPORTED_SHAPES
        .into_iter()
        .filter(|shape| shape.n_inputs() >= inputs)
        .map(|shape| shape.n_outputs())
        .max()
        .unwrap_or(0)
}

pub fn select(available: &[TrackedUtxo], amount: u64, max_inputs: usize) -> Option<Selection> {
    let mut candidates: Vec<&TrackedUtxo> = available.iter().collect();
    candidates.sort_by_key(|utxo| Reverse(utxo.amount()));
    select_amount(candidates, amount, max_inputs)
}

pub fn select_all(available: &[TrackedUtxo], max_inputs: usize) -> Selection {
    let mut candidates: Vec<&TrackedUtxo> = available.iter().collect();
    candidates.sort_by_key(|utxo| Reverse(utxo.amount()));
    let mut selection = Selection::default();
    for utxo in candidates {
        if selection.inputs.len() >= max_inputs {
            break;
        }
        selection.push(utxo);
    }
    selection
}

pub fn select_smallest(available: &[TrackedUtxo], count: usize) -> Selection {
    let mut candidates: Vec<&TrackedUtxo> = available.iter().collect();
    candidates.sort_by_key(|utxo| utxo.amount());
    let mut selection = Selection::default();
    for utxo in candidates {
        if selection.inputs.len() >= count {
            break;
        }
        selection.push(utxo);
    }
    selection
}

fn select_amount(
    candidates: Vec<&TrackedUtxo>,
    amount: u64,
    max_inputs: usize,
) -> Option<Selection> {
    let mut selection = Selection::default();
    for utxo in candidates {
        if selection.total >= amount || selection.inputs.len() >= max_inputs {
            break;
        }
        selection.push(utxo);
    }
    (selection.total >= amount && !selection.inputs.is_empty()).then_some(selection)
}
