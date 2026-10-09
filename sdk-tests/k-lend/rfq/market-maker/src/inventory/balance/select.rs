use std::cmp::Reverse;

use zolana_client::SPP_SUPPORTED_SHAPES;
use zolana_transaction::WalletUtxo;

use super::reservations::TrackedUtxo;

#[derive(Clone)]
pub struct SelectedInput {
    pub utxo: TrackedUtxo,
    pub leaf_index: u64,
}

impl SelectedInput {
    pub fn wallet(&self) -> WalletUtxo {
        let mut wallet = self.utxo.wallet.clone();
        wallet.leaf_index = self.leaf_index;
        wallet
    }
}

#[derive(Clone, Default)]
pub struct Selection {
    pub inputs: Vec<SelectedInput>,
    pub total: u64,
}

impl Selection {
    pub fn single(utxo: &TrackedUtxo) -> Option<Self> {
        let mut selection = Self::default();
        selection.push(utxo).then_some(selection)
    }

    fn push(&mut self, utxo: &TrackedUtxo) -> bool {
        let Some(leaf_index) = utxo.leaf_index else {
            return false;
        };
        self.total = self.total.saturating_add(utxo.amount());
        self.inputs.push(SelectedInput {
            utxo: utxo.clone(),
            leaf_index,
        });
        true
    }

    pub fn hashes(&self) -> Vec<[u8; 32]> {
        self.inputs
            .iter()
            .map(|input| input.utxo.utxo_hash())
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
    let candidates: Vec<&TrackedUtxo> = available
        .iter()
        .filter(|utxo| utxo.leaf_index.is_some())
        .collect();
    let picked = pick(candidates, |utxo| utxo.amount(), amount, max_inputs)?;
    let mut selection = Selection::default();
    for utxo in picked {
        selection.push(utxo);
    }
    Some(selection)
}

pub fn width(utxos: Vec<u64>, amount: u64, max_inputs: usize) -> Option<usize> {
    pick(utxos, |utxo| *utxo, amount, max_inputs).map(|picked| picked.len())
}

fn pick<T>(
    mut candidates: Vec<T>,
    amount_of: impl Fn(&T) -> u64,
    amount: u64,
    max_inputs: usize,
) -> Option<Vec<T>> {
    candidates.sort_by_key(|candidate| Reverse(amount_of(candidate)));
    let mut picked = Vec::new();
    let mut total = 0u64;
    while picked.len() < max_inputs && !candidates.is_empty() {
        let remaining = amount.saturating_sub(total);
        let covering = candidates
            .iter()
            .rposition(|candidate| amount_of(candidate) >= remaining)
            .unwrap_or(0);
        let candidate = candidates.remove(covering);
        total = total.saturating_add(amount_of(&candidate));
        picked.push(candidate);
        if total >= amount {
            return Some(picked);
        }
    }
    None
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
