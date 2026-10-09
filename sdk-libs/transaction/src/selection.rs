//! Which UTXOs a spend takes.
//!
//! A spend takes default-ring UTXOs of one asset, the largest first, at most
//! [`MAX_SPEND_INPUTS`] of them and from at most [`MAX_INPUT_TREES`] trees,
//! since a proof resolves roots for that many. A balance that needs more
//! UTXOs or more trees is merged first. A merge takes the UTXOs of one tree,
//! which [`spend_tree`] finds.

use std::{cmp::Reverse, collections::HashSet};

use solana_address::Address;
use zolana_interface::MAX_INPUT_TREES;

use crate::{error::TransactionError, instructions::transact::MAX_SPEND_INPUTS, utxo::WalletUtxo};

/// The UTXOs a default-ring spend of `amount` of `asset` takes from `utxos`:
/// the largest first, until they cover `amount`. Zero-amount UTXOs are left
/// out: they add an input and nothing to the amount.
pub fn select_spend<'a>(
    utxos: impl IntoIterator<Item = &'a WalletUtxo>,
    asset: Address,
    amount: u64,
) -> Result<Vec<WalletUtxo>, TransactionError> {
    select(candidates(utxos, asset), asset, amount)
}

/// [`select_spend`] without the UTXOs whose nullifier is in `excluded`, such
/// as the UTXOs of a spend that is prepared but not sent yet. When the other
/// UTXOs do not hold `amount` and the excluded ones would cover it, this
/// fails with [`TransactionError::SpendNeedsExcludedUtxos`]. A balance that
/// needs a merge first is reported as such, excluded UTXOs or not.
pub fn select_spend_excluding<'a>(
    utxos: impl IntoIterator<Item = &'a WalletUtxo>,
    asset: Address,
    amount: u64,
    excluded: &HashSet<[u8; 32]>,
) -> Result<Vec<WalletUtxo>, TransactionError> {
    let candidates = candidates(utxos, asset);
    let free = candidates
        .iter()
        .copied()
        .filter(|utxo| !excluded.contains(&utxo.nullifier))
        .collect();
    select(free, asset, amount).map_err(|error| {
        let short = matches!(
            error,
            TransactionError::InsufficientBalance { .. }
                | TransactionError::NoSpendableBalance { .. }
        );
        if short && select(candidates, asset, amount).is_ok() {
            TransactionError::SpendNeedsExcludedUtxos { amount }
        } else {
            error
        }
    })
}

/// The single tree holding the UTXOs of `asset` that `eligible` accepts, the
/// tree a merge of them consolidates on.
pub fn spend_tree<'a>(
    utxos: impl IntoIterator<Item = &'a WalletUtxo>,
    asset: Address,
    eligible: impl Fn(&WalletUtxo) -> bool,
) -> Result<u16, TransactionError> {
    let mut trees: Vec<u16> = utxos
        .into_iter()
        .filter(|utxo| utxo.utxo.asset.asset == asset && eligible(utxo))
        .map(WalletUtxo::tree_id)
        .collect();
    trees.sort_unstable();
    trees.dedup();
    match trees.as_slice() {
        [tree] => Ok(*tree),
        [] => Err(TransactionError::NoSpendableBalance { asset }),
        _ => Err(TransactionError::BalanceOnSeveralTrees { trees: trees.len() }),
    }
}

fn candidates<'a>(
    utxos: impl IntoIterator<Item = &'a WalletUtxo>,
    asset: Address,
) -> Vec<&'a WalletUtxo> {
    utxos
        .into_iter()
        .filter(|utxo| {
            utxo.utxo.asset.asset == asset
                && utxo.utxo.amount > 0
                && utxo.is_default_ring_spendable()
        })
        .collect()
}

fn select(
    mut utxos: Vec<&WalletUtxo>,
    asset: Address,
    amount: u64,
) -> Result<Vec<WalletUtxo>, TransactionError> {
    if amount == 0 {
        return Err(TransactionError::ZeroSpendAmount);
    }
    if utxos.is_empty() {
        return Err(TransactionError::NoSpendableBalance { asset });
    }
    let available = utxos
        .iter()
        .try_fold(0u64, |total, utxo| total.checked_add(utxo.utxo.amount))
        .ok_or(TransactionError::SelectedBalanceOverflow)?;
    if available < amount {
        return Err(TransactionError::InsufficientBalance {
            requested: amount,
            available,
        });
    }
    utxos.sort_by_key(|utxo| Reverse(utxo.utxo.amount));
    let mut selected = Vec::new();
    let mut covered = 0u64;
    for utxo in utxos.into_iter().take(MAX_SPEND_INPUTS) {
        // At most `available`, which did not overflow.
        covered += utxo.utxo.amount;
        selected.push(utxo.clone());
        if covered >= amount {
            let mut trees: Vec<u16> = selected.iter().map(WalletUtxo::tree_id).collect();
            trees.sort_unstable();
            trees.dedup();
            if trees.len() > MAX_INPUT_TREES {
                return Err(TransactionError::TooManyInputTrees {
                    got: trees.len(),
                    max: MAX_INPUT_TREES,
                });
            }
            return Ok(selected);
        }
    }
    Err(TransactionError::SpendNeedsMerge {
        amount,
        max_inputs: MAX_SPEND_INPUTS,
    })
}
