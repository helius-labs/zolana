//! Which UTXOs a spend takes.
//!
//! A transact binds one input tree and at most as many inputs as the widest
//! automatic shape has, so a spend takes the largest UTXOs of one tree first.
//! A balance spread over trees, or one that needs more UTXOs, is merged first.

use std::{cmp::Reverse, collections::HashSet};

use solana_address::Address;

use crate::{
    decrypt::SpendableDecryptionResult, error::TransactionError,
    instructions::transact::auto_shapes, utxo::WalletUtxo,
};

/// A ring-bound UTXO's commitment covers its ring; the default-ring circuit
/// does not.
pub fn is_default_ring_spendable(utxo: &WalletUtxo) -> bool {
    utxo.utxo.ring_program_id.is_none() && utxo.ring_data_hash.is_none()
}

/// No ring binding and no attached data: the only UTXOs a split or a merge
/// takes, since their spend input drops the committed data hashes.
pub fn is_plain_utxo(utxo: &WalletUtxo) -> bool {
    is_default_ring_spendable(utxo) && utxo.data_hash.is_none() && utxo.utxo.data.is_empty()
}

impl SpendableDecryptionResult {
    /// The single tree holding the UTXOs of `asset` that `eligible` accepts.
    pub fn spend_tree(
        &self,
        asset: Address,
        eligible: impl Fn(&WalletUtxo) -> bool,
    ) -> Result<u16, TransactionError> {
        let utxos: Vec<&WalletUtxo> = self
            .utxos()
            .filter(|utxo| utxo.utxo.asset.asset == asset && eligible(utxo))
            .collect();
        single_tree(&utxos, asset)
    }

    /// The UTXOs a default-ring spend of `amount` of `asset` takes: the
    /// largest first, all on one tree, at most as many as the widest automatic
    /// shape has inputs. Zero-amount UTXOs are left out: they add an input and
    /// nothing to the amount.
    ///
    /// UTXOs whose nullifier is in `excluded` are left out, such as the UTXOs
    /// of a spend that is prepared but not sent yet. When the other UTXOs do
    /// not hold `amount` and the excluded ones would cover it, this fails with
    /// [`TransactionError::SpendNeedsExcludedUtxos`]. A balance that needs a
    /// merge first is reported as such, excluded UTXOs or not.
    pub fn select_spend(
        &self,
        asset: Address,
        amount: u64,
        excluded: &HashSet<[u8; 32]>,
    ) -> Result<Vec<WalletUtxo>, TransactionError> {
        let eligible: Vec<&WalletUtxo> = self
            .utxos()
            .filter(|utxo| {
                utxo.utxo.asset.asset == asset
                    && utxo.utxo.amount > 0
                    && is_default_ring_spendable(utxo)
            })
            .collect();
        let free = eligible
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
            if short && !excluded.is_empty() && select(eligible, asset, amount).is_ok() {
                TransactionError::SpendNeedsExcludedUtxos { amount }
            } else {
                error
            }
        })
    }
}

fn single_tree(utxos: &[&WalletUtxo], asset: Address) -> Result<u16, TransactionError> {
    let mut trees: Vec<u16> = utxos.iter().map(|utxo| utxo.tree_id()).collect();
    trees.sort_unstable();
    trees.dedup();
    match trees.as_slice() {
        [tree] => Ok(*tree),
        [] => Err(TransactionError::NoSpendableBalance { asset }),
        _ => Err(TransactionError::BalanceOnSeveralTrees { trees: trees.len() }),
    }
}

fn select(
    mut utxos: Vec<&WalletUtxo>,
    asset: Address,
    amount: u64,
) -> Result<Vec<WalletUtxo>, TransactionError> {
    single_tree(&utxos, asset)?;
    let max_inputs = auto_shapes()
        .map(|shape| shape.n_inputs())
        .max()
        .unwrap_or(0);
    utxos.sort_by_key(|utxo| Reverse(utxo.utxo.amount));
    let available = utxos
        .iter()
        .fold(0u64, |total, utxo| total.saturating_add(utxo.utxo.amount));
    let mut selected = Vec::new();
    let mut covered = 0u64;
    for utxo in utxos.into_iter().take(max_inputs) {
        covered = covered.saturating_add(utxo.utxo.amount);
        selected.push(utxo.clone());
        if covered >= amount {
            return Ok(selected);
        }
    }
    Err(if available >= amount {
        TransactionError::SpendNeedsMerge { amount, max_inputs }
    } else {
        TransactionError::InsufficientBalance {
            requested: amount,
            available,
        }
    })
}
