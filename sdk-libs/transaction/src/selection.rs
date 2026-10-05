//! Which notes a spend takes.
//!
//! A transact binds one input tree and at most as many inputs as the widest
//! automatic shape has, so a spend takes the largest notes of one tree first.
//! A balance spread over trees, or one that needs more notes, is merged first.

use std::{cmp::Reverse, collections::HashSet};

use solana_address::Address;

use crate::{
    decrypt::SpendableDecryptionResult, error::TransactionError,
    instructions::transact::auto_shapes, utxo::WalletUtxo,
};

/// A ring-bound note's commitment covers its ring; the default-ring circuit
/// does not.
pub fn is_default_ring_spendable(note: &WalletUtxo) -> bool {
    note.utxo.ring_program_id.is_none() && note.ring_data_hash.is_none()
}

/// No ring binding and no attached data: the only notes a split or a merge
/// takes, since their spend input drops the committed data hashes.
pub fn is_plain_utxo(note: &WalletUtxo) -> bool {
    is_default_ring_spendable(note) && note.data_hash.is_none() && note.utxo.data.is_empty()
}

impl SpendableDecryptionResult {
    /// The single tree holding the notes of `asset` that `eligible` accepts.
    pub fn spend_tree(
        &self,
        asset: Address,
        eligible: impl Fn(&WalletUtxo) -> bool,
    ) -> Result<u16, TransactionError> {
        let notes: Vec<&WalletUtxo> = self
            .utxos()
            .filter(|note| note.utxo.asset.asset == asset && eligible(note))
            .collect();
        single_tree(&notes, asset)
    }

    /// The notes a default-ring spend of `amount` of `asset` takes: the
    /// largest first, all on one tree, at most as many as the widest automatic
    /// shape has inputs. Zero-amount notes are left out: they add an input and
    /// nothing to the amount.
    ///
    /// Notes whose nullifier is in `excluded` are left out, such as the notes
    /// of a spend that is prepared but not sent yet. When the other notes do
    /// not hold `amount` and the excluded ones would cover it, this fails with
    /// [`TransactionError::SpendNeedsExcludedNotes`]. A balance that needs a
    /// merge first is reported as such, excluded notes or not.
    pub fn select_spend(
        &self,
        asset: Address,
        amount: u64,
        excluded: &HashSet<[u8; 32]>,
    ) -> Result<Vec<WalletUtxo>, TransactionError> {
        let eligible: Vec<&WalletUtxo> = self
            .utxos()
            .filter(|note| {
                note.utxo.asset.asset == asset
                    && note.utxo.amount > 0
                    && is_default_ring_spendable(note)
            })
            .collect();
        let free = eligible
            .iter()
            .copied()
            .filter(|note| !excluded.contains(&note.nullifier))
            .collect();
        select(free, asset, amount).map_err(|error| {
            let short = matches!(
                error,
                TransactionError::InsufficientBalance { .. }
                    | TransactionError::NoSpendableBalance { .. }
            );
            if short && !excluded.is_empty() && select(eligible, asset, amount).is_ok() {
                TransactionError::SpendNeedsExcludedNotes { amount }
            } else {
                error
            }
        })
    }
}

fn single_tree(notes: &[&WalletUtxo], asset: Address) -> Result<u16, TransactionError> {
    let mut trees: Vec<u16> = notes.iter().map(|note| note.tree_id()).collect();
    trees.sort_unstable();
    trees.dedup();
    match trees.as_slice() {
        [tree] => Ok(*tree),
        [] => Err(TransactionError::NoSpendableBalance { asset }),
        _ => Err(TransactionError::BalanceOnSeveralTrees { trees: trees.len() }),
    }
}

fn select(
    mut notes: Vec<&WalletUtxo>,
    asset: Address,
    amount: u64,
) -> Result<Vec<WalletUtxo>, TransactionError> {
    single_tree(&notes, asset)?;
    let max_inputs = auto_shapes()
        .map(|shape| shape.n_inputs())
        .max()
        .unwrap_or(0);
    notes.sort_by_key(|note| Reverse(note.utxo.amount));
    let available = notes
        .iter()
        .fold(0u64, |total, note| total.saturating_add(note.utxo.amount));
    let mut selected = Vec::new();
    let mut covered = 0u64;
    for note in notes.into_iter().take(max_inputs) {
        covered = covered.saturating_add(note.utxo.amount);
        selected.push(note.clone());
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
