//! Which UTXOs a spend takes.
//!
//! A spend takes default-ring UTXOs of one asset, the largest first, at most
//! as many as the widest shape for its outputs holds ([`max_spend_inputs`])
//! and from at most [`MAX_INPUT_TREES`] trees, since a proof resolves roots
//! for that many. A balance that needs more UTXOs or more trees is merged
//! first: a merge takes plain UTXOs of one tree, the smallest first, which
//! [`select_merge`] picks.

use std::{
    cmp::Reverse,
    collections::{BTreeMap, HashSet},
};

use solana_address::Address;
use spr_interface::MAX_INPUT_TREES;

use crate::{
    error::TransactionError,
    instructions::{merge::MAX_MERGE_INPUTS, transact::max_spend_inputs},
    utxo::WalletUtxo,
};

/// The UTXOs a default-ring spend of `amount` of `asset` takes from `utxos`:
/// the largest first, until they cover `amount`. Zero-amount UTXOs are left
/// out: they add an input and nothing to the amount.
///
/// `outputs` counts the private outputs the spend creates other than its
/// change; a spend whose UTXOs exceed `amount` proves one more. The UTXOs fit
/// the widest shape for that many outputs ([`max_spend_inputs`]); a spend
/// that needs more fails with [`TransactionError::SpendNeedsMerge`], and one
/// whose outputs no shape holds with [`TransactionError::UnsupportedShape`].
pub fn select_spend<'a>(
    utxos: impl IntoIterator<Item = &'a WalletUtxo>,
    asset: Address,
    amount: u64,
    outputs: usize,
) -> Result<Vec<WalletUtxo>, TransactionError> {
    select(candidates(utxos, asset), asset, amount, outputs)
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
    outputs: usize,
    excluded: &HashSet<[u8; 32]>,
) -> Result<Vec<WalletUtxo>, TransactionError> {
    let candidates = candidates(utxos, asset);
    let free = candidates
        .iter()
        .copied()
        .filter(|utxo| !excluded.contains(&utxo.nullifier))
        .collect();
    select(free, asset, amount, outputs).map_err(|error| {
        let short = matches!(
            error,
            TransactionError::InsufficientBalance { .. }
                | TransactionError::NoSpendableBalance { .. }
        );
        if short && select(candidates, asset, amount, outputs).is_ok() {
            TransactionError::SpendNeedsExcludedUtxos { amount }
        } else {
            error
        }
    })
}

/// The UTXOs a merge of `asset` takes from `utxos`: the plain ones of the tree
/// that holds the most of them, the smallest first, at most `max_inputs`
/// (capped at [`MAX_MERGE_INPUTS`]), leaving out those whose nullifier is in
/// `excluded`, such as the UTXOs of a prepared spend. Zero-amount UTXOs are
/// left out. Fails with [`TransactionError::NothingToMerge`] when fewer than
/// two remain.
///
/// A merge publishes one input tree, so a balance on two trees is merged one
/// tree at a time; the fuller tree goes first.
pub fn select_merge<'a>(
    utxos: impl IntoIterator<Item = &'a WalletUtxo>,
    asset: Address,
    max_inputs: usize,
    excluded: &HashSet<[u8; 32]>,
) -> Result<Vec<WalletUtxo>, TransactionError> {
    let mut trees: BTreeMap<u16, Vec<&WalletUtxo>> = BTreeMap::new();
    for utxo in utxos.into_iter().filter(|utxo| {
        utxo.utxo.asset.asset == asset
            && utxo.utxo.amount > 0
            && utxo.is_plain()
            && !excluded.contains(&utxo.nullifier)
    }) {
        trees.entry(utxo.tree_id()).or_default().push(utxo);
    }
    // The lowest tree id wins a tie, so the choice does not depend on order.
    let mut selected = trees
        .into_values()
        .rev()
        .max_by_key(Vec::len)
        .unwrap_or_default();
    selected.sort_by_key(|utxo| utxo.utxo.amount);
    selected.truncate(max_inputs.min(MAX_MERGE_INPUTS));
    if selected.len() < 2 {
        return Err(TransactionError::NothingToMerge { asset });
    }
    Ok(selected.into_iter().cloned().collect())
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
    outputs: usize,
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
    // The largest come first, so the shortest run that covers `amount` is
    // the fewest UTXOs that do. `available` covers it.
    let mut count = 0;
    let mut covered = 0u64;
    for utxo in &utxos {
        if covered >= amount {
            break;
        }
        // At most `available`, which did not overflow.
        covered += utxo.utxo.amount;
        count += 1;
    }
    let proven_outputs = if covered > amount {
        outputs.saturating_add(1)
    } else {
        outputs
    };
    let max_inputs = max_spend_inputs(proven_outputs);
    if max_inputs == 0 {
        return Err(TransactionError::UnsupportedShape {
            n_in: count,
            n_out: proven_outputs,
        });
    }
    if count > max_inputs {
        return Err(TransactionError::SpendNeedsMerge { amount, max_inputs });
    }
    let selected: Vec<WalletUtxo> = utxos.into_iter().take(count).cloned().collect();
    let mut trees: Vec<u16> = selected.iter().map(WalletUtxo::tree_id).collect();
    trees.sort_unstable();
    trees.dedup();
    if trees.len() > MAX_INPUT_TREES {
        return Err(TransactionError::TooManyInputTrees {
            got: trees.len(),
            max: MAX_INPUT_TREES,
        });
    }
    Ok(selected)
}
