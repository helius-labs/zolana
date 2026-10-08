//! Which UTXOs a spend takes: largest first, at most `MAX_SPEND_INPUTS` from
//! at most `MAX_INPUT_TREES` trees, leaving out excluded and zero-amount UTXOs.
mod common;

use std::collections::HashSet;

use common::{keypair, wallet_utxo};
use solana_address::Address;
use zolana_interface::MAX_INPUT_TREES;
use zolana_transaction::{
    error::TransactionError, instructions::transact::MAX_SPEND_INPUTS, select_spend,
    select_spend_excluding, spend_tree, Mint, WalletUtxo,
};

const TOKEN: Mint = Mint::new(Address::new_from_array([7; 32]), 2);

fn amounts(utxos: &[WalletUtxo]) -> Vec<u64> {
    utxos.iter().map(|utxo| utxo.utxo.amount).collect()
}

#[test]
fn takes_the_largest_utxos_of_the_asset_until_the_amount_is_covered() {
    let owner = keypair(1);
    let wallet = vec![
        wallet_utxo(&owner, Mint::SOL, 20, 0, 1),
        wallet_utxo(&owner, Mint::SOL, 50, 0, 2),
        wallet_utxo(&owner, Mint::SOL, 30, 0, 3),
        wallet_utxo(&owner, TOKEN, 500, 0, 4),
    ];
    let select = |amount| select_spend(&wallet, Mint::SOL.asset, amount);
    assert_eq!(amounts(&select(40).unwrap()), [50]);
    assert_eq!(amounts(&select(60).unwrap()), [50, 30]);
    assert_eq!(
        select(101),
        Err(TransactionError::InsufficientBalance {
            requested: 101,
            available: 100,
        })
    );
    assert_eq!(select(0), Err(TransactionError::ZeroSpendAmount));
    assert_eq!(
        amounts(&select_spend(&wallet, TOKEN.asset, 500).unwrap()),
        [500]
    );
}

#[test]
fn leaves_out_excluded_utxos() {
    let owner = keypair(1);
    let wallet = vec![
        wallet_utxo(&owner, Mint::SOL, 50, 0, 1),
        wallet_utxo(&owner, Mint::SOL, 30, 0, 2),
        wallet_utxo(&owner, Mint::SOL, 20, 0, 3),
    ];
    let excluded = HashSet::from([wallet[0].nullifier]);
    let select = |amount| select_spend_excluding(&wallet, Mint::SOL.asset, amount, &excluded);
    assert_eq!(amounts(&select(40).unwrap()), [30, 20]);
    assert_eq!(
        select(60),
        Err(TransactionError::SpendNeedsExcludedUtxos { amount: 60 })
    );
    assert_eq!(
        select(101),
        Err(TransactionError::InsufficientBalance {
            requested: 101,
            available: 50,
        })
    );

    // With every UTXO excluded, nothing is left: the excluded UTXOs are needed.
    let only = vec![wallet_utxo(&owner, Mint::SOL, 100, 0, 4)];
    let excluded = HashSet::from([only[0].nullifier]);
    assert_eq!(
        select_spend_excluding(&only, Mint::SOL.asset, 50, &excluded),
        Err(TransactionError::SpendNeedsExcludedUtxos { amount: 50 })
    );
}

#[test]
fn leaves_out_zero_amount_and_ring_bound_utxos() {
    let owner = keypair(1);
    let mut ring_bound = wallet_utxo(&owner, Mint::SOL, 1_000, 0, 1);
    ring_bound.utxo.ring_program_id = Some(Address::new_from_array([9; 32]));
    let mut ring_data = wallet_utxo(&owner, Mint::SOL, 1_000, 0, 2);
    ring_data.ring_data_hash = Some([5; 32]);
    let wallet = vec![
        ring_bound,
        ring_data,
        wallet_utxo(&owner, Mint::SOL, 0, 0, 3),
        wallet_utxo(&owner, Mint::SOL, 10, 0, 4),
    ];
    let select = |amount| select_spend(&wallet, Mint::SOL.asset, amount);
    assert_eq!(amounts(&select(10).unwrap()), [10]);
    assert_eq!(
        select(11),
        Err(TransactionError::InsufficientBalance {
            requested: 11,
            available: 10,
        })
    );
    assert_eq!(
        select_spend(&wallet[..3], Mint::SOL.asset, 1),
        Err(TransactionError::NoSpendableBalance {
            asset: Mint::SOL.asset
        })
    );
}

#[test]
fn spans_at_most_max_input_trees() {
    let owner = keypair(1);
    let tree_count = u16::try_from(MAX_INPUT_TREES + 1).unwrap();
    let wallet: Vec<_> = (0..tree_count)
        .map(|tree| wallet_utxo(&owner, Mint::SOL, 10, tree, u8::try_from(tree).unwrap()))
        .collect();
    let fits = 10 * u64::try_from(MAX_INPUT_TREES).unwrap();
    let selected = select_spend(&wallet, Mint::SOL.asset, fits).unwrap();
    let trees: HashSet<u16> = selected.iter().map(WalletUtxo::tree_id).collect();
    assert_eq!(trees.len(), MAX_INPUT_TREES);
    assert_eq!(
        select_spend(&wallet, Mint::SOL.asset, fits + 1),
        Err(TransactionError::TooManyInputTrees {
            got: MAX_INPUT_TREES + 1,
            max: MAX_INPUT_TREES,
        })
    );
}

#[test]
fn a_merge_takes_the_one_tree_of_its_eligible_utxos() {
    let owner = keypair(1);
    let mut with_data = wallet_utxo(&owner, Mint::SOL, 10, 1, 3);
    with_data.data_hash = Some([4; 32]);
    let wallet = vec![
        wallet_utxo(&owner, Mint::SOL, 10, 0, 1),
        wallet_utxo(&owner, Mint::SOL, 10, 1, 2),
        with_data,
    ];
    assert_eq!(
        spend_tree(&wallet, Mint::SOL.asset, WalletUtxo::is_plain),
        Err(TransactionError::BalanceOnSeveralTrees { trees: 2 })
    );
    assert_eq!(
        spend_tree(&wallet[..1], Mint::SOL.asset, WalletUtxo::is_plain),
        Ok(0)
    );
    assert_eq!(
        spend_tree(&wallet[2..], Mint::SOL.asset, WalletUtxo::is_plain),
        Err(TransactionError::NoSpendableBalance {
            asset: Mint::SOL.asset
        })
    );
    assert_eq!(
        spend_tree(&wallet, TOKEN.asset, WalletUtxo::is_plain),
        Err(TransactionError::NoSpendableBalance { asset: TOKEN.asset })
    );
}

#[test]
fn needs_a_merge_beyond_max_spend_inputs() {
    let owner = keypair(1);
    let count = u8::try_from(MAX_SPEND_INPUTS + 1).unwrap();
    let wallet: Vec<_> = (1..=count)
        .map(|nonce| wallet_utxo(&owner, Mint::SOL, 10, 0, nonce))
        .collect();
    let amount = 10 * u64::from(count);
    assert_eq!(
        select_spend(&wallet, Mint::SOL.asset, amount),
        Err(TransactionError::SpendNeedsMerge {
            amount,
            max_inputs: MAX_SPEND_INPUTS
        })
    );
}

#[test]
fn a_merge_is_reported_even_when_excluded_utxos_would_cover_the_amount() {
    let owner = keypair(1);
    let count = u8::try_from(MAX_SPEND_INPUTS + 1).unwrap();
    let large = wallet_utxo(&owner, Mint::SOL, 100, 0, count + 1);
    let excluded = HashSet::from([large.nullifier]);
    let mut wallet: Vec<_> = (1..=count)
        .map(|nonce| wallet_utxo(&owner, Mint::SOL, 10, 0, nonce))
        .collect();
    wallet.push(large);
    let amount = 10 * u64::from(count);
    assert_eq!(
        select_spend_excluding(&wallet, Mint::SOL.asset, amount, &excluded),
        Err(TransactionError::SpendNeedsMerge {
            amount,
            max_inputs: MAX_SPEND_INPUTS
        })
    );
}
