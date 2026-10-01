//! Which notes a spend takes: largest first, one tree, bounded by the widest
//! automatic shape, leaving out excluded notes.
mod common;

use std::collections::HashSet;

use common::{keypair, wallet_utxo};
use solana_address::Address;
use zolana_transaction::{
    error::TransactionError, instructions::transact::auto_shapes, is_plain_utxo, AssetBalance,
    Balances, Mint, SpendableDecryptionResult, WalletUtxo,
};

const TOKEN: Mint = Mint::new(Address::new_from_array([7; 32]), 2);

fn spendable(notes: Vec<WalletUtxo>) -> SpendableDecryptionResult {
    let mut assets: Vec<AssetBalance> = Vec::new();
    for note in notes {
        match assets.iter_mut().find(|b| b.mint == note.utxo.asset.asset) {
            Some(balance) => {
                balance.amount += note.utxo.amount;
                balance.utxos.push(note);
            }
            None => assets.push(AssetBalance {
                asset_id: note.utxo.asset.asset_id,
                mint: note.utxo.asset.asset,
                amount: note.utxo.amount,
                utxos: vec![note],
            }),
        }
    }
    SpendableDecryptionResult {
        balances: Balances { assets },
        ..Default::default()
    }
}

fn amounts(notes: &[WalletUtxo]) -> Vec<u64> {
    notes.iter().map(|note| note.utxo.amount).collect()
}

#[test]
fn takes_the_largest_notes_of_the_asset_until_the_amount_is_covered() {
    let owner = keypair(1);
    let wallet = spendable(vec![
        wallet_utxo(&owner, Mint::SOL, 20, 0, 1),
        wallet_utxo(&owner, Mint::SOL, 50, 0, 2),
        wallet_utxo(&owner, Mint::SOL, 30, 0, 3),
        wallet_utxo(&owner, TOKEN, 500, 0, 4),
    ]);
    let none = HashSet::new();
    let select = |amount| wallet.select_spend(Mint::SOL.asset, amount, &none);
    assert_eq!(amounts(&select(40).unwrap()), [50]);
    assert_eq!(amounts(&select(60).unwrap()), [50, 30]);
    assert_eq!(
        select(101),
        Err(TransactionError::InsufficientBalance {
            requested: 101,
            available: 100,
        })
    );
    assert_eq!(
        amounts(&wallet.select_spend(TOKEN.asset, 500, &none).unwrap()),
        [500]
    );
}

#[test]
fn leaves_out_excluded_notes() {
    let owner = keypair(1);
    let notes = vec![
        wallet_utxo(&owner, Mint::SOL, 50, 0, 1),
        wallet_utxo(&owner, Mint::SOL, 30, 0, 2),
        wallet_utxo(&owner, Mint::SOL, 20, 0, 3),
    ];
    let excluded = HashSet::from([notes[0].nullifier]);
    let wallet = spendable(notes);
    let select = |amount| wallet.select_spend(Mint::SOL.asset, amount, &excluded);
    assert_eq!(amounts(&select(40).unwrap()), [30, 20]);
    assert_eq!(
        select(60),
        Err(TransactionError::SpendNeedsExcludedNotes { amount: 60 })
    );
    assert_eq!(
        select(101),
        Err(TransactionError::InsufficientBalance {
            requested: 101,
            available: 50,
        })
    );
}

#[test]
fn spends_one_tree_of_default_ring_notes() {
    let owner = keypair(1);
    let mut ring_bound = wallet_utxo(&owner, Mint::SOL, 1_000, 0, 3);
    ring_bound.utxo.ring_program_id = Some(Address::new_from_array([9; 32]));
    let wallet = spendable(vec![
        wallet_utxo(&owner, Mint::SOL, 10, 0, 1),
        wallet_utxo(&owner, Mint::SOL, 10, 1, 2),
        ring_bound,
    ]);
    let none = HashSet::new();
    assert_eq!(
        wallet.select_spend(Mint::SOL.asset, 5, &none),
        Err(TransactionError::BalanceOnSeveralTrees { trees: 2 })
    );
    assert_eq!(
        wallet.select_spend(TOKEN.asset, 5, &none),
        Err(TransactionError::NoSpendableBalance { asset: TOKEN.asset })
    );
    assert_eq!(
        wallet.spend_tree(Mint::SOL.asset, |note| note.tree_id() == 1),
        Ok(1)
    );
    assert_eq!(
        wallet.spend_tree(Mint::SOL.asset, is_plain_utxo),
        Err(TransactionError::BalanceOnSeveralTrees { trees: 2 })
    );
}

#[test]
fn needs_a_merge_beyond_the_widest_shape() {
    let owner = keypair(1);
    let max_inputs = auto_shapes().map(|shape| shape.n_inputs()).max().unwrap();
    let count = u8::try_from(max_inputs + 1).unwrap();
    let wallet = spendable(
        (1..=count)
            .map(|nonce| wallet_utxo(&owner, Mint::SOL, 10, 0, nonce))
            .collect(),
    );
    let amount = 10 * u64::from(count);
    assert_eq!(
        wallet.select_spend(Mint::SOL.asset, amount, &HashSet::new()),
        Err(TransactionError::SpendNeedsMerge { amount, max_inputs })
    );
}
