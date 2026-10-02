//! `WalletHistory::entries` over synthetic transactions: what each one did to
//! the wallet's balance of each asset.

mod common;

use common::{keypair, wallet_utxo};
use solana_address::Address;
use solana_signature::Signature;
use zolana_transaction::{
    HistoryKind, Mint, OutputContext, OutputSlot, ShieldedTransaction, WalletHistory, WalletUtxo,
};

const TREE: u16 = 1;

fn output(utxo: &WalletUtxo) -> OutputSlot {
    OutputSlot {
        view_tag: [0; 32],
        output_context: OutputContext {
            hash: utxo.utxo_hash,
            tree_id: utxo.tree_id,
            leaf_index: utxo.leaf_index,
        },
        payload: Vec::new(),
    }
}

/// A transaction in `slot` that spends `inputs` and creates `outputs`.
fn transaction(
    signature: u8,
    slot: u64,
    inputs: &[&WalletUtxo],
    outputs: &[&WalletUtxo],
) -> ShieldedTransaction {
    ShieldedTransaction {
        slot,
        tx_signature: Signature::from([signature; 64]),
        event_index: Some(0),
        tx_viewing_pk: None,
        salt: None,
        output_slots: outputs.iter().map(|utxo| output(utxo)).collect(),
        messages: Vec::new(),
        nullifiers: inputs.iter().map(|utxo| utxo.nullifier).collect(),
        proofless: false,
        ring_config: None,
        ring_program_id: None,
    }
}

/// A deposit instruction's output, published as its own event.
fn deposit(signature: u8, slot: u64, utxo: &WalletUtxo) -> ShieldedTransaction {
    ShieldedTransaction {
        event_index: None,
        proofless: true,
        ..transaction(signature, slot, &[], &[utxo])
    }
}

/// The entries of one transaction, given the UTXOs the wallet owns.
fn classify(owned: &[&WalletUtxo], tx: ShieldedTransaction) -> Vec<(HistoryKind, u64)> {
    WalletHistory {
        transactions: vec![tx],
        utxos: owned.iter().map(|&utxo| utxo.clone()).collect(),
        ..WalletHistory::default()
    }
    .entries()
    .into_iter()
    .map(|entry| (entry.kind, entry.amount))
    .collect()
}

#[test]
fn each_transaction_is_classified_by_the_wallets_utxos_it_moved() {
    use HistoryKind::*;
    let owner = keypair(1);
    let other = keypair(2);
    let ours = |amount, nonce| wallet_utxo(&owner, Mint::SOL, amount, TREE, nonce);
    let theirs = |amount, nonce| wallet_utxo(&other, Mint::SOL, amount, TREE, nonce);

    let deposited = ours(50, 1);
    assert_eq!(
        classify(&[&deposited], deposit(1, 1, &deposited)),
        [(Deposit, 50)]
    );

    // A payment from another wallet, with that wallet's change.
    let (paid, their_change) = (ours(7, 2), theirs(3, 3));
    assert_eq!(
        classify(&[&paid], transaction(2, 2, &[], &[&paid, &their_change])),
        [(Received, 7)]
    );

    // A payment to another wallet keeps the change, or spends a whole UTXO.
    let (input, change, payment) = (ours(30, 4), ours(20, 5), theirs(10, 6));
    assert_eq!(
        classify(
            &[&input, &change],
            transaction(3, 3, &[&input], &[&payment, &change])
        ),
        [(Sent, 10)]
    );
    let (input, payment) = (ours(100, 7), theirs(100, 8));
    assert_eq!(
        classify(&[&input], transaction(4, 4, &[&input], &[&payment])),
        [(Sent, 100)]
    );

    // Every output is the wallet's own: what did not come back was withdrawn.
    // The zero-amount padding output is the wallet's too.
    let (input, change, padding) = (ours(50, 9), ours(40, 10), ours(0, 11));
    assert_eq!(
        classify(
            &[&input, &change, &padding],
            transaction(5, 5, &[&input], &[&change, &padding])
        ),
        [(Withdrawal, 10)]
    );
    let (input, padding) = (ours(50, 12), ours(0, 13));
    assert_eq!(
        classify(
            &[&input, &padding],
            transaction(6, 6, &[&input], &[&padding])
        ),
        [(Withdrawal, 50)]
    );

    // A merge, and a transfer to the wallet itself.
    let (first, second, merged) = (ours(30, 14), ours(30, 15), ours(60, 16));
    assert_eq!(
        classify(
            &[&first, &second, &merged],
            transaction(7, 7, &[&first, &second], &[&merged])
        ),
        [(SelfTransfer, 60)]
    );
    let (input, to_self, change) = (ours(25, 17), ours(5, 18), ours(20, 19));
    assert_eq!(
        classify(
            &[&input, &to_self, &change],
            transaction(8, 8, &[&input], &[&to_self, &change])
        ),
        [(SelfTransfer, 25)]
    );

    // A spend with a public deposit leg gives back more than it spent: the
    // extra is the deposit, here net of a payment to another wallet.
    let (input, change) = (ours(30, 22), ours(70, 23));
    assert_eq!(
        classify(
            &[&input, &change],
            transaction(10, 10, &[&input], &[&change])
        ),
        [(Deposit, 40)]
    );
    let (input, change, payment) = (ours(30, 24), ours(60, 25), theirs(10, 26));
    assert_eq!(
        classify(
            &[&input, &change],
            transaction(11, 11, &[&input], &[&payment, &change])
        ),
        [(Deposit, 30)]
    );

    // Another wallet's transaction moves nothing of this wallet's.
    let (their_input, their_output) = (theirs(9, 20), theirs(9, 21));
    assert!(classify(&[], transaction(9, 9, &[&their_input], &[&their_output])).is_empty());
}

#[test]
fn entries_list_newest_first_with_one_entry_per_asset_and_transaction() {
    let owner = keypair(3);
    let other = keypair(4);
    let token = Mint::new(Address::new_from_array([9; 32]), 2);

    // One deposit instruction shielding two outputs arrives as two events.
    let (first_deposit, second_deposit) = (
        wallet_utxo(&owner, Mint::SOL, 30, TREE, 1),
        wallet_utxo(&owner, Mint::SOL, 12, TREE, 2),
    );
    // A payment of the token and of SOL in one transaction.
    let (paid_token, paid_sol) = (
        wallet_utxo(&owner, token, 9, TREE, 3),
        wallet_utxo(&owner, Mint::SOL, 5, TREE, 4),
    );
    // A token payment to another wallet whose padding is zero SOL.
    let (token_change, padding, payment) = (
        wallet_utxo(&owner, token, 5, TREE, 5),
        wallet_utxo(&owner, Mint::SOL, 0, TREE, 6),
        wallet_utxo(&other, token, 4, TREE, 7),
    );
    let history = WalletHistory {
        transactions: vec![
            deposit(1, 10, &first_deposit),
            transaction(3, 30, &[&paid_token], &[&payment, &token_change, &padding]),
            deposit(1, 10, &second_deposit),
            transaction(2, 20, &[], &[&paid_token, &paid_sol]),
        ],
        utxos: vec![
            first_deposit,
            second_deposit,
            paid_token.clone(),
            paid_sol,
            token_change,
            padding,
        ],
        ..WalletHistory::default()
    };

    let entries: Vec<_> = history
        .entries()
        .into_iter()
        .map(|entry| {
            (
                entry.slot,
                entry.tx_signature,
                entry.kind,
                entry.mint,
                entry.amount,
            )
        })
        .collect();
    assert_eq!(
        entries,
        [
            (
                30,
                Signature::from([3; 64]),
                HistoryKind::Sent,
                token.asset,
                4
            ),
            (
                20,
                Signature::from([2; 64]),
                HistoryKind::Received,
                Mint::SOL.asset,
                5
            ),
            (
                20,
                Signature::from([2; 64]),
                HistoryKind::Received,
                token.asset,
                9
            ),
            (
                10,
                Signature::from([1; 64]),
                HistoryKind::Deposit,
                Mint::SOL.asset,
                42
            ),
        ]
    );
}
