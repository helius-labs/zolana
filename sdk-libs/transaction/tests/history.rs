//! `History::entries` over synthetic transactions: what each one did to
//! the wallet's balance of each asset.

mod common;

use std::collections::BTreeSet;

use common::{keypair, wallet_utxo};
use solana_address::Address;
use solana_signature::Signature;
use zolana_transaction::{
    History, HistoryKind, Mint, OutputContext, OutputSlot, ShieldedTransaction, WalletUtxo,
};

const TREE: u16 = 1;
/// The tag the wallet reads its transactions by.
const WALLET_TAG: [u8; 32] = [0xa5; 32];

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

/// `tx` with `count` dummy outputs, which a spend publishes under the
/// spender's tag and which no wallet owns.
fn with_dummies(mut tx: ShieldedTransaction, count: u8) -> ShieldedTransaction {
    for index in 0..count {
        tx.output_slots.push(OutputSlot {
            view_tag: WALLET_TAG,
            output_context: OutputContext {
                hash: [0xd0 + index; 32],
                tree_id: TREE,
                leaf_index: u64::from(index),
            },
            payload: vec![index; 64],
        });
    }
    tx
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
    History {
        transactions: vec![tx],
        utxos: owned.iter().map(|&utxo| utxo.clone()).collect(),
        view_tags: BTreeSet::from([WALLET_TAG]),
        ..History::default()
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
    // The spend's dummy outputs do not hide the payment.
    let (input, change, payment) = (ours(30, 4), ours(20, 5), theirs(10, 6));
    assert_eq!(
        classify(
            &[&input, &change],
            with_dummies(transaction(3, 3, &[&input], &[&payment, &change]), 1)
        ),
        [(Sent, 10)]
    );
    let (input, payment) = (ours(100, 7), theirs(100, 8));
    assert_eq!(
        classify(&[&input], transaction(4, 4, &[&input], &[&payment])),
        [(Sent, 100)]
    );

    // No output goes to another wallet: what did not come back was withdrawn.
    // The spend's dummy outputs are under the wallet's own tag.
    let (input, change) = (ours(50, 9), ours(40, 10));
    assert_eq!(
        classify(
            &[&input, &change],
            with_dummies(transaction(5, 5, &[&input], &[&change]), 1)
        ),
        [(Withdrawal, 10)]
    );
    let input = ours(50, 12);
    assert_eq!(
        classify(
            &[&input],
            with_dummies(transaction(6, 6, &[&input], &[]), 2)
        ),
        [(Withdrawal, 50)]
    );
    // A full withdrawal that names no other participant keeps a zero-amount
    // change.
    let (input, zero_change) = (ours(50, 13), ours(0, 11));
    assert_eq!(
        classify(
            &[&input, &zero_change],
            with_dummies(transaction(12, 12, &[&input], &[&zero_change]), 1)
        ),
        [(Withdrawal, 50)]
    );
    // The same unowned output under another wallet's tag is a payment to it.
    let input = ours(50, 27);
    let mut foreign = with_dummies(transaction(13, 13, &[&input], &[]), 1);
    foreign.output_slots[0].view_tag = [0x5a; 32];
    assert_eq!(classify(&[&input], foreign), [(Sent, 50)]);

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

/// The indexer lists a merge's output twice: under the merge, and as a
/// proofless event of the same transaction. It is one merge of what it spent.
#[test]
fn a_utxo_listed_under_two_events_of_a_transaction_counts_once() {
    let owner = keypair(1);
    let inputs = [
        wallet_utxo(&owner, Mint::SOL, 30, TREE, 1),
        wallet_utxo(&owner, Mint::SOL, 20, TREE, 2),
    ];
    let merged = wallet_utxo(&owner, Mint::SOL, 50, TREE, 3);
    let merge = transaction(7, 7, &[&inputs[0], &inputs[1]], &[&merged]);
    let listed_again = ShieldedTransaction {
        event_index: None,
        proofless: true,
        ..transaction(7, 7, &[], &[&merged])
    };
    let entries = History {
        transactions: vec![merge.clone(), listed_again, merge],
        utxos: vec![inputs[0].clone(), inputs[1].clone(), merged],
        view_tags: BTreeSet::from([WALLET_TAG]),
        ..History::default()
    }
    .entries();
    let entries: Vec<_> = entries
        .into_iter()
        .map(|entry| (entry.kind, entry.amount))
        .collect();
    assert_eq!(entries, [(HistoryKind::SelfTransfer, 50)]);
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
    // A token payment to another wallet with a zero-amount SOL change and a
    // dummy output.
    let (token_change, zero_sol, payment) = (
        wallet_utxo(&owner, token, 5, TREE, 5),
        wallet_utxo(&owner, Mint::SOL, 0, TREE, 6),
        wallet_utxo(&other, token, 4, TREE, 7),
    );
    let history = History {
        transactions: vec![
            deposit(1, 10, &first_deposit),
            with_dummies(
                transaction(3, 30, &[&paid_token], &[&payment, &token_change, &zero_sol]),
                1,
            ),
            deposit(1, 10, &second_deposit),
            transaction(2, 20, &[], &[&paid_token, &paid_sol]),
        ],
        utxos: vec![
            first_deposit,
            second_deposit,
            paid_token.clone(),
            paid_sol,
            token_change,
            zero_sol,
        ],
        view_tags: BTreeSet::from([WALLET_TAG]),
        ..History::default()
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
