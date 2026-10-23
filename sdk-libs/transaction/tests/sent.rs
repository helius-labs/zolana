//! A transaction read as the wallet that sent it, and one transaction read
//! without the rest of the wallet's history.

mod transfer_fixtures;

use transfer_fixtures::{build_unified_transfer, keypair_from_index, UnifiedTransferSpec};
use zolana_event::SplTransfer;
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{
    decrypt_sent, AssetRegistry, HistoryKind, ShieldedTransaction, TransactionDetail, SOL_MINT,
};

/// A transfer of `amount` from `sender` to `recipient` that keeps `change`,
/// in output order: the change, a padding slot, then the payment.
fn transfer(
    sender: &ShieldedKeypair,
    recipient: &ShieldedKeypair,
    amount: u64,
    change: u64,
) -> ShieldedTransaction {
    let mut first_nullifier = [0x0b; 32];
    first_nullifier[0] = 0;
    let (tx, _, _) = build_unified_transfer(
        &AssetRegistry::default(),
        UnifiedTransferSpec {
            sender,
            recipient,
            amount,
            change_amount: change,
            first_nullifier,
            blinding: [0; 32].map(|_: u8| 0x05),
            change_blinding: [0; 32].map(|_: u8| 0x06),
        },
    );
    tx
}

/// `tx` without the payment: what the sender kept, and padding.
fn without_payment(mut tx: ShieldedTransaction) -> ShieldedTransaction {
    tx.output_slots.truncate(2);
    tx
}

fn withdrawal(amount: u64) -> SplTransfer {
    SplTransfer {
        is_deposit: false,
        amount,
        asset: None,
    }
}

/// The entries of `events` as `wallet` reads them.
fn read(
    wallet: &ShieldedKeypair,
    events: &[ShieldedTransaction],
    public: &[Vec<SplTransfer>],
) -> Vec<(HistoryKind, u64)> {
    let detail =
        TransactionDetail::read(wallet, events, public, &AssetRegistry::default()).unwrap();
    assert!(detail.entries.iter().all(|entry| entry.mint == SOL_MINT));
    detail
        .entries
        .iter()
        .map(|entry| (entry.kind, entry.amount))
        .collect()
}

#[test]
fn the_sender_opens_every_output_it_paid_and_nobody_else_does() {
    let (sender, recipient, other) = (
        keypair_from_index(1),
        keypair_from_index(2),
        keypair_from_index(3),
    );
    let tx = transfer(&sender, &recipient, 70, 30);
    let assets = AssetRegistry::default();

    let sent = decrypt_sent(&sender, &tx, &assets)
        .unwrap()
        .expect("the sender derives the published transaction key");
    let outputs: Vec<_> = sent
        .outputs
        .iter()
        .map(|output| (output.slot_index, output.amount, output.owned))
        .collect();
    assert_eq!(outputs, [(0, 30, true), (2, 70, false)]);
    assert_eq!(
        sent.outputs[0].recipient_viewing_pk,
        sender.viewing_pubkey()
    );
    assert_eq!(
        sent.outputs[1].recipient_viewing_pk,
        recipient.viewing_pubkey()
    );
    assert!(sent.unknown_asset_ids.is_empty());

    assert_eq!(decrypt_sent(&recipient, &tx, &assets).unwrap(), None);
    assert_eq!(decrypt_sent(&other, &tx, &assets).unwrap(), None);

    let mut unkeyed = tx;
    unkeyed.tx_viewing_pk = None;
    assert_eq!(decrypt_sent(&sender, &unkeyed, &assets).unwrap(), None);
}

/// Each side reads what `History::entries` reports, with no earlier
/// transaction: the sender learns what it spent from the outputs it opens
/// and the public legs.
#[test]
fn one_transaction_reads_as_its_history_entries() {
    use HistoryKind::*;
    let (sender, recipient, other) = (
        keypair_from_index(1),
        keypair_from_index(2),
        keypair_from_index(3),
    );
    let tx = numbered(transfer(&sender, &recipient, 70, 30), 0);

    assert_eq!(read(&sender, std::slice::from_ref(&tx), &[]), [(Sent, 70)]);
    assert_eq!(
        read(&recipient, std::slice::from_ref(&tx), &[]),
        [(Received, 70)]
    );
    assert_eq!(read(&other, std::slice::from_ref(&tx), &[]), []);

    // A payment that also withdraws counts its public part as sent.
    assert_eq!(
        read(&sender, std::slice::from_ref(&tx), &[vec![withdrawal(5)]]),
        [(Sent, 75)]
    );

    // No payment: what left publicly was withdrawn, and with nothing public
    // either the transaction moved notes within the wallet.
    let kept = without_payment(tx.clone());
    assert_eq!(
        read(
            &sender,
            std::slice::from_ref(&kept),
            &[vec![withdrawal(50)]]
        ),
        [(Withdrawal, 50)]
    );
    assert_eq!(read(&sender, &[kept], &[]), [(SelfTransfer, 30)]);

    let detail = TransactionDetail::read(
        &sender,
        std::slice::from_ref(&tx),
        &[],
        &AssetRegistry::default(),
    )
    .unwrap();
    assert_eq!(detail.sent.len(), 2);
    assert_eq!(detail.entries[0].tx_signature, tx.tx_signature);
    let detail =
        TransactionDetail::read(&recipient, &[tx], &[], &AssetRegistry::default()).unwrap();
    assert!(detail.sent.is_empty());

    assert_eq!(
        TransactionDetail::read(&sender, &[], &[], &AssetRegistry::default()).unwrap(),
        TransactionDetail::default()
    );
}

fn deposit(amount: u64) -> SplTransfer {
    SplTransfer {
        is_deposit: true,
        amount,
        asset: None,
    }
}

/// `tx` as the event the indexer numbers `event_index` in its transaction.
fn numbered(mut tx: ShieldedTransaction, event_index: u16) -> ShieldedTransaction {
    tx.event_index = Some(event_index);
    tx
}

/// An event's public legs net before what it spent is inferred, so their
/// order does not matter: 20 kept, 100 deposited and 110 withdrawn spent 30.
#[test]
fn public_legs_net_in_any_order() {
    let (sender, recipient) = (keypair_from_index(1), keypair_from_index(2));
    let kept = numbered(without_payment(transfer(&sender, &recipient, 70, 20)), 0);
    for legs in [
        vec![deposit(100), withdrawal(110)],
        vec![withdrawal(110), deposit(100)],
    ] {
        assert_eq!(
            read(&sender, std::slice::from_ref(&kept), &[legs]),
            [(HistoryKind::Withdrawal, 10)]
        );
    }
}

/// Spending is inferred for each event: a payment received in another event
/// of the same transaction is not something the wallet spent.
#[test]
fn each_event_infers_its_own_spending() {
    let (sender, recipient, other) = (
        keypair_from_index(1),
        keypair_from_index(2),
        keypair_from_index(3),
    );
    let sent = numbered(transfer(&sender, &recipient, 70, 30), 0);
    let received = numbered(transfer(&other, &sender, 20, 5), 1);
    assert_eq!(sent.tx_signature, received.tx_signature);
    assert_eq!(
        read(
            &sender,
            &[sent.clone(), received.clone()],
            &[vec![], vec![]]
        ),
        [(HistoryKind::Sent, 50)]
    );
    // A leg of the incoming event is not the sender's either.
    assert_eq!(
        read(&sender, &[sent, received], &[vec![], vec![withdrawal(9)]]),
        [(HistoryKind::Sent, 50)]
    );
}
