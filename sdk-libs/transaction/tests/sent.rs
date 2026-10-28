//! A transaction read as the wallet that sent it, and one transaction read
//! without the rest of the wallet's history.

mod transfer_fixtures;

use transfer_fixtures::{build_unified_transfer, keypair_from_index, UnifiedTransferSpec};
use zolana_event::{OutputDataEncoding, SplTransfer};
use zolana_keypair::{ShieldedKeypair, SigningKey};
use zolana_transaction::{
    decrypt_sent,
    serialization::plaintext::{PlaintextEncode, PlaintextTransfer},
    utxo::derive_transact_output_blinding,
    AssetRegistry, Data, HistoryKind, Mint, OwnerCx, ShieldedTransaction, TransactionDetail,
    TransactionError, Utxo, UtxoSerialization, SOL_MINT,
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
        .utxos
        .iter()
        .map(|output| (output.slot_index, output.amount, output.owned))
        .collect();
    assert_eq!(outputs, [(0, 30, true), (2, 70, false)]);
    assert_eq!(sent.utxos[0].recipient_viewing_pk, sender.viewing_pubkey());
    assert_eq!(
        sent.utxos[1].recipient_viewing_pk,
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

/// Legs the indexer stored replace the chain list, and an empty stored list
/// is a recorded "settled nothing", so a chain withdrawal is not applied.
#[test]
fn recorded_settlement_legs_replace_the_chain_list() {
    let (sender, recipient) = (keypair_from_index(1), keypair_from_index(2));
    let mut kept = numbered(without_payment(transfer(&sender, &recipient, 70, 20)), 0);
    kept.spl_transfers = Some(vec![deposit(100), withdrawal(110)]);
    assert_eq!(
        read(&sender, std::slice::from_ref(&kept), &[]),
        [(HistoryKind::Withdrawal, 10)]
    );
    assert_eq!(
        read(&sender, std::slice::from_ref(&kept), &[vec![withdrawal(1)]]),
        [(HistoryKind::Withdrawal, 10)]
    );
    kept.spl_transfers = Some(vec![]);
    assert_eq!(
        read(
            &sender,
            std::slice::from_ref(&kept),
            &[vec![withdrawal(110)]]
        ),
        [(HistoryKind::SelfTransfer, 20)]
    );
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

/// Owners sharing a viewing key derive the same transaction key, so neither
/// can tell which of them sent a transfer between them.
#[test]
fn a_shared_viewing_key_cannot_tell_its_sender() {
    let sender = keypair_from_index(1);
    let sharer = ShieldedKeypair::with_viewing_key(
        SigningKey::from_ed25519_bytes(&[0x30; 32]),
        sender.viewing_key.clone(),
    )
    .unwrap();
    let tx = transfer(&sender, &sharer, 70, 30);
    for wallet in [&sender, &sharer] {
        assert_eq!(
            decrypt_sent(wallet, &tx, &AssetRegistry::default()),
            Err(TransactionError::AmbiguousSender)
        );
    }
}

/// A sent transfer with an output the sender does not read cannot say what
/// the sender paid.
#[test]
fn a_sent_output_in_another_format_is_unreadable() {
    let (sender, recipient) = (keypair_from_index(1), keypair_from_index(2));
    let mut tx = transfer(&sender, &recipient, 70, 30);
    tx.output_slots[2].payload = borsh::to_vec(&OutputDataEncoding::Plaintext(vec![7])).unwrap();
    assert_eq!(
        decrypt_sent(&sender, &tx, &AssetRegistry::default()),
        Err(TransactionError::SentOutputUnreadable { slot_index: 2 })
    );
}

/// A plaintext transfer has a merge's shape, nullifiers and no transaction
/// viewing key: what the recipient reads in it is received.
#[test]
fn a_plaintext_payment_is_received_not_merged() {
    let (sender, recipient) = (keypair_from_index(1), keypair_from_index(2));
    let assets = AssetRegistry::default();
    let (first_nullifier, blinding_seed) = ([0x0c; 32].map(|byte: u8| byte & 0x0f), [7; 32]);
    let payment = Utxo {
        owner: recipient.signing_pubkey(),
        asset: Mint::SOL,
        amount: 70,
        blinding: derive_transact_output_blinding(&first_nullifier, &blinding_seed, 0).unwrap(),
        ring_program_id: None,
        data: Data::default(),
    };
    let owner = OwnerCx {
        owner: sender.signing_pubkey(),
        assets: &assets,
        ring_program_id: None,
        first_nullifier: Some(first_nullifier),
    };
    let encode = PlaintextEncode {
        blinding_seed,
        first_nullifier,
    };
    let plaintext =
        PlaintextTransfer::from_utxos(std::slice::from_ref(&payment), &owner, &encode).unwrap();
    let mut blob = vec![PlaintextTransfer::SCHEME.as_byte()];
    blob.extend(PlaintextTransfer::serialize(&plaintext).unwrap());
    let mut tx = without_payment(transfer(&sender, &recipient, 70, 30));
    tx.tx_viewing_pk = None;
    tx.salt = None;
    tx.nullifiers = vec![first_nullifier];
    tx.output_slots.truncate(1);
    tx.output_slots[0].payload = borsh::to_vec(&OutputDataEncoding::Plaintext(blob)).unwrap();
    tx.output_slots[0].output_context.hash = payment
        .hash(
            &recipient.nullifier_key.pubkey().unwrap(),
            &[0; 32],
            &[0; 32],
            0,
        )
        .unwrap();
    assert_eq!(read(&recipient, &[tx], &[]), [(HistoryKind::Received, 70)]);
}
