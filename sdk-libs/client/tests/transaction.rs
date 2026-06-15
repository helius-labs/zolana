//! Unit tests for the `Transaction` builder abstraction that do not need the
//! prover server: change derivation, blinding positions, the encrypted-bundle
//! round-trip, rail detection, external-data assembly, and the error paths.

#[path = "common/test_indexer.rs"]
mod test_indexer;

use rand::{rngs::ThreadRng, RngCore};
use solana_address::Address;
use test_indexer::TestIndexer;
use zolana_client::private_transaction::field::signed_to_field;
use zolana_client::{
    CircuitType, ClientError, PublicAmounts, Rpc, SignedTransaction, SpendUtxo, Transaction,
    TransferP256Prover, WithdrawalTarget,
};
use zolana_keypair::shielded::ShieldedKeypair;
use zolana_keypair::{NullifierKey, PublicKey};
use zolana_transaction::transfer::{
    TransferEncryptedUtxos, TransferRecipientPlaintext, TransferSenderPlaintext,
};
use zolana_transaction::utxo::derive_blinding;
use zolana_transaction::{
    AssetRegistry, Data, ExternalData, OutputUtxo, TransactionEncryption, Utxo, SOL_ASSET_ID,
    SOL_MINT,
};

fn blinding(rng: &mut ThreadRng) -> [u8; 31] {
    let mut b = [0u8; 31];
    rng.fill_bytes(&mut b);
    b
}

fn p256_input(sender: &ShieldedKeypair, amount: u64, rng: &mut ThreadRng) -> SpendUtxo {
    let utxo = Utxo {
        owner: sender.signing_pubkey(),
        asset: SOL_MINT,
        amount,
        blinding: blinding(rng),
        zone_program_id: None,
        data: Data::default(),
    };
    SpendUtxo::from((utxo, sender))
}

fn registry() -> AssetRegistry {
    AssetRegistry::new([]).expect("registry")
}

fn sign(tx: Transaction, sender: &ShieldedKeypair) -> Result<SignedTransaction, ClientError> {
    tx.sign(
        sender,
        &registry(),
        sender.get_sender_view_tag(0).expect("sender view tag"),
    )
}

fn prover_of(signed: SignedTransaction) -> TransferP256Prover {
    let mut indexer = TestIndexer::new();
    let commitments = signed.input_commitments().expect("commitments");
    for commitment in &commitments {
        indexer.add_utxo(commitment.utxo_hash);
    }
    let input_merkle_proofs = indexer
        .get_input_merkle_proofs(&commitments)
        .expect("input merkle proofs");
    match signed
        .into_prover(&input_merkle_proofs)
        .expect("into prover")
    {
        CircuitType::P256(prover) => prover,
        CircuitType::Eddsa(_) => panic!("expected P256 rail"),
    }
}

fn decrypt(
    sender: &ShieldedKeypair,
    first_nullifier: &[u8; 32],
    external_data: &ExternalData,
) -> (TransferSenderPlaintext, Vec<TransferRecipientPlaintext>) {
    let blob = TransferEncryptedUtxos::deserialize(&external_data.encrypted_utxos).unwrap();
    sender
        .viewing_key
        .decrypt_transfer(first_nullifier, &blob)
        .unwrap()
}

#[test]
fn transfer_round_trip_outputs_and_bundle() {
    let mut rng = rand::thread_rng();
    let sender = ShieldedKeypair::new().unwrap();
    let recipient = ShieldedKeypair::new().unwrap();
    let sender_owner = sender.shielded_address().unwrap().owner_hash().unwrap();
    let recipient_owner = recipient.shielded_address().unwrap().owner_hash().unwrap();

    let mut tx = Transaction::new(
        sender.shielded_address().unwrap(),
        vec![p256_input(&sender, 100, &mut rng)],
        Address::default(),
    );
    tx.send(
        &recipient.shielded_address().unwrap(),
        SOL_MINT,
        60,
        recipient.recipient_bootstrap_view_tag(),
    )
    .unwrap();

    let signed = sign(tx, &sender).unwrap();
    let first_nullifier = signed
        .input_commitments()
        .unwrap()
        .first()
        .unwrap()
        .nullifier;
    let prover = prover_of(signed);
    let (sender_pt, recipients_pt) = decrypt(&sender, &first_nullifier, &prover.external_data);
    let seed = sender_pt.blinding_seed;

    // Proof outputs: SOL change (position 1) + recipient (position 2).
    assert_eq!(
        prover.outputs,
        vec![
            OutputUtxo {
                owner_hash: sender_owner,
                asset: SOL_MINT,
                amount: 40,
                blinding: derive_blinding(&seed, 1),
                ..Default::default()
            },
            OutputUtxo {
                owner_hash: recipient_owner,
                asset: SOL_MINT,
                amount: 60,
                blinding: derive_blinding(&seed, 2),
                ..Default::default()
            },
        ]
    );

    // A pure transfer moves no public value.
    assert_eq!(prover.public_amounts, PublicAmounts::transfer());

    // External data: transact discriminator, no public movement, defaulted
    // accounts; the random ciphertext is passed through.
    assert_eq!(
        prover.external_data,
        ExternalData {
            instruction_discriminator: 0,
            expiry_unix_ts: 0,
            sender_view_tag: sender.get_sender_view_tag(0).unwrap(),
            relayer_fee: 0,
            public_sol_amount: 0,
            public_spl_amount: 0,
            user_sol_account: Address::default(),
            user_spl_token: Address::default(),
            spl_token_interface: Address::default(),
            encrypted_utxos: prover.external_data.encrypted_utxos.clone(),
        }
    );

    // The encrypted bundle decrypts back to the sender change + recipient.
    assert_eq!(
        sender_pt,
        TransferSenderPlaintext {
            owner_pubkey: sender.signing_pubkey(),
            spl_asset_id: 0,
            spl_amount: 0,
            sol_amount: 40,
            blinding_seed: seed,
            recipient_viewing_pks: vec![recipient.viewing_pubkey()],
            spl_data: Data::default(),
            sol_data: Data::default(),
        }
    );
    assert_eq!(
        recipients_pt,
        vec![TransferRecipientPlaintext {
            owner_pubkey: recipient.signing_pubkey(),
            sender_pubkey: sender.viewing_pubkey(),
            asset_id: SOL_ASSET_ID,
            amount: 60,
            blinding: derive_blinding(&seed, 2),
            data: Data::default(),
        }]
    );
}

#[test]
fn withdrawal_sets_external_data_and_change() {
    let mut rng = rand::thread_rng();
    let sender = ShieldedKeypair::new().unwrap();
    let sender_owner = sender.shielded_address().unwrap().owner_hash().unwrap();
    let dest = Address::new_from_array([9u8; 32]);

    let mut tx = Transaction::new(
        sender.shielded_address().unwrap(),
        vec![p256_input(&sender, 100, &mut rng)],
        Address::default(),
    );
    tx.withdraw(
        SOL_MINT,
        30,
        WithdrawalTarget::Sol {
            user_sol_account: dest,
        },
    )
    .unwrap();

    let signed = sign(tx, &sender).unwrap();
    let first_nullifier = signed
        .input_commitments()
        .unwrap()
        .first()
        .unwrap()
        .nullifier;
    let prover = prover_of(signed);
    let (sender_pt, recipients_pt) = decrypt(&sender, &first_nullifier, &prover.external_data);
    let seed = sender_pt.blinding_seed;

    assert_eq!(
        prover.outputs,
        vec![OutputUtxo {
            owner_hash: sender_owner,
            asset: SOL_MINT,
            amount: 70,
            blinding: derive_blinding(&seed, 1),
            ..Default::default()
        }]
    );
    assert!(recipients_pt.is_empty());
    assert_eq!(
        prover.public_amounts,
        PublicAmounts {
            sol: signed_to_field(-30),
            spl: [0u8; 32],
            asset: [0u8; 32],
        }
    );
    assert_eq!(
        prover.external_data,
        ExternalData {
            instruction_discriminator: 0,
            expiry_unix_ts: 0,
            sender_view_tag: sender.get_sender_view_tag(0).unwrap(),
            relayer_fee: 0,
            public_sol_amount: 30,
            public_spl_amount: 0,
            user_sol_account: dest,
            user_spl_token: Address::default(),
            spl_token_interface: Address::default(),
            encrypted_utxos: prover.external_data.encrypted_utxos.clone(),
        }
    );
}

#[test]
fn rail_follows_input_owner_type() {
    let mut rng = rand::thread_rng();
    let sender = ShieldedKeypair::new().unwrap();

    let p256_tx = Transaction::new(
        sender.shielded_address().unwrap(),
        vec![p256_input(&sender, 10, &mut rng)],
        Address::default(),
    );
    assert!(p256_tx.requires_p256_owner().unwrap());

    let ed_input = SpendUtxo {
        utxo: Utxo {
            owner: PublicKey::from_ed25519(&[1u8; 32]),
            asset: SOL_MINT,
            amount: 10,
            blinding: blinding(&mut rng),
            zone_program_id: None,
            data: Data::default(),
        },
        nullifier_key: NullifierKey::from_secret(blinding(&mut rng)),
        zone_data_hash: None,
        program_data_hash: None,
    };
    let ed_tx = Transaction::new(
        sender.shielded_address().unwrap(),
        vec![ed_input],
        Address::default(),
    );
    assert!(!ed_tx.requires_p256_owner().unwrap());

    let signed = ed_tx
        .finalize(&sender, &registry(), sender.get_sender_view_tag(0).unwrap())
        .unwrap();
    let mut indexer = TestIndexer::new();
    let commitments = signed.input_commitments().unwrap();
    for commitment in &commitments {
        indexer.add_utxo(commitment.utxo_hash);
    }
    let input_merkle_proofs = indexer.get_input_merkle_proofs(&commitments).unwrap();
    assert!(matches!(
        signed.into_prover(&input_merkle_proofs).unwrap(),
        CircuitType::Eddsa(_)
    ));
}

#[test]
fn sign_without_inputs_is_no_inputs() {
    let sender = ShieldedKeypair::new().unwrap();
    let tx = Transaction::new(
        sender.shielded_address().unwrap(),
        vec![],
        Address::default(),
    );
    assert!(matches!(sign(tx, &sender), Err(ClientError::NoInputs)));
}

#[test]
fn oversend_is_insufficient_balance() {
    let mut rng = rand::thread_rng();
    let sender = ShieldedKeypair::new().unwrap();
    let recipient = ShieldedKeypair::new().unwrap();

    let mut tx = Transaction::new(
        sender.shielded_address().unwrap(),
        vec![p256_input(&sender, 100, &mut rng)],
        Address::default(),
    );
    tx.send(
        &recipient.shielded_address().unwrap(),
        SOL_MINT,
        200,
        recipient.recipient_bootstrap_view_tag(),
    )
    .unwrap();
    match sign(tx, &sender) {
        Err(ClientError::InsufficientBalance {
            requested,
            available,
        }) => assert_eq!((requested, available), (100, 0)),
        _ => panic!("expected InsufficientBalance"),
    }
}

#[test]
fn second_withdraw_is_rejected() {
    let mut rng = rand::thread_rng();
    let sender = ShieldedKeypair::new().unwrap();
    let mut tx = Transaction::new(
        sender.shielded_address().unwrap(),
        vec![p256_input(&sender, 100, &mut rng)],
        Address::default(),
    );
    tx.withdraw(
        SOL_MINT,
        10,
        WithdrawalTarget::Sol {
            user_sol_account: Address::default(),
        },
    )
    .unwrap();
    assert!(matches!(
        tx.withdraw(
            SOL_MINT,
            5,
            WithdrawalTarget::Sol {
                user_sol_account: Address::default(),
            },
        ),
        Err(ClientError::WithdrawalAlreadySet)
    ));
}

#[test]
fn two_distinct_spl_assets_are_rejected() {
    let mut rng = rand::thread_rng();
    let sender = ShieldedKeypair::new().unwrap();
    let ra = ShieldedKeypair::new().unwrap();
    let rb = ShieldedKeypair::new().unwrap();

    let mut tx = Transaction::new(
        sender.shielded_address().unwrap(),
        vec![p256_input(&sender, 100, &mut rng)],
        Address::default(),
    );
    tx.send(
        &ra.shielded_address().unwrap(),
        Address::new_from_array([2u8; 32]),
        1,
        ra.recipient_bootstrap_view_tag(),
    )
    .unwrap();
    tx.send(
        &rb.shielded_address().unwrap(),
        Address::new_from_array([3u8; 32]),
        1,
        rb.recipient_bootstrap_view_tag(),
    )
    .unwrap();
    assert!(matches!(
        sign(tx, &sender),
        Err(ClientError::MultiplePublicSplAssets)
    ));
}
