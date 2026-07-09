//! End-to-end round trip for the `Transaction::split` builder path: build a
//! split of a known UTXO into N equal self-owned notes through the SDK builder,
//! project the signed transaction into the indexer's `ShieldedTransaction` shape
//! exactly as the on-chain event does, and recover it through `Wallet::sync`.
//! Asserts N self-owned notes with the right per-part amount come back, decoded
//! as `PrivateTransactionKind::Split`, and that the spent input is retired.

use borsh::BorshDeserialize;
use zolana_event::OutputData;
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{
    instructions::{
        transact::{
            OutputContext, OutputSlot, ShieldedTransaction, SignedTransaction, Transaction,
            WithdrawalTarget,
        },
        types::SpendUtxo,
    },
    wallet::{PrivateTransactionDirection, PrivateTransactionKind, Wallet, WalletUtxo},
    Address, AssetRegistry, Data, TransactionError, Utxo, SOL_ASSET_ID, SOL_MINT,
};

fn sol_utxo(keypair: &ShieldedKeypair, amount: u64) -> Utxo {
    Utxo {
        owner: keypair.signing_pubkey(),
        asset: SOL_MINT,
        amount,
        blinding: [9u8; 31],
        zone_program_id: None,
        data: Data::default(),
    }
}

/// Seed a fresh wallet with `input` as an already-owned unspent note, so a
/// subsequent split's nullifier resolves to a known spend and the outbound Split
/// history row records (mirrors a wallet that synced the deposit first).
fn wallet_holding(keypair: ShieldedKeypair, input: &Utxo) -> Wallet {
    let mut wallet = Wallet::new(keypair, AssetRegistry::default()).unwrap();
    let nullifier_pk = wallet.keypair.nullifier_key.pubkey().unwrap();
    let hash = input.hash(&nullifier_pk, &[0u8; 32], &[0u8; 32]).unwrap();
    let nullifier = input
        .nullifier(&hash, &wallet.keypair.nullifier_key)
        .unwrap();
    wallet.utxos.push(WalletUtxo {
        utxo: input.clone(),
        output_context: OutputContext {
            hash,
            tree: Address::default(),
            leaf_index: 0,
        },
        nullifier,
        spent: false,
    });
    wallet
}

/// The program's sender-slot mapping (`build_transact_event`): the bundle
/// ciphertext (`output_ciphertexts[0]`) covers the leading `n_outputs -
/// (n_ciphertexts - 1)` output positions.
fn sender_slot_count(n_outputs: usize, n_ciphertexts: usize) -> usize {
    n_outputs.saturating_sub(n_ciphertexts.saturating_sub(1))
}

/// Project a split `SignedTransaction` into the indexer's `ShieldedTransaction`,
/// mirroring the program's `build_transact_event` exactly. With
/// `n_ciphertexts = 1 + (n_outputs - N)`, `sender_slot_count == N`: position 0
/// carries the Split bundle, positions `1..N` are empty (the bundle already
/// covers them), and each tail position `N..n_outputs` carries its own aligned
/// dummy ciphertext. Every position's committed hash is published.
fn to_shielded_transaction(signed: &SignedTransaction) -> ShieldedTransaction {
    let external = &signed.external_data;
    let n_outputs = external.output_utxo_hashes.len();
    let n_ciphertexts = external.output_ciphertexts.len();
    let sender_slots = sender_slot_count(n_outputs, n_ciphertexts);
    let mut output_slots = Vec::with_capacity(n_outputs);
    for (i, hash) in external.output_utxo_hashes.iter().enumerate() {
        let ciphertext = if i == 0 {
            external.output_ciphertexts.first()
        } else if i < sender_slots {
            None
        } else {
            external.output_ciphertexts.get(1 + i - sender_slots)
        };
        let (view_tag, payload) = match ciphertext {
            Some(c) => (c.view_tag, c.data.clone()),
            None => ([0u8; 32], Vec::new()),
        };
        output_slots.push(OutputSlot {
            view_tag,
            output_context: OutputContext {
                hash: *hash,
                tree: Default::default(),
                leaf_index: i as u64,
            },
            payload,
        });
    }
    let tx_viewing_pk =
        zolana_keypair::P256Pubkey::from_bytes(external.tx_viewing_pk).expect("tx viewing pk");
    ShieldedTransaction {
        slot: 0,
        tx_signature: solana_signature::Signature::default(),
        tx_viewing_pk: Some(tx_viewing_pk),
        salt: Some(external.salt),
        output_slots,
        nullifiers: signed
            .inputs
            .iter()
            .filter(|spend| !spend.is_dummy())
            .map(|spend| {
                let nullifier_pk = spend.nullifier_key.pubkey().unwrap();
                let hash = spend
                    .utxo
                    .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
                    .unwrap();
                spend
                    .nullifier_key
                    .nullifier(&hash, &spend.utxo.blinding)
                    .unwrap()
            })
            .collect(),
        proofless: false,
    }
}

fn build_and_recover(num_outputs: u8, per_output_amount: u64) -> (Wallet, SignedTransaction) {
    let keypair = ShieldedKeypair::new().unwrap();
    let assets = AssetRegistry::default();
    let total = u64::from(num_outputs) * per_output_amount;
    let input = sol_utxo(&keypair, total);

    let mut tx = Transaction::new(
        keypair.shielded_address().unwrap(),
        vec![SpendUtxo::from_keypair(input.clone(), &keypair)],
        Address::default(),
    );
    tx.split(SOL_MINT, num_outputs, per_output_amount).unwrap();
    let signed = tx.sign(&keypair, &assets).unwrap();

    let shielded = to_shielded_transaction(&signed);
    let mut wallet = wallet_holding(keypair, &input);
    let report = wallet.sync(&[shielded], 1_700_000_000, 8).unwrap();
    assert_eq!(report.unparsed_transactions, 0, "split slot must classify");
    (wallet, signed)
}

/// The emitted shape must always be `{1, 8}` so the on-chain verifier selects the
/// `transfer(_p256)_confidential_1_8` verifying key from `inputs.len()` and
/// `output_utxo_hashes.len()`. `num_real` real self-split outputs are padded with
/// `8 - num_real` commitment-only dummies, and `1 + (8 - num_real)` ciphertexts
/// are emitted (one bundle at slot 0 plus one aligned dummy per padding output).
/// The bundle at slot 0 is an `Encrypted` blob tagged `Split`.
fn assert_shape_and_bundle(signed: &SignedTransaction, num_real: usize) {
    let external = &signed.external_data;
    assert_eq!(signed.shape.n_inputs, 1, "split shape is {{1, 8}}");
    assert_eq!(signed.shape.n_outputs, 8, "split shape is {{1, 8}}");
    assert_eq!(
        signed.inputs.len(),
        1,
        "one real input, no dummy inputs for {{1, 8}}"
    );
    assert_eq!(
        external.output_utxo_hashes.len(),
        8,
        "emitted output count must be the shape's 8, not the real {num_real}"
    );
    let expected_ciphertexts = 1 + (8 - num_real);
    assert_eq!(
        external.output_ciphertexts.len(),
        expected_ciphertexts,
        "one bundle plus one aligned dummy ciphertext per padding output"
    );
    // sender_slot_count must resolve to the real count so positions 0..N map to
    // the bundle and the dummies each map to their own tail ciphertext.
    assert_eq!(
        sender_slot_count(8, external.output_ciphertexts.len()),
        num_real
    );
    let blob = match OutputData::try_from_slice(&external.output_ciphertexts[0].data).unwrap() {
        OutputData::Encrypted(blob) => blob,
        other => panic!("split bundle must be Encrypted, got {other:?}"),
    };
    assert_eq!(
        blob.first().copied(),
        Some(zolana_transaction::EncryptedScheme::Split.as_byte())
    );
}

fn sol_balance(wallet: &Wallet) -> zolana_transaction::AssetBalance {
    wallet
        .balances(false)
        .unwrap()
        .into_iter()
        .find(|b| b.mint == SOL_MINT)
        .expect("sol balance")
}

#[test]
fn split_rejects_existing_send_and_prepare_rejects_recorded_split() {
    let keypair = ShieldedKeypair::new().unwrap();
    let recipient = ShieldedKeypair::new().unwrap();
    let input = sol_utxo(&keypair, 100);
    let mut tx = Transaction::new(
        keypair.shielded_address().unwrap(),
        vec![SpendUtxo::from_keypair(input, &keypair)],
        Address::default(),
    );

    tx.send(&recipient.shielded_address().unwrap(), SOL_MINT, 40)
        .unwrap();
    let err = match tx.split(SOL_MINT, 2, 50) {
        Ok(_) => panic!("split after send must error"),
        Err(err) => err,
    };
    assert_eq!(err, TransactionError::SplitWithOtherActions);

    let input = sol_utxo(&keypair, 100);
    let mut split_tx = Transaction::new(
        keypair.shielded_address().unwrap(),
        vec![SpendUtxo::from_keypair(input, &keypair)],
        Address::default(),
    );
    split_tx.split(SOL_MINT, 2, 50).unwrap();
    let err = match split_tx.prepare(&AssetRegistry::default()) {
        Ok(_) => panic!("prepare after split must error"),
        Err(err) => err,
    };
    assert_eq!(err, TransactionError::SplitWithOtherActions);
}

#[test]
fn split_rejects_withdrawal_and_send_after_split() {
    let keypair = ShieldedKeypair::new().unwrap();
    let recipient = ShieldedKeypair::new().unwrap();
    let input = sol_utxo(&keypair, 100);
    let mut tx = Transaction::new(
        keypair.shielded_address().unwrap(),
        vec![SpendUtxo::from_keypair(input, &keypair)],
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
    let err = match tx.split(SOL_MINT, 2, 50) {
        Ok(_) => panic!("split after withdrawal must error"),
        Err(err) => err,
    };
    assert_eq!(err, TransactionError::SplitWithOtherActions);

    let input = sol_utxo(&keypair, 100);
    let mut split_tx = Transaction::new(
        keypair.shielded_address().unwrap(),
        vec![SpendUtxo::from_keypair(input, &keypair)],
        Address::default(),
    );
    split_tx.split(SOL_MINT, 2, 50).unwrap();
    let err = match split_tx.send(&recipient.shielded_address().unwrap(), SOL_MINT, 10) {
        Ok(_) => panic!("send after split must error"),
        Err(err) => err,
    };
    assert_eq!(err, TransactionError::SplitWithOtherActions);
}

#[test]
fn split_even_into_four_recovers_four_self_owned_notes() {
    let (wallet, signed) = build_and_recover(4, 100);
    // Emitted shape is {1, 8}: 4 real notes + 4 padding dummies.
    assert_shape_and_bundle(&signed, 4);

    let balance = sol_balance(&wallet);
    assert_eq!(balance.amount, 400);
    assert_eq!(balance.utxos.len(), 4, "four self-owned notes recovered");
    for utxo in &balance.utxos {
        assert_eq!(utxo.amount, 100);
        assert_eq!(utxo.owner, wallet.keypair.signing_pubkey());
        assert_eq!(utxo.asset, SOL_MINT);
    }
    // Distinct blindings => distinct commitments => independently spendable.
    let mut blindings: Vec<_> = balance.utxos.iter().map(|u| u.blinding).collect();
    blindings.sort();
    blindings.dedup();
    assert_eq!(blindings.len(), 4);

    // The original input note is retired.
    let input_spent = wallet
        .utxos
        .iter()
        .find(|w| w.utxo.blinding == [9u8; 31])
        .expect("seeded input note");
    assert!(input_spent.spent, "split input must be marked spent");

    let split = wallet
        .private_transactions()
        .iter()
        .find(|tx| tx.kind == PrivateTransactionKind::Split)
        .expect("split history row");
    assert_eq!(split.direction, PrivateTransactionDirection::SelfTransfer);
    assert_eq!(split.asset, SOL_MINT);
    assert_eq!(split.amount, 400);
}

#[test]
fn split_into_max_eight_recovers_all() {
    // N == 8 fills the shape with no dummy padding: exactly one ciphertext.
    let (wallet, signed) = build_and_recover(8, 10);
    assert_shape_and_bundle(&signed, 8);
    assert_eq!(
        signed.external_data.output_ciphertexts.len(),
        1,
        "a full 8-way split needs no dummy ciphertexts"
    );
    let balance = sol_balance(&wallet);
    assert_eq!(balance.utxos.len(), 8);
    assert_eq!(balance.amount, 80);
    for utxo in &balance.utxos {
        assert_eq!(utxo.amount, 10);
    }
}

/// Every N in 2..=8 must emit the {1, 8} shape (so the on-chain verifier finds a
/// key) and round-trip to exactly N spendable self-owned notes — the padding
/// outputs must NOT decode as notes.
#[test]
fn every_split_arity_emits_1x8_shape_and_recovers_n_notes() {
    for num_outputs in 2u8..=8 {
        let per_output_amount = 10u64;
        let (wallet, signed) = build_and_recover(num_outputs, per_output_amount);

        // Emitted shape drives on-chain VK selection: always {1, 8}.
        assert_eq!(
            signed.inputs.len(),
            1,
            "N={num_outputs}: one input for the {{1, 8}} key"
        );
        assert_eq!(
            signed.external_data.output_utxo_hashes.len(),
            8,
            "N={num_outputs}: emitted output count must be 8, not {num_outputs}"
        );

        // Round-trip recovers exactly N spendable notes; the (8 - N) padding
        // commitments are commitment-only dummies and never become notes.
        let balance = sol_balance(&wallet);
        assert_eq!(
            balance.utxos.len(),
            usize::from(num_outputs),
            "N={num_outputs}: padding outputs must not decode as spendable notes"
        );
        assert_eq!(balance.amount, per_output_amount * u64::from(num_outputs));
        for utxo in &balance.utxos {
            assert_eq!(utxo.amount, per_output_amount);
            assert_eq!(utxo.owner, wallet.keypair.signing_pubkey());
        }
    }
}

#[test]
fn recovered_note_hashes_are_a_subset_of_committed_outputs() {
    // The N real self-owned notes the decode side reconstructs must each match
    // a committed output hash; the extra padding commitments have no matching
    // recovered note.
    let (wallet, signed) = build_and_recover(3, 30);
    let nullifier_pk = wallet.keypair.nullifier_key.pubkey().unwrap();
    let recovered_hashes: Vec<[u8; 32]> = wallet
        .utxos
        .iter()
        .filter(|w| !w.spent)
        .map(|w| w.utxo.hash(&nullifier_pk, &[0u8; 32], &[0u8; 32]).unwrap())
        .collect();
    assert_eq!(recovered_hashes.len(), 3);
    let committed = &signed.external_data.output_utxo_hashes;
    assert_eq!(committed.len(), 8);
    for hash in &recovered_hashes {
        assert!(
            committed.contains(hash),
            "recovered note hash {hash:?} is not a committed output"
        );
    }
    // Exactly 3 of the 8 committed outputs correspond to recovered notes; the
    // other 5 are padding dummies.
    let matched = committed
        .iter()
        .filter(|h| recovered_hashes.contains(h))
        .count();
    assert_eq!(matched, 3, "only the real notes match recovered hashes");
}

#[test]
fn split_asset_id_is_sol() {
    let (_, signed) = build_and_recover(3, 20);
    // 3 real + 5 padding => 1 bundle + 5 dummy ciphertexts.
    assert_eq!(signed.external_data.output_ciphertexts.len(), 1 + (8 - 3));
    assert_eq!(SOL_ASSET_ID, 1, "SOL uses reserved asset id 1");
}

#[test]
fn split_rejects_value_mismatch() {
    // num_outputs * per_output_amount must equal the selected input balance.
    let keypair = ShieldedKeypair::new().unwrap();
    let input = sol_utxo(&keypair, 100);
    let mut tx = Transaction::new(
        keypair.shielded_address().unwrap(),
        vec![SpendUtxo::from_keypair(input, &keypair)],
        Address::default(),
    );
    // 3 * 40 = 120 != 100
    tx.split(SOL_MINT, 3, 40).unwrap();
    let err = match tx.sign(&keypair, &AssetRegistry::default()) {
        Ok(_) => panic!("value mismatch must be rejected"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            TransactionError::SplitAmountMismatch {
                requested: 120,
                available: 100
            }
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn split_rejects_more_than_eight_outputs() {
    let keypair = ShieldedKeypair::new().unwrap();
    let input = sol_utxo(&keypair, 90);
    let mut tx = Transaction::new(
        keypair.shielded_address().unwrap(),
        vec![SpendUtxo::from_keypair(input, &keypair)],
        Address::default(),
    );
    tx.split(SOL_MINT, 9, 10).unwrap();
    let err = match tx.sign(&keypair, &AssetRegistry::default()) {
        Ok(_) => panic!("split into more than eight outputs must be rejected"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            TransactionError::UnsupportedShape { n_in: 1, n_out: 9 }
        ),
        "unexpected error: {err:?}"
    );
}
