use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{
    instructions::{
        transact::{
            OutputContext, OutputSlot, OutputUtxo, ShieldedTransaction, SignedTransaction,
            Transaction, WithdrawalTarget,
        },
        types::SpendUtxo,
    },
    wallet::{PrivateTransactionKind, Wallet, WalletUtxo},
    Address, AssetRegistry, Data, TransactionError, Utxo, SOL_MINT,
};

fn sol_utxo(keypair: &ShieldedKeypair, amount: u64, blinding: [u8; 31]) -> Utxo {
    Utxo {
        owner: keypair.signing_pubkey(),
        asset: SOL_MINT,
        amount,
        blinding,
        zone_program_id: None,
        data: Data::default(),
    }
}

fn transaction(keypair: &ShieldedKeypair, inputs: Vec<Utxo>) -> Transaction {
    Transaction::new(
        keypair.shielded_address().unwrap(),
        inputs
            .into_iter()
            .map(|utxo| SpendUtxo::from_keypair(utxo, keypair))
            .collect(),
        Address::default(),
    )
}

fn to_shielded_transaction(signed: &SignedTransaction) -> ShieldedTransaction {
    let external = &signed.external_data;
    let bundle = external.output_ciphertexts.first().expect("split bundle");
    let output_slots = external
        .output_utxo_hashes
        .iter()
        .enumerate()
        .map(|(index, hash)| OutputSlot {
            view_tag: if index == 0 {
                bundle.view_tag
            } else {
                [0u8; 32]
            },
            output_context: OutputContext {
                hash: *hash,
                tree: Address::default(),
                leaf_index: index as u64,
            },
            payload: if index == 0 {
                bundle.data.clone()
            } else {
                Vec::new()
            },
        })
        .collect();
    ShieldedTransaction {
        slot: 0,
        tx_signature: solana_signature::Signature::default(),
        tx_viewing_pk: Some(
            zolana_keypair::P256Pubkey::from_bytes(external.tx_viewing_pk).unwrap(),
        ),
        salt: Some(external.salt),
        output_slots,
        nullifiers: signed
            .input_commitments()
            .unwrap()
            .into_iter()
            .map(|commitment| commitment.nullifier)
            .collect(),
        proofless: false,
    }
}

fn wallet_holding(keypair: ShieldedKeypair, input: &Utxo) -> Wallet {
    let mut wallet = Wallet::new(keypair, AssetRegistry::default()).unwrap();
    let nullifier_pk = wallet.keypair.nullifier_key.pubkey().unwrap();
    let hash = input.hash(&nullifier_pk, &[0u8; 32], &[0u8; 32]).unwrap();
    wallet.utxos.push(WalletUtxo {
        utxo: input.clone(),
        output_context: OutputContext {
            hash,
            tree: Address::default(),
            leaf_index: 0,
        },
        nullifier: input
            .nullifier(&hash, &wallet.keypair.nullifier_key)
            .unwrap(),
        spent: false,
    });
    wallet
}

fn build_and_recover(num_outputs: u8, per_output_amount: u64) -> (Wallet, SignedTransaction) {
    let keypair = ShieldedKeypair::new().unwrap();
    let input = sol_utxo(
        &keypair,
        u64::from(num_outputs) * per_output_amount,
        [9u8; 31],
    );
    let mut tx = transaction(&keypair, vec![input.clone()]);
    tx.split(SOL_MINT, num_outputs, per_output_amount).unwrap();
    let signed = tx.sign(&keypair, &AssetRegistry::default()).unwrap();

    assert_eq!(signed.shape.n_inputs, 1);
    assert_eq!(signed.shape.n_outputs, 8);
    assert_eq!(signed.external_data.output_utxo_hashes.len(), 8);
    assert_eq!(
        signed.external_data.output_ciphertexts.len(),
        1,
        "N={num_outputs}: a split always emits one bundle"
    );
    let bundle_tag = signed.external_data.output_ciphertexts[0].view_tag;
    for output in signed.outputs.iter().skip(usize::from(num_outputs)) {
        assert_eq!(output.owner_tag, Some(bundle_tag));
    }

    let mut wallet = wallet_holding(keypair, &input);
    let report = wallet
        .sync(&[to_shielded_transaction(&signed)], 1_700_000_000, 8)
        .unwrap();
    assert_eq!(report.unparsed_transactions, 0);
    (wallet, signed)
}

#[test]
fn every_split_arity_round_trips_with_one_packet_safe_bundle() {
    for num_outputs in 2u8..=8 {
        let (wallet, signed) = build_and_recover(num_outputs, 10);
        let balance = wallet
            .balances(false)
            .unwrap()
            .into_iter()
            .find(|balance| balance.mint == SOL_MINT)
            .expect("SOL balance");
        assert_eq!(balance.amount, u64::from(num_outputs) * 10);
        assert_eq!(balance.utxos.len(), usize::from(num_outputs));
        assert!(balance.utxos.iter().all(|utxo| utxo.amount == 10));
        assert!(wallet
            .private_transactions()
            .iter()
            .any(|tx| tx.kind == PrivateTransactionKind::Split));

        let nullifier_pk = wallet.keypair.nullifier_key.pubkey().unwrap();
        for utxo in &balance.utxos {
            let hash = utxo.hash(&nullifier_pk, &[0u8; 32], &[0u8; 32]).unwrap();
            assert!(signed.external_data.output_utxo_hashes.contains(&hash));
        }
    }
}

#[test]
fn split_rejects_every_out_of_range_arity_at_configuration() {
    let keypair = ShieldedKeypair::new().unwrap();
    for parts in [0, 1, 9] {
        let mut tx = transaction(&keypair, vec![sol_utxo(&keypair, 90, [parts; 31])]);
        let err = tx
            .split(SOL_MINT, parts, 10)
            .err()
            .expect("invalid split arity");
        assert_eq!(err, TransactionError::InvalidSplitOutputCount(parts));
    }
}

#[test]
fn split_is_mutually_exclusive_with_other_actions() {
    let keypair = ShieldedKeypair::new().unwrap();
    let recipient = ShieldedKeypair::new().unwrap();

    let mut sent = transaction(&keypair, vec![sol_utxo(&keypair, 100, [1u8; 31])]);
    sent.send(&recipient.shielded_address().unwrap(), SOL_MINT, 10)
        .unwrap();
    assert_eq!(
        sent.split(SOL_MINT, 2, 50).err().unwrap(),
        TransactionError::SplitWithOtherActions
    );

    let mut withdrawn = transaction(&keypair, vec![sol_utxo(&keypair, 100, [2u8; 31])]);
    withdrawn
        .withdraw(
            SOL_MINT,
            10,
            WithdrawalTarget::Sol {
                user_sol_account: Address::default(),
            },
        )
        .unwrap();
    assert_eq!(
        withdrawn.split(SOL_MINT, 2, 50).err().unwrap(),
        TransactionError::SplitWithOtherActions
    );

    let mut split = transaction(&keypair, vec![sol_utxo(&keypair, 100, [3u8; 31])]);
    split.split(SOL_MINT, 2, 50).unwrap();
    assert_eq!(
        split
            .add_output(OutputUtxo {
                owner_address: Some(recipient.shielded_address().unwrap()),
                amount: 1,
                ..Default::default()
            })
            .err()
            .unwrap(),
        TransactionError::SplitWithOtherActions
    );
}

#[test]
fn split_rejects_value_input_and_asset_mismatches() {
    let keypair = ShieldedKeypair::new().unwrap();
    let assets = AssetRegistry::default();

    let mut value = transaction(&keypair, vec![sol_utxo(&keypair, 100, [4u8; 31])]);
    value.split(SOL_MINT, 3, 40).unwrap();
    assert_eq!(
        value.prepare_split(&assets).err().unwrap(),
        TransactionError::SplitAmountMismatch {
            requested: 120,
            available: 100,
        }
    );

    let mut multiple = transaction(
        &keypair,
        vec![
            sol_utxo(&keypair, 50, [5u8; 31]),
            sol_utxo(&keypair, 50, [6u8; 31]),
        ],
    );
    multiple.split(SOL_MINT, 2, 50).unwrap();
    assert_eq!(
        multiple.prepare_split(&assets).err().unwrap(),
        TransactionError::SplitInputCount(2)
    );

    let requested = Address::new_from_array([7u8; 32]);
    let mut asset = transaction(&keypair, vec![sol_utxo(&keypair, 100, [7u8; 31])]);
    asset.split(requested, 2, 50).unwrap();
    assert_eq!(
        asset.prepare_split(&assets).err().unwrap(),
        TransactionError::SplitAssetMismatch {
            input: SOL_MINT,
            requested,
        }
    );
}
