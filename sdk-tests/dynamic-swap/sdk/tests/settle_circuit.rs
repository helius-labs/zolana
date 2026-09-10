use dynamic_swap_program::instructions::{
    settle::SettlePublicInput,
    verifier::{verify_groth16, CompressedGroth16Proof},
};
use dynamic_swap_prover::EscrowSettleProofInputs;
use dynamic_swap_sdk::{
    instructions::settle::{settle_blinding_seed, SettleProofInputParams},
    state::EscrowTerms,
};
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{
    instructions::{
        transact::{assign_output_blindings, PrivateTxHash, SppProofOutputUtxo},
        types::SppProofInputUtxo,
    },
    utxo::{
        derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
    },
    Address, Data, Utxo, SOL_MINT,
};

const INPUT_TREE_ID: u16 = 3;
const OUTPUT_TREE_ID: u16 = 7;

fn fe(value: u8) -> [u8; 32] {
    let mut out = [0; 32];
    out[31] = value;
    out
}

fn sample_params(execution_price: u64) -> SettleProofInputParams {
    let operator = ShieldedKeypair::new_ed25519().unwrap();
    let recipient = ShieldedKeypair::new_ed25519()
        .unwrap()
        .shielded_address()
        .unwrap();
    let authority = operator.shielded_address().unwrap();
    let source_asset = Address::new_from_array([1; 32]);
    let order_amount = 10;
    let max_price = 5;
    let created_at = 123;
    let terms = EscrowTerms {
        recipient_owner_hash: recipient.owner_hash().unwrap(),
        max_price,
    };
    let order_in = SppProofInputUtxo::new(
        Utxo {
            owner: operator.signing_pubkey(),
            asset: source_asset,
            amount: order_amount,
            blinding: fe(7),
            ring_program_id: None,
            data: Data::default(),
        },
        &operator,
    )
    .in_tree(INPUT_TREE_ID)
    .with_data_hash(terms.data_hash(created_at).unwrap());
    let escrow_utxo_hash = order_in.hash().unwrap();
    let reservation_in = SppProofInputUtxo::new(
        Utxo {
            owner: operator.signing_pubkey(),
            asset: SOL_MINT,
            amount: order_amount * max_price,
            blinding: fe(13),
            ring_program_id: None,
            data: Data::default(),
        },
        &operator,
    )
    .in_tree(INPUT_TREE_ID)
    .with_data_hash(escrow_utxo_hash);
    let reservation_utxo_hash = reservation_in.hash().unwrap();
    let is_settle = execution_price <= max_price;
    let owed = if is_settle {
        order_amount * execution_price
    } else {
        0
    };
    let mut outputs = [
        SppProofOutputUtxo::new(
            if is_settle { SOL_MINT } else { source_asset },
            if is_settle { owed } else { order_amount },
            recipient,
        )
        .unwrap(),
        SppProofOutputUtxo::new(SOL_MINT, order_amount * max_price - owed, authority).unwrap(),
        SppProofOutputUtxo::new(
            source_asset,
            if is_settle { order_amount } else { 0 },
            authority,
        )
        .unwrap(),
    ];
    let first_nullifier = order_in.nullifier().unwrap();
    let blinding_seed =
        settle_blinding_seed(&order_in.utxo.blinding, &reservation_in.utxo.blinding).unwrap();
    let seed = derive_output_blinding_seed(&first_nullifier, &blinding_seed).unwrap();
    assign_output_blindings(&mut outputs, &first_nullifier, &seed).unwrap();
    let [recipient_out, maker_counter, maker_source] = outputs;
    SettleProofInputParams {
        order_in,
        reservation_in,
        recipient_out,
        maker_counter,
        maker_source,
        execution_price,
        max_price,
        created_at,
        order_amount,
        escrow_utxo_hash,
        reservation_utxo_hash,
        recipient_owner_hash: terms.recipient_owner_hash,
        authority_owner_hash: authority.owner_hash().unwrap(),
        external_data_hash: fe(8),
        private_tx_blinding: derive_private_tx_blinding(&first_nullifier, &blinding_seed).unwrap(),
        output_tree_id: OUTPUT_TREE_ID,
    }
}

fn public_hash(inputs: &EscrowSettleProofInputs) -> [u8; 32] {
    SettlePublicInput {
        private_tx_hash: &inputs.private_tx_hash,
        execution_price: inputs.execution_price,
        order_in_hash: &inputs.order_in_hash,
        reservation_in_hash: &inputs.reservation_in_hash,
        authority_owner_hash: &inputs.authority_owner_hash,
        first_nullifier: &inputs.first_nullifier,
    }
    .hash()
    .unwrap()
}

// Keep transcript hashes consistent so attacks exercise the recovery checks.
fn refresh_hashes(inputs: &mut EscrowSettleProofInputs) {
    inputs.private_tx_hash = PrivateTxHash::new(
        &[
            inputs.order_in.hash().unwrap(),
            inputs.reservation_in.hash().unwrap(),
        ],
        &[
            inputs.recipient_out.hash().unwrap(),
            inputs.maker_counter.hash().unwrap(),
            inputs.maker_source.hash().unwrap(),
        ],
        &inputs.external_data_hash,
        &inputs.private_tx_blinding,
    )
    .hash()
    .unwrap();
    inputs.public_input_hash = public_hash(inputs);
}

#[test]
fn settle_and_refund_prove_and_recover_without_ciphertext() {
    for price in [3, 7] {
        let params = sample_params(price);
        let inputs = params.to_proof_inputs().unwrap();
        let proof = inputs.prove().expect("prove settlement outcome");
        verify_groth16(
            CompressedGroth16Proof {
                a: &proof.proof_a,
                b: &proof.proof_b,
                c: &proof.proof_c,
                commitment: None,
            },
            inputs.public_input_hash,
            &dynamic_swap_program::verifying_keys::escrow_settle::VERIFYINGKEY,
        )
        .expect("settlement must verify against the program key");

        // The creator retained these two openings. The only settlement datum
        // needed for recovery is its first published nullifier.
        let blinding_seed = settle_blinding_seed(
            &params.order_in.utxo.blinding,
            &params.reservation_in.utxo.blinding,
        )
        .unwrap();
        let seed = derive_output_blinding_seed(&inputs.first_nullifier, &blinding_seed).unwrap();
        for (index, output) in [
            &inputs.recipient_out,
            &inputs.maker_counter,
            &inputs.maker_source,
        ]
        .into_iter()
        .enumerate()
        {
            let mut recovered = output.clone();
            recovered.blinding =
                derive_transact_output_blinding(&inputs.first_nullifier, &seed, index as u32)
                    .unwrap();
            assert_eq!(recovered.hash().unwrap(), output.hash().unwrap());
        }

        let mut forged = inputs.clone();
        forged.first_nullifier = fe(17);
        assert!(verify_groth16(
            CompressedGroth16Proof {
                a: &proof.proof_a,
                b: &proof.proof_b,
                c: &proof.proof_c,
                commitment: None,
            },
            public_hash(&forged),
            &dynamic_swap_program::verifying_keys::escrow_settle::VERIFYINGKEY
        )
        .is_err());
    }
}

#[test]
fn settle_rejects_unrecoverable_outputs_and_operator_selected_blinding_seed() {
    for price in [3, 7] {
        let good = sample_params(price).to_proof_inputs().unwrap();
        good.prove().expect("positive control");
        for attack in 0..5 {
            let mut inputs = good.clone();
            match attack {
                0 => inputs.recipient_out.blinding = fe(29),
                1 => inputs.maker_counter.blinding = fe(29),
                2 => inputs.maker_source.blinding = fe(29),
                3 => inputs.private_tx_blinding = fe(29),
                _ => {
                    let blinding_seed = fe(29);
                    let seed = derive_output_blinding_seed(&inputs.first_nullifier, &blinding_seed)
                        .unwrap();
                    inputs.private_tx_blinding =
                        derive_private_tx_blinding(&inputs.first_nullifier, &blinding_seed)
                            .unwrap();
                    for (index, output) in [
                        &mut inputs.recipient_out,
                        &mut inputs.maker_counter,
                        &mut inputs.maker_source,
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        output.blinding = derive_transact_output_blinding(
                            &inputs.first_nullifier,
                            &seed,
                            index as u32,
                        )
                        .unwrap();
                    }
                }
            }
            refresh_hashes(&mut inputs);
            assert!(
                inputs.prove().is_err(),
                "accepted recovery attack {attack} at price {price}"
            );
        }
    }
}

#[test]
fn sdk_rejects_unrecoverable_settlement() {
    let mut params = sample_params(3);
    params.recipient_out.blinding = fe(29);
    assert!(params
        .to_proof_inputs()
        .unwrap_err()
        .to_string()
        .contains("output 0 blinding"));
    let mut params = sample_params(7);
    params.private_tx_blinding = fe(29);
    assert!(params
        .to_proof_inputs()
        .unwrap_err()
        .to_string()
        .contains("blinding seed"));
}
