use dynamic_swap_program::{
    circuits::{EscrowCancel, EscrowCancelPrivateInputs, PoolSettle, PoolSettlePrivateInputs},
    instructions::shared::u64_right_align,
    verifier::{escrow_cancel, pool_settle},
};
use dynamic_swap_sdk::{
    instructions::{
        cancel::CancelProofInputParams,
        settle::{cancel_blinding_seed, settle_blinding_seed, SettleProofInputParams},
    },
    shared::transaction_blindings,
    state::{order_data_hash, PoolUtxo},
};
use std::sync::OnceLock;
use zolana_keypair::ShieldedKeypair;
use zolana_program::{CompressedProof, Groth16Prover, SolanaProof, ZkCircuit};
use zolana_transaction::{
    instructions::transact::{asset_field, PrivateTxHash, SppProofOutputUtxo},
    utxo::{
        derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
        SppProofInputUtxo,
    },
    Address, Data, Mint, Utxo,
};

const INPUT_TREE_ID: u16 = 3;
const OUTPUT_TREE_ID: u16 = 7;
const ORDER_AMOUNT: u64 = 10;
const MIN_PRICE: u64 = 5;
const POOL_AMOUNT: u64 = 1_000;
const POOL_BOOKED: u64 = 900;
const MAX_ORDER_SIZE: u64 = 100;
/// Below MIN_PRICE (refund) and at or above it (fill).
const PRICES: [u64; 2] = [3, 7];

fn fe(value: u8) -> [u8; 32] {
    let mut out = [0; 32];
    out[31] = value;
    out
}

fn source() -> Mint {
    Mint::new(Address::new_from_array([1; 32]), 2)
}

fn destination() -> Mint {
    Mint::new(Address::new_from_array([2; 32]), 3)
}

fn spend(
    owner: &ShieldedKeypair,
    asset: Mint,
    amount: u64,
    blinding: u8,
    leaf_index: u64,
    data_hash: [u8; 32],
) -> SppProofInputUtxo {
    zolana_test_utils::utxo::wallet(
        Utxo {
            owner: owner.signing_pubkey(),
            asset,
            amount,
            blinding: fe(blinding),
            ring_program_id: None,
            data: Data::default(),
        },
        &owner.nullifier_key,
        INPUT_TREE_ID,
        leaf_index,
        Some(data_hash),
        None,
    )
    .unwrap()
    .into()
}

fn order_in(recipient_owner_hash: &[u8; 32]) -> SppProofInputUtxo {
    spend(
        &ShieldedKeypair::new_ed25519().unwrap(),
        source(),
        ORDER_AMOUNT,
        7,
        0,
        order_data_hash(recipient_owner_hash, MIN_PRICE).unwrap(),
    )
}

fn verify_settle(proof: &SolanaProof, public_input_hash: [u8; 32]) -> bool {
    zolana_program::verifier::verify_groth16(
        &CompressedProof::try_from(proof).unwrap(),
        public_input_hash,
        &pool_settle::VERIFYINGKEY,
    )
    .is_ok()
}

fn verify_cancel(proof: &SolanaProof, public_input_hash: [u8; 32]) -> bool {
    zolana_program::verifier::verify_groth16(
        &CompressedProof::try_from(proof).unwrap(),
        public_input_hash,
        &escrow_cancel::VERIFYINGKEY,
    )
    .is_ok()
}

fn sample_settle(execution_price: u64) -> SettleProofInputParams {
    let taker = ShieldedKeypair::new_ed25519()
        .unwrap()
        .shielded_address()
        .unwrap();
    let pool = ShieldedKeypair::new_ed25519().unwrap();
    let pool_address = pool.shielded_address().unwrap();
    let maker = ShieldedKeypair::new_ed25519()
        .unwrap()
        .shielded_address()
        .unwrap();
    let recipient_owner_hash = taker.owner_hash().unwrap();
    let order_in = order_in(&recipient_owner_hash);
    let order_utxo_hash = order_in.hash();
    let pool_in = spend(
        &pool,
        destination(),
        POOL_AMOUNT,
        13,
        1,
        u64_right_align(POOL_BOOKED),
    );
    let fills = execution_price >= MIN_PRICE;
    let owed = ORDER_AMOUNT * execution_price;
    let settled = if fills { owed } else { 0 };
    let first_nullifier = order_in.nullifier();
    let blinding_seed = settle_blinding_seed(&order_in.utxo.blinding).unwrap();
    let (private_tx_blinding, blindings) =
        transaction_blindings(&first_nullifier, &blinding_seed, 3).unwrap();
    let [recipient_blinding, change_blinding, receipt_blinding]: [_; 3] =
        blindings.try_into().unwrap();
    let mut recipient_out = SppProofOutputUtxo::new(
        if fills { destination() } else { source() },
        if fills { owed } else { ORDER_AMOUNT },
        taker,
    )
    .unwrap();
    recipient_out.blinding = recipient_blinding;
    let pool_change = PoolUtxo {
        asset: destination(),
        amount: POOL_AMOUNT - settled,
        booked: POOL_BOOKED.saturating_sub(MAX_ORDER_SIZE),
        blinding: change_blinding,
    }
    .output_utxo(&pool_address)
    .unwrap();
    let mut maker_receipt =
        SppProofOutputUtxo::new(source(), if fills { ORDER_AMOUNT } else { 0 }, maker).unwrap();
    maker_receipt.blinding = receipt_blinding;
    SettleProofInputParams {
        order_in,
        pool_in,
        pool_booked_in: POOL_BOOKED,
        recipient_out,
        pool_change,
        maker_receipt,
        execution_price,
        order_amount: ORDER_AMOUNT,
        recipient_owner_hash,
        min_price: MIN_PRICE,
        order_utxo_hash,
        destination_asset: asset_field(&destination().asset).unwrap(),
        pool_authority_owner_hash: pool_address.owner_hash().unwrap(),
        max_order_size: MAX_ORDER_SIZE,
        receipt_owner_hash: maker.owner_hash().unwrap(),
        private_tx_blinding,
        output_tree_id: OUTPUT_TREE_ID,
    }
}

fn sample_cancel() -> CancelProofInputParams {
    let taker = ShieldedKeypair::new_ed25519()
        .unwrap()
        .shielded_address()
        .unwrap();
    let recipient_owner_hash = taker.owner_hash().unwrap();
    let order_in = order_in(&recipient_owner_hash);
    let order_utxo_hash = order_in.hash();
    let first_nullifier = order_in.nullifier();
    let blinding_seed = cancel_blinding_seed(&order_in.utxo.blinding).unwrap();
    let (private_tx_blinding, blindings) =
        transaction_blindings(&first_nullifier, &blinding_seed, 1).unwrap();
    let mut refund_out = SppProofOutputUtxo::new(source(), ORDER_AMOUNT, taker).unwrap();
    refund_out.blinding = blindings.into_iter().next().unwrap();
    CancelProofInputParams {
        order_in,
        refund_out,
        order_amount: ORDER_AMOUNT,
        recipient_owner_hash,
        min_price: MIN_PRICE,
        order_utxo_hash,
        private_tx_blinding,
        output_tree_id: OUTPUT_TREE_ID,
    }
}

fn settle_public_hash(inputs: &PoolSettle) -> [u8; 32] {
    pool_settle::PublicInputs {
        execution_price: inputs.public.execution_price,
        order_in_hash: inputs.public.order_in_hash,
        destination_asset: inputs.public.destination_asset,
        pool_authority_owner_hash: inputs.public.pool_authority_owner_hash,
        max_order_size: inputs.public.max_order_size,
        receipt_owner_hash: inputs.public.receipt_owner_hash,
        first_nullifier: inputs.public.first_nullifier,
    }
    .hash(&inputs.private.private_tx_hash)
    .unwrap()
}

fn cancel_public_hash(inputs: &EscrowCancel) -> [u8; 32] {
    escrow_cancel::PublicInputs {
        order_in_hash: inputs.public.order_in_hash,
        first_nullifier: inputs.public.first_nullifier,
    }
    .hash(&inputs.private.private_tx_hash)
    .unwrap()
}

// Keep transcript hashes consistent so attacks exercise the recovery checks.
fn refresh_settle_hashes(inputs: &mut PoolSettle) {
    inputs.private.private_tx_hash = PrivateTxHash::new(
        &[
            inputs.private.order_in.hash().unwrap(),
            inputs.private.pool_in.hash().unwrap(),
        ],
        &[
            inputs.private.recipient_out.hash().unwrap(),
            inputs.private.pool_change.hash().unwrap(),
            inputs.private.maker_receipt.hash().unwrap(),
        ],
        &inputs.private.private_tx_blinding,
    )
    .hash()
    .unwrap();
}

fn refresh_cancel_hashes(inputs: &mut EscrowCancel) {
    inputs.private.private_tx_hash = PrivateTxHash::new(
        &[inputs.private.order_in.hash().unwrap()],
        &[inputs.private.refund_out.hash().unwrap()],
        &inputs.private.private_tx_blinding,
    )
    .hash()
    .unwrap();
}

/// Replace the private transaction blinding and `outputs` blindings with the
/// ones a prover-chosen `blinding_seed` derives.
fn reseed(
    first_nullifier: &[u8; 32],
    blinding_seed: &[u8; 32],
    private_tx_blinding: &mut [u8; 32],
    outputs: Vec<&mut [u8; 32]>,
) {
    let seed = derive_output_blinding_seed(first_nullifier, blinding_seed).unwrap();
    *private_tx_blinding = derive_private_tx_blinding(first_nullifier, blinding_seed).unwrap();
    for (index, blinding) in outputs.into_iter().enumerate() {
        *blinding = derive_transact_output_blinding(first_nullifier, &seed, index as u32).unwrap();
    }
}

#[test]
fn settle_and_refund_prove_and_recover_without_ciphertext() {
    for price in PRICES {
        let params = sample_settle(price);
        let inputs = params.to_proof_inputs().unwrap();
        static PROVER: OnceLock<Groth16Prover<PoolSettle>> = OnceLock::new();
        let prover = PROVER.get_or_init(|| Groth16Prover::new_with_test_setup().unwrap());
        let proof = prover
            .prove(&inputs)
            .expect("prove settlement outcome")
            .proof;
        assert!(
            verify_settle(&proof, settle_public_hash(&inputs)),
            "settlement must verify against the program key"
        );

        // The taker holds the order opening. The only settlement datum it
        // needs for recovery is the first published nullifier.
        let blinding_seed = settle_blinding_seed(&params.order_in.utxo.blinding).unwrap();
        let seed =
            derive_output_blinding_seed(&inputs.public.first_nullifier, &blinding_seed).unwrap();
        let mut recovered = inputs.private.recipient_out.clone();
        recovered.blinding =
            derive_transact_output_blinding(&inputs.public.first_nullifier, &seed, 0).unwrap();
        assert_eq!(
            recovered.hash().unwrap(),
            inputs.private.recipient_out.hash().unwrap()
        );

        let mut forged = inputs.clone();
        forged.public.first_nullifier = fe(17);
        assert!(!verify_settle(&proof, settle_public_hash(&forged)));
    }
}

#[test]
fn settle_rejects_unrecoverable_outputs_and_maker_selected_blinding_seed() {
    for price in PRICES {
        let good = sample_settle(price).to_proof_inputs().unwrap();
        good.check_constraints().expect("positive control");
        for attack in 0..5 {
            let mut inputs = good.clone();
            match attack {
                0 => inputs.private.recipient_out.blinding = fe(29),
                1 => inputs.private.pool_change.blinding = fe(29),
                2 => inputs.private.maker_receipt.blinding = fe(29),
                3 => inputs.private.private_tx_blinding = fe(29),
                _ => {
                    let first_nullifier = inputs.public.first_nullifier;
                    let PoolSettlePrivateInputs {
                        private_tx_blinding,
                        recipient_out,
                        pool_change,
                        maker_receipt,
                        ..
                    } = &mut inputs.private;
                    reseed(
                        &first_nullifier,
                        &fe(29),
                        private_tx_blinding,
                        vec![
                            &mut recipient_out.blinding,
                            &mut pool_change.blinding,
                            &mut maker_receipt.blinding,
                        ],
                    );
                }
            }
            refresh_settle_hashes(&mut inputs);
            assert!(
                inputs.check_constraints().is_err(),
                "accepted recovery attack {attack} at price {price}"
            );
        }
    }
}

#[test]
fn sdk_rejects_unrecoverable_settlement() {
    let mut params = sample_settle(3);
    params.recipient_out.blinding = fe(29);
    assert!(params
        .to_proof_inputs()
        .unwrap_err()
        .to_string()
        .contains("output 0 blinding"));
    let mut params = sample_settle(7);
    params.private_tx_blinding = fe(29);
    assert!(params
        .to_proof_inputs()
        .unwrap_err()
        .to_string()
        .contains("private_tx_blinding"));
}

#[test]
fn cancel_proves_and_recovers_without_ciphertext() {
    let params = sample_cancel();
    let inputs = params.to_proof_inputs().unwrap();
    static PROVER: OnceLock<Groth16Prover<EscrowCancel>> = OnceLock::new();
    let prover = PROVER.get_or_init(|| Groth16Prover::new_with_test_setup().unwrap());
    let proof = prover.prove(&inputs).expect("prove cancel").proof;
    assert!(
        verify_cancel(&proof, cancel_public_hash(&inputs)),
        "cancel must verify against the program key"
    );

    let blinding_seed = cancel_blinding_seed(&params.order_in.utxo.blinding).unwrap();
    let seed = derive_output_blinding_seed(&inputs.public.first_nullifier, &blinding_seed).unwrap();
    let mut recovered = inputs.private.refund_out.clone();
    recovered.blinding =
        derive_transact_output_blinding(&inputs.public.first_nullifier, &seed, 0).unwrap();
    assert_eq!(
        recovered.hash().unwrap(),
        inputs.private.refund_out.hash().unwrap()
    );

    let mut forged = inputs.clone();
    forged.public.first_nullifier = fe(17);
    assert!(!verify_cancel(&proof, cancel_public_hash(&forged)));
}

#[test]
fn cancel_rejects_unrecoverable_refund_and_canceller_selected_blinding_seed() {
    let good = sample_cancel().to_proof_inputs().unwrap();
    good.check_constraints().expect("positive control");
    for attack in 0..3 {
        let mut inputs = good.clone();
        match attack {
            0 => inputs.private.refund_out.blinding = fe(29),
            1 => inputs.private.private_tx_blinding = fe(29),
            _ => {
                let first_nullifier = inputs.public.first_nullifier;
                let EscrowCancelPrivateInputs {
                    private_tx_blinding,
                    refund_out,
                    ..
                } = &mut inputs.private;
                reseed(
                    &first_nullifier,
                    &fe(29),
                    private_tx_blinding,
                    vec![&mut refund_out.blinding],
                );
            }
        }
        refresh_cancel_hashes(&mut inputs);
        assert!(
            inputs.check_constraints().is_err(),
            "accepted recovery attack {attack}"
        );
    }
}

#[test]
fn sdk_rejects_unrecoverable_cancel() {
    let mut params = sample_cancel();
    params.refund_out.blinding = fe(29);
    assert!(params
        .to_proof_inputs()
        .unwrap_err()
        .to_string()
        .contains("refund_out blinding"));
}

#[test]
fn settle_rejects_diverted_outputs_and_incorrect_pool_accounting() {
    for price in PRICES {
        let good = sample_settle(price).to_proof_inputs().unwrap();
        for attack in 0..11 {
            let mut inputs = good.clone();
            match attack {
                0 => inputs.private.recipient_out.owner_hash = fe(29),
                1 => inputs.private.recipient_out.amount = u64_right_align(ORDER_AMOUNT + 1),
                2 => inputs.private.recipient_out.asset = fe(29),
                3 => inputs.private.pool_change.owner_hash = fe(29),
                4 => inputs.private.pool_change.amount = u64_right_align(POOL_AMOUNT + 1),
                5 => inputs.private.pool_change.data_hash = u64_right_align(POOL_BOOKED),
                6 => inputs.private.maker_receipt.owner_hash = fe(29),
                7 => inputs.private.maker_receipt.amount = u64_right_align(ORDER_AMOUNT + 1),
                8 => inputs.private.pool_in.owner_hash = fe(29),
                9 => inputs.private.min_price = MIN_PRICE + 1,
                _ => inputs.public.execution_price = 0,
            }
            refresh_settle_hashes(&mut inputs);
            assert!(
                inputs.check_constraints().is_err(),
                "accepted settlement attack {attack} at price {price}"
            );
        }
    }
}

#[test]
fn cancel_rejects_diverted_refund_or_changed_order_opening() {
    let good = sample_cancel().to_proof_inputs().unwrap();
    for attack in 0..8 {
        let mut inputs = good.clone();
        match attack {
            0 => inputs.private.refund_out.owner_hash = fe(29),
            1 => inputs.private.refund_out.amount = u64_right_align(ORDER_AMOUNT - 1),
            2 => inputs.private.refund_out.asset = fe(29),
            3 => inputs.private.refund_out.data_hash = fe(29),
            4 => inputs.private.order_amount = ORDER_AMOUNT + 1,
            5 => inputs.private.min_price = MIN_PRICE + 1,
            6 => inputs.public.order_in_hash = fe(29),
            _ => inputs.private.refund_out.ring_program_id = fe(29),
        }
        refresh_cancel_hashes(&mut inputs);
        assert!(
            inputs.check_constraints().is_err(),
            "accepted cancel attack {attack}"
        );
    }
}

#[test]
fn settlement_clamps_booked_change_at_the_reservation_boundary() {
    for price in PRICES {
        for booked in [MAX_ORDER_SIZE - 1, MAX_ORDER_SIZE, MAX_ORDER_SIZE + 1] {
            let mut params = sample_settle(price);
            params.pool_booked_in = booked;
            params.pool_in.data_hash = Some(u64_right_align(booked));
            let expected_booked = booked.saturating_sub(MAX_ORDER_SIZE);
            params.pool_change.data_hash = Some(u64_right_align(expected_booked));
            let good = params.to_proof_inputs().unwrap();
            good.check_constraints().unwrap_or_else(|error| {
                panic!("rejected booked={booked} at price={price}: {error}")
            });

            let mut forged = good.clone();
            forged.private.pool_change.data_hash = u64_right_align(expected_booked + 1);
            refresh_settle_hashes(&mut forged);
            let error = forged.check_constraints().unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("the pool change does not consume the full reservation"),
                "unexpected rejection at booked={booked}, price={price}: {error}"
            );
        }
    }
}
