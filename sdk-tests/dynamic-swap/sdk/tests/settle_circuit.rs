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
use spr_keypair::ShieldedKeypair;
use spr_program::{checked, CompressedProof, Field};
use spr_transaction::{
    instructions::transact::{asset_field, SppProofOutputUtxo},
    utxo::{
        derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
        SppProofInputUtxo,
    },
    Address, Data, Mint, Utxo,
};

mod support;
use support::{bytes, check, field, private_tx_hash, prove};

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
    spr_test_utils::utxo::wallet(
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

fn verify_settle(proof: &CompressedProof, public_input_hash: [u8; 32]) -> bool {
    spr_program::verifier::verify_groth16(proof, public_input_hash, &pool_settle::VERIFYINGKEY)
        .is_ok()
}

fn verify_cancel(proof: &CompressedProof, public_input_hash: [u8; 32]) -> bool {
    spr_program::verifier::verify_groth16(proof, public_input_hash, &escrow_cancel::VERIFYINGKEY)
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
        booked: POOL_BOOKED - MAX_ORDER_SIZE,
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
        order_in_hash: bytes(&inputs.public.order_in_hash),
        destination_asset: bytes(&inputs.public.destination_asset),
        pool_authority_owner_hash: bytes(&inputs.public.pool_authority_owner_hash),
        max_order_size: inputs.public.max_order_size,
        receipt_owner_hash: bytes(&inputs.public.receipt_owner_hash),
        first_nullifier: bytes(&inputs.public.first_nullifier),
    }
    .hash(&bytes(&inputs.private.private_tx_hash))
    .unwrap()
}

fn cancel_public_hash(inputs: &EscrowCancel) -> [u8; 32] {
    escrow_cancel::PublicInputs {
        order_in_hash: bytes(&inputs.public.order_in_hash),
        first_nullifier: bytes(&inputs.public.first_nullifier),
    }
    .hash(&bytes(&inputs.private.private_tx_hash))
    .unwrap()
}

fn check_settle(inputs: &PoolSettle) -> bool {
    check("pool_settle", inputs, settle_public_hash(inputs)).is_ok()
}

/// The reservation check: the pool change books `booked_in - max_order_size`.
const RESERVATION_CHECK: (&str, &[&str]) = (
    "execute → require_eq",
    &[
        "program.private.pool_change.data_hash",
        "program.public.max_order_size",
    ],
);
/// The u64 range check on the pool change's booked total.
const BOOKED_RANGE_CHECK: (&str, &[&str]) = (
    "execute → require_u64 → to_bits",
    &["program.private.pool_change.data_hash"],
);

/// Whether the compiled circuit refuses `inputs` at `site`, naming each input
/// the failing check reads. Names are matched one by one: on a terminal Xark
/// colours each name separately.
fn refused_at(inputs: &PoolSettle, (site, names): (&str, &[&str])) -> Result<(), String> {
    let error = check("pool_settle", inputs, settle_public_hash(inputs))
        .expect_err("the compiled settlement must refuse these inputs")
        .to_string();
    if error.contains(site) && names.iter().all(|name| error.contains(name)) {
        Ok(())
    } else {
        Err(error)
    }
}

fn check_cancel(inputs: &EscrowCancel) -> bool {
    check("escrow_cancel", inputs, cancel_public_hash(inputs)).is_ok()
}

// Keep transcript hashes consistent so attacks exercise the recovery checks.
fn refresh_settle_hashes(inputs: &mut PoolSettle) {
    let private = &mut inputs.private;
    private.private_tx_hash = private_tx_hash(
        &[
            private.order_in.hash().unwrap(),
            private.pool_in.hash().unwrap(),
        ],
        &[
            private.recipient_out.hash().unwrap(),
            private.pool_change.hash().unwrap(),
            private.maker_receipt.hash().unwrap(),
        ],
        &private.private_tx_blinding,
    );
}

fn refresh_cancel_hashes(inputs: &mut EscrowCancel) {
    let private = &mut inputs.private;
    private.private_tx_hash = private_tx_hash(
        &[private.order_in.hash().unwrap()],
        &[private.refund_out.hash().unwrap()],
        &private.private_tx_blinding,
    );
}

/// Replace the private transaction blinding and `outputs` blindings with the
/// ones a prover-chosen `blinding_seed` derives.
fn reseed(
    first_nullifier: &Field,
    blinding_seed: &[u8; 32],
    private_tx_blinding: &mut Field,
    outputs: Vec<&mut Field>,
) {
    let first_nullifier = bytes(first_nullifier);
    let seed = derive_output_blinding_seed(&first_nullifier, blinding_seed).unwrap();
    *private_tx_blinding =
        field(&derive_private_tx_blinding(&first_nullifier, blinding_seed).unwrap());
    for (index, blinding) in (0u32..).zip(outputs) {
        *blinding =
            field(&derive_transact_output_blinding(&first_nullifier, &seed, index).unwrap());
    }
}

#[test]
fn settle_and_refund_prove_and_recover_without_ciphertext() {
    for price in PRICES {
        let params = sample_settle(price);
        let inputs = params.to_proof_inputs().unwrap();
        let native = checked(|| inputs.execute()).expect("valid settlement");
        assert_eq!(bytes(native.public_hash()), settle_public_hash(&inputs));
        let proof = prove("pool_settle", &inputs, settle_public_hash(&inputs));
        assert!(
            verify_settle(&proof, settle_public_hash(&inputs)),
            "settlement must verify against the program key"
        );

        // The taker holds the order opening. The only settlement datum it
        // needs for recovery is the first published nullifier.
        let first_nullifier = bytes(&inputs.public.first_nullifier);
        let blinding_seed = settle_blinding_seed(&params.order_in.utxo.blinding).unwrap();
        let seed = derive_output_blinding_seed(&first_nullifier, &blinding_seed).unwrap();
        let mut recovered = inputs.private.recipient_out;
        recovered.blinding =
            field(&derive_transact_output_blinding(&first_nullifier, &seed, 0).unwrap());
        assert_eq!(
            bytes(&recovered.hash().unwrap()),
            bytes(&inputs.private.recipient_out.hash().unwrap())
        );

        let mut forged = inputs;
        forged.public.first_nullifier = field(&fe(17));
        assert!(!verify_settle(&proof, settle_public_hash(&forged)));
    }
}

#[test]
fn settle_rejects_unrecoverable_outputs_and_maker_selected_blinding_seed() {
    for price in PRICES {
        let good = sample_settle(price).to_proof_inputs().unwrap();
        assert!(check_settle(&good), "positive control at price {price}");
        for attack in 0..5 {
            let mut inputs = good;
            match attack {
                0 => inputs.private.recipient_out.blinding = field(&fe(29)),
                1 => inputs.private.pool_change.blinding = field(&fe(29)),
                2 => inputs.private.maker_receipt.blinding = field(&fe(29)),
                3 => inputs.private.private_tx_blinding = field(&fe(29)),
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
                !check_settle(&inputs),
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
    let native = checked(|| inputs.execute()).expect("valid cancel");
    assert_eq!(bytes(native.public_hash()), cancel_public_hash(&inputs));
    let proof = prove("escrow_cancel", &inputs, cancel_public_hash(&inputs));
    assert!(
        verify_cancel(&proof, cancel_public_hash(&inputs)),
        "cancel must verify against the program key"
    );

    let first_nullifier = bytes(&inputs.public.first_nullifier);
    let blinding_seed = cancel_blinding_seed(&params.order_in.utxo.blinding).unwrap();
    let seed = derive_output_blinding_seed(&first_nullifier, &blinding_seed).unwrap();
    let mut recovered = inputs.private.refund_out;
    recovered.blinding =
        field(&derive_transact_output_blinding(&first_nullifier, &seed, 0).unwrap());
    assert_eq!(
        bytes(&recovered.hash().unwrap()),
        bytes(&inputs.private.refund_out.hash().unwrap())
    );

    let mut forged = inputs;
    forged.public.first_nullifier = field(&fe(17));
    assert!(!verify_cancel(&proof, cancel_public_hash(&forged)));
}

#[test]
fn cancel_rejects_unrecoverable_refund_and_canceller_selected_blinding_seed() {
    let good = sample_cancel().to_proof_inputs().unwrap();
    assert!(check_cancel(&good), "positive control");
    for attack in 0..3 {
        let mut inputs = good;
        match attack {
            0 => inputs.private.refund_out.blinding = field(&fe(29)),
            1 => inputs.private.private_tx_blinding = field(&fe(29)),
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
        assert!(!check_cancel(&inputs), "accepted recovery attack {attack}");
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
            let mut inputs = good;
            match attack {
                0 => inputs.private.recipient_out.owner_hash = field(&fe(29)),
                1 => inputs.private.recipient_out.amount = Field::from(ORDER_AMOUNT + 1),
                2 => inputs.private.recipient_out.asset = field(&fe(29)),
                3 => inputs.private.pool_change.owner_hash = field(&fe(29)),
                4 => inputs.private.pool_change.amount = Field::from(POOL_AMOUNT + 1),
                5 => inputs.private.pool_change.data_hash = Field::from(POOL_BOOKED),
                6 => inputs.private.maker_receipt.owner_hash = field(&fe(29)),
                7 => inputs.private.maker_receipt.amount = Field::from(ORDER_AMOUNT + 1),
                8 => inputs.private.pool_in.owner_hash = field(&fe(29)),
                9 => inputs.private.min_price = MIN_PRICE + 1,
                _ => inputs.public.execution_price = 0,
            }
            refresh_settle_hashes(&mut inputs);
            assert!(
                !check_settle(&inputs),
                "accepted settlement attack {attack} at price {price}"
            );
        }
    }
}

#[test]
fn cancel_rejects_diverted_refund_or_changed_order_opening() {
    let good = sample_cancel().to_proof_inputs().unwrap();
    for attack in 0..8 {
        let mut inputs = good;
        match attack {
            0 => inputs.private.refund_out.owner_hash = field(&fe(29)),
            1 => inputs.private.refund_out.amount = Field::from(ORDER_AMOUNT - 1),
            2 => inputs.private.refund_out.asset = field(&fe(29)),
            3 => inputs.private.refund_out.data_hash = field(&fe(29)),
            4 => inputs.private.order_amount = ORDER_AMOUNT + 1,
            5 => inputs.private.min_price = MIN_PRICE + 1,
            6 => inputs.public.order_in_hash = field(&fe(29)),
            _ => inputs.private.refund_out.ring_program_id = field(&fe(29)),
        }
        refresh_cancel_hashes(&mut inputs);
        assert!(!check_cancel(&inputs), "accepted cancel attack {attack}");
    }
}

/// Settlement drops the pool's booked total by the full reservation.
#[test]
fn settlement_consumes_the_full_reservation_from_booked() {
    for price in PRICES {
        for booked in [MAX_ORDER_SIZE, MAX_ORDER_SIZE + 1] {
            let mut params = sample_settle(price);
            params.pool_booked_in = booked;
            params.pool_in.data_hash = Some(u64_right_align(booked));
            let expected_booked = booked - MAX_ORDER_SIZE;
            params.pool_change.data_hash = Some(u64_right_align(expected_booked));
            let good = params.to_proof_inputs().unwrap();
            assert!(
                check_settle(&good),
                "rejected booked={booked} at price={price}"
            );

            let mut forged = good;
            forged.private.pool_change.data_hash = Field::from(expected_booked + 1);
            refresh_settle_hashes(&mut forged);
            if let Err(error) = refused_at(&forged, RESERVATION_CHECK) {
                panic!("unexpected rejection at booked={booked}, price={price}: {error}");
            }
        }
    }
}

/// `p - 1` for the BN254 scalar field: the field value of `-1`.
const FIELD_NEGATIVE_ONE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x00,
];

/// A pool note booked below `max_order_size` would release more reservation
/// than it books, stranding counted liquidity. The SDK refuses to build the
/// proof inputs, and the circuit rejects both the old clamped change
/// (`booked = 0`) and the wrapped `booked_in - max_order_size`.
#[test]
fn settlement_rejects_pool_note_booked_below_the_reservation() {
    let booked = MAX_ORDER_SIZE - 1;
    for price in PRICES {
        let mut params = sample_settle(price);
        params.pool_booked_in = booked;
        params.pool_in.data_hash = Some(u64_right_align(booked));
        let error = params.to_proof_inputs().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("pool_in books less than max_order_size"),
            "unexpected SDK rejection at price={price}: {error}"
        );

        let good = sample_settle(price).to_proof_inputs().unwrap();
        for (change_booked, expected) in [
            (Field::zero(), RESERVATION_CHECK),
            (field(&FIELD_NEGATIVE_ONE), BOOKED_RANGE_CHECK),
        ] {
            let mut forged = good;
            forged.private.pool_in.data_hash = Field::from(booked);
            forged.private.pool_change.data_hash = change_booked;
            refresh_settle_hashes(&mut forged);
            if let Err(error) = refused_at(&forged, expected) {
                panic!("expected `{}` at price={price}: {error}", expected.0);
            }
        }
    }
}
