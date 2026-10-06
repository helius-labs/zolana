//! Real-validator confirmation of the widest ring transactions: the widest
//! transact shape of every output count on both ring rails and the widest ring
//! merge, each at the most real inputs that fit the 4,096-byte v1 ceiling, with
//! compact padding for the rest. LiteSVM does not enforce that ceiling, so only
//! a validator shows that these transactions land.

use anyhow::{anyhow, Result};
use serial_test::serial;
use solana_message::v1::MAX_TRANSACTION_SIZE;
use solana_signature::Signature;
use zolana_client::Shape;
use zolana_test_utils::{
    nullifier_pda::assert_nullifier_pdas,
    ring::{RingHarness, RingRail},
    test_validator_asserts::assert_transaction_compute_units,
};
use zolana_transaction::SOL_MINT;

const DEPOSIT_AMOUNT: u64 = 100_000_000;
/// A real input's nullifier (32) and tree index (1) in the instruction data,
/// plus its nullifier PDA address (32) and account index (1).
const BYTES_PER_INPUT: usize = 66;
const SENT_AMOUNT: u64 = 1_000_000;
const MERGE_INPUTS: usize = 51;
const CU_LIMIT: u64 = 1_400_000;

/// The widest shape of one output count and the real inputs and outputs it
/// carries under 4,096 bytes; compact padding fills the remaining slots.
struct MaxShape {
    n_inputs: usize,
    n_outputs: usize,
    real_inputs: usize,
    real_outputs: usize,
}

const fn max_shape(
    (n_inputs, n_outputs): (usize, usize),
    real_inputs: usize,
    real_outputs: usize,
) -> MaxShape {
    MaxShape {
        n_inputs,
        n_outputs,
        real_inputs,
        real_outputs,
    }
}

const EDDSA_SHAPES: [MaxShape; 4] = [
    max_shape((51, 2), 48, 2),
    max_shape((24, 4), 24, 4),
    max_shape((16, 8), 16, 8),
    max_shape((8, 16), 8, 16),
];
/// A P256 proof carries its BSB22 commitment and every output joins the
/// ring, so the P256 rail fits fewer real inputs at 51x2 and fewer real
/// outputs at 8x16.
const P256_SHAPES: [MaxShape; 4] = [
    max_shape((51, 2), 45, 2),
    max_shape((24, 4), 24, 4),
    max_shape((16, 8), 16, 8),
    max_shape((8, 16), 8, 15),
];

#[test]
#[serial]
fn widest_ring_eddsa_transact_shapes_confirm() -> Result<()> {
    widest_ring_transact_shapes_confirm(RingRail::Eddsa, &EDDSA_SHAPES)
}

#[test]
#[serial]
fn widest_ring_p256_transact_shapes_confirm() -> Result<()> {
    widest_ring_transact_shapes_confirm(RingRail::P256, &P256_SHAPES)
}

#[test]
#[serial]
fn widest_ring_merge_confirms() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;
    for _ in 0..MERGE_INPUTS {
        harness.ring_shield_sol("merge-owner", DEPOSIT_AMOUNT)?;
    }

    let signature = harness.merge_ring("merge-owner", SOL_MINT, MERGE_INPUTS)?;
    assert_landed(
        &harness,
        &signature,
        &format!("ring merge {MERGE_INPUTS}x1"),
    )?;
    harness.assert_merged_ring("merge-owner")?;
    Ok(())
}

fn widest_ring_transact_shapes_confirm(rail: RingRail, shapes: &[MaxShape]) -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;

    for &MaxShape {
        n_inputs,
        n_outputs,
        real_inputs,
        real_outputs,
    } in shapes
    {
        let label = format!(
            "ring {rail:?} {n_inputs}x{n_outputs}, {real_inputs} real inputs, {real_outputs} real outputs"
        );
        let sender = format!("sender-{n_inputs}x{n_outputs}");
        if rail == RingRail::P256 {
            harness.make_p256_actor(&sender)?;
        }
        let recipients = (1..real_outputs)
            .map(|index| format!("recipient-{n_inputs}x{n_outputs}-{index}"))
            .collect::<Vec<_>>();
        let recipients = recipients.iter().map(String::as_str).collect::<Vec<_>>();
        for _ in 0..real_inputs {
            harness.ring_shield_sol(&sender, DEPOSIT_AMOUNT)?;
        }

        let signature = harness.ring_transfer_to_many(
            &sender,
            &recipients,
            real_inputs,
            SENT_AMOUNT,
            rail,
            Shape::new(n_inputs, n_outputs),
        )?;
        let bytes = assert_landed(&harness, &signature, &label)?;
        if real_inputs < n_inputs {
            assert!(
                bytes + BYTES_PER_INPUT > MAX_TRANSACTION_SIZE,
                "{label}: {bytes} bytes leave room for another real input"
            );
        }

        let indexed = harness
            .indexed
            .last()
            .ok_or_else(|| anyhow!("{label} was not indexed"))?
            .clone();
        assert_eq!(indexed.tx_signature, signature);
        assert_eq!(indexed.nullifiers.len(), real_inputs);
        assert_eq!(indexed.output_slots.len(), real_outputs);
        assert_nullifier_pdas(&harness.rpc, &harness.tree, &indexed.nullifiers)?;
    }
    Ok(())
}

/// The transaction fits both v1 ceilings and landed within the ring
/// transaction compute ceiling. Returns its size in bytes.
fn assert_landed(harness: &RingHarness, signature: &Signature, label: &str) -> Result<usize> {
    let size = harness
        .last_transaction_size
        .ok_or_else(|| anyhow!("{label} recorded no transaction size"))?;
    assert!(
        size.fits(),
        "{label}: {} bytes and {} addresses exceed a v1 ceiling",
        size.bytes,
        size.addresses
    );
    let consumed = assert_transaction_compute_units(&harness.rpc, signature, label, CU_LIMIT)?;
    println!(
        "{label}: {} bytes, {} addresses, {consumed} CU",
        size.bytes, size.addresses
    );
    Ok(size.bytes)
}
