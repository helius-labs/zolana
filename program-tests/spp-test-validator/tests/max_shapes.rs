//! Real-validator confirmation of the widest default-ring transactions: the
//! widest transact shape of every output count and the widest merge, each at
//! every real input it supports. LiteSVM does not enforce the 4,096-byte v1
//! ceiling, so only a validator shows that these transactions land.

use anyhow::{anyhow, Result};
use serial_test::serial;
use solana_message::v1::MAX_TRANSACTION_SIZE;
use solana_signature::Signature;
use zolana_client::{Shape, DEFAULT_TRANSACT_CU_LIMIT};
use zolana_test_utils::{
    lifecycle::LifecycleHarness, nullifier_pda::assert_nullifier_pdas,
    test_validator_asserts::assert_transaction_compute_units,
};
use zolana_transaction::SOL_MINT;

const DEPOSIT_AMOUNT: u64 = 100_000_000;
/// A real input's nullifier (32) and tree index (1) in the instruction data,
/// plus its nullifier PDA address (32) and account index (1).
const BYTES_PER_INPUT: usize = 66;
const SENT_AMOUNT: u64 = 1_000_000;
const MERGE_INPUTS: usize = 51;
const MERGE_CU_LIMIT: u64 = 1_400_000;

/// `(shape, real inputs)`: 51x2 cannot carry 51 real inputs under 4,096
/// bytes, so its last slots are compact padding.
const SHAPES: [((usize, usize), usize); 4] =
    [((51, 2), 49), ((24, 4), 24), ((16, 8), 16), ((8, 16), 8)];

#[test]
#[serial]
fn widest_transact_shapes_confirm() -> Result<()> {
    let mut harness = LifecycleHarness::new()?;

    for ((n_inputs, n_outputs), real_inputs) in SHAPES {
        let label = format!("confidential eddsa {n_inputs}x{n_outputs}, {real_inputs} real inputs");
        let sender = format!("sender-{n_inputs}x{n_outputs}");
        let recipients = (1..n_outputs)
            .map(|index| format!("recipient-{n_inputs}x{n_outputs}-{index}"))
            .collect::<Vec<_>>();
        let recipients = recipients.iter().map(String::as_str).collect::<Vec<_>>();
        for _ in 0..real_inputs {
            harness.deposit_sol(&sender, DEPOSIT_AMOUNT)?;
        }

        let signature = harness.transfer_to_many(
            &sender,
            &recipients,
            real_inputs,
            SENT_AMOUNT,
            Shape::new(n_inputs, n_outputs),
        )?;
        let bytes = assert_landed(
            &harness,
            &signature,
            &label,
            DEFAULT_TRANSACT_CU_LIMIT.into(),
        )?;
        assert_no_room_for_another_input(&label, bytes, real_inputs, n_inputs);

        let indexed = harness
            .indexed
            .last()
            .ok_or_else(|| anyhow!("{label} was not indexed"))?
            .clone();
        assert_eq!(indexed.tx_signature, signature);
        assert_eq!(indexed.nullifiers.len(), real_inputs);
        assert_eq!(indexed.output_slots.len(), n_outputs);
        assert_nullifier_pdas(&harness.rpc, &harness.tree, &indexed.nullifiers)?;
        for recipient in &recipients {
            harness.sync(recipient)?;
            harness.assert_utxos(recipient)?;
        }
    }
    Ok(())
}

#[test]
#[serial]
fn widest_merge_confirms() -> Result<()> {
    let mut harness = LifecycleHarness::new()?;
    let owner = harness.register_merge_owner("merge-owner", true)?;
    for _ in 0..MERGE_INPUTS {
        harness.deposit_sol("merge-owner", DEPOSIT_AMOUNT)?;
    }

    let signature = harness.merge("merge-owner", &owner, SOL_MINT, MERGE_INPUTS)?;
    assert_landed(
        &harness,
        &signature,
        &format!("merge {MERGE_INPUTS}x1, direct"),
        MERGE_CU_LIMIT,
    )?;
    harness.assert_merged("merge-owner")?;
    Ok(())
}

/// A compact-padded shape carries the most real inputs that fit: one more
/// would add its nullifier and tree index to the instruction data and its
/// nullifier PDA to the accounts, and overflow 4,096 bytes.
fn assert_no_room_for_another_input(
    label: &str,
    bytes: usize,
    real_inputs: usize,
    n_inputs: usize,
) {
    if real_inputs < n_inputs {
        assert!(
            bytes + BYTES_PER_INPUT > MAX_TRANSACTION_SIZE,
            "{label}: {bytes} bytes leave room for another real input"
        );
    }
}

/// The transaction fits both v1 ceilings and landed within `cu_limit`.
/// Returns its size in bytes.
fn assert_landed(
    harness: &LifecycleHarness,
    signature: &Signature,
    label: &str,
    cu_limit: u64,
) -> Result<usize> {
    let size = harness
        .last_transaction_size
        .ok_or_else(|| anyhow!("{label} recorded no transaction size"))?;
    assert!(
        size.fits(),
        "{label}: {} bytes and {} addresses exceed a v1 ceiling",
        size.bytes,
        size.addresses
    );
    let consumed = assert_transaction_compute_units(&harness.rpc, signature, label, cu_limit)?;
    println!(
        "{label}: {} bytes, {} addresses, {consumed} CU",
        size.bytes, size.addresses
    );
    Ok(size.bytes)
}
