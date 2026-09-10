use anyhow::{anyhow, Result};
use serial_test::serial;
use solana_message::v1;
use zolana_client::Shape;
use zolana_test_utils::{
    compute::DEFAULT_TRANSACT_CU_LIMIT,
    lifecycle::LifecycleHarness,
    localnet::{ValidatorBackend, SOL_CHANGE_POSITION},
    nullifier_pda::{assert_nullifier_pdas, nullifier_queue_next_index},
    test_validator_asserts::assert_transaction_compute_units,
};
use zolana_transaction::SOL_MINT;

const PACKET_DATA_SIZE: usize = 1232;

const DEPOSIT_LAMPORTS: u64 = 100_000_000;

#[test]
#[serial]
fn the_consolidation_shape_lands_as_a_transaction_v1() -> Result<()> {
    let shape = Shape::IN36_OUT2;
    let mut harness = LifecycleHarness::new_on(ValidatorBackend::Surfpool)?;

    for _ in 0..shape.n_inputs() {
        harness.deposit_sol("consolidator", DEPOSIT_LAMPORTS)?;
    }
    let consolidator = harness.actor("consolidator").keypair.signing_pubkey();

    let queue_before = nullifier_queue_next_index(&harness.rpc, &harness.tree)?;
    let record = harness.consolidate_at_shape("consolidator", SOL_MINT, shape)?;
    println!(
        "{} inputs x {} outputs: {} transaction v1 bytes",
        shape.n_inputs(),
        shape.n_outputs(),
        record.transaction_len
    );

    assert!(
        record.transaction_len <= v1::MAX_TRANSACTION_SIZE,
        "{} bytes exceeds the transaction v1 limit of {}",
        record.transaction_len,
        v1::MAX_TRANSACTION_SIZE
    );
    assert!(
        record.transaction_len > PACKET_DATA_SIZE,
        "{} bytes fits a legacy packet, so this test no longer proves anything \
         about v1",
        record.transaction_len
    );
    assert_eq!(
        record.nullifiers.len(),
        shape.n_inputs(),
        "one nullifier per declared input"
    );

    let pdas = assert_nullifier_pdas(&harness.rpc, &harness.tree, &record.nullifiers)?;
    let expected_indices: Vec<u64> = (0..shape.n_inputs() as u64)
        .map(|offset| queue_before + offset)
        .collect();
    assert_eq!(
        pdas.iter().map(|pda| pda.queue_index).collect::<Vec<_>>(),
        expected_indices,
        "nullifier PDA queue indices must be contiguous from {queue_before}"
    );
    assert_eq!(
        nullifier_queue_next_index(&harness.rpc, &harness.tree)?,
        queue_before + shape.n_inputs() as u64,
        "the nullifier queue advances once per input"
    );

    let indexed = &record.indexed;
    assert_eq!(
        indexed.output_slots.len(),
        shape.n_outputs(),
        "indexed output count"
    );
    let first_leaf = indexed
        .output_slots
        .first()
        .ok_or_else(|| anyhow!("indexed transaction has no output slots"))?
        .output_context
        .leaf_index;
    let expected_leaves: Vec<u64> = (0..shape.n_outputs() as u64)
        .map(|offset| first_leaf + offset)
        .collect();
    assert_eq!(
        indexed
            .output_slots
            .iter()
            .map(|slot| slot.output_context.leaf_index)
            .collect::<Vec<_>>(),
        expected_leaves,
        "outputs must append at contiguous leaf indices from {first_leaf}"
    );

    let expected_total = DEPOSIT_LAMPORTS
        .checked_mul(shape.n_inputs() as u64)
        .ok_or_else(|| anyhow!("deposit total overflows u64"))?;
    assert_eq!(record.input_total, expected_total, "every deposit is spent");
    assert_eq!(
        (
            record.output.utxo.owner,
            record.output.utxo.asset,
            record.output.utxo.amount,
            record.output.output_context.leaf_index,
            record.output.spent,
        ),
        (
            consolidator,
            SOL_MINT,
            expected_total,
            first_leaf + u64::from(SOL_CHANGE_POSITION),
            false,
        ),
        "the change output returns the whole consolidated balance to the consolidator"
    );

    assert_transaction_compute_units(
        &harness.rpc,
        &record.signature,
        "transact 36x2",
        u64::from(DEFAULT_TRANSACT_CU_LIMIT),
    )?;
    Ok(())
}
