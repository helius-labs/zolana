//! Transaction v1 acceptance for the large consolidation shape.
//!
//! This is the only check that a real validator accepts a 4 KB transaction.
//! litesvm never enforces a packet size, and `solana-test-validator` refuses
//! anything above `PACKET_DATA_SIZE` at its packet buffer before the runtime
//! sees it, so the suite boots surfpool instead.

use anyhow::{anyhow, Result};
use serial_test::serial;
use solana_message::v1;
use zolana_client::Shape;
use zolana_test_utils::{
    lifecycle::{large_shape::CONSOLIDATION_CU_LIMIT, LifecycleHarness},
    localnet::ValidatorBackend,
    nullifier_pda::{assert_nullifier_pdas, nullifier_queue_next_index},
    test_validator_asserts::{assert_transaction_compute_units, wait_for_indexed_transaction},
};
use zolana_transaction::SOL_MINT;

/// The legacy and v0 packet ceiling. The consolidation shape's instruction data
/// alone is larger, so no address lookup table could bring it under: addresses
/// are not what overflows.
const PACKET_DATA_SIZE: usize = 1232;

/// One deposit per input. Small enough that 36 of them stay well inside the
/// bootstrap payer's balance.
const DEPOSIT_LAMPORTS: u64 = 100_000_000;

#[test]
#[serial]
fn the_consolidation_shape_lands_as_a_transaction_v1() -> Result<()> {
    let shape = Shape::IN36_OUT2;
    let mut harness = LifecycleHarness::new_on(ValidatorBackend::Surfpool)?;

    // Every input belongs to one actor, so the signer run is a single entry and
    // the transaction carries one signature. The binding limit here is
    // `MAX_UNIQUE_SIGNERS` (8, payer included), not v1's `MAX_SIGNATURES` of 12.
    for _ in 0..shape.n_inputs() {
        harness.deposit_sol("consolidator", DEPOSIT_LAMPORTS)?;
    }

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

    // Each input takes the next nullifier-queue index, so the PDAs the
    // transaction created must carry a contiguous run starting where the queue
    // stood before it.
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

    // Photon indexing the event is the second half of the acceptance claim: a
    // transaction the RPC accepts but the indexer cannot read back is not usable.
    let indexed = wait_for_indexed_transaction(&harness.indexer, record.view_tag, record.signature);
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

    assert_transaction_compute_units(
        &harness.rpc,
        &record.signature,
        "transact 36x2",
        u64::from(CONSOLIDATION_CU_LIMIT),
    )?;
    Ok(())
}
