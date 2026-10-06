//! Real-validator compute contracts for proof-bearing default-ring operations.

use anyhow::Result;
use serial_test::serial;
use zolana_test_utils::{
    lifecycle::LifecycleHarness, test_validator_asserts::assert_transaction_compute_units,
};
use zolana_transaction::SOL_MINT;

// Local-validator baselines (surfpool, 2026-10-06): transact 2x4 = 142,432;
// withdrawal = 146,029; merge 8 inputs at 24x1 = 242,412. The widest shapes
// measure up to 309,168 (`max_shapes`).
const TRANSACT_CU_LIMIT: u64 = 350_000;
const WITHDRAWAL_CU_LIMIT: u64 = 350_000;
const MERGE_TRANSACTION_CU_LIMIT: u64 = 400_000;

#[test]
#[serial]
fn proof_bearing_default_ring_variants_stay_within_budget() -> Result<()> {
    let mut harness = LifecycleHarness::new()?;

    for _ in 0..2 {
        harness.deposit_sol("sender", 1_000_000_000)?;
    }
    let signature = harness.transfer_asset("sender", "recipient", SOL_MINT, 400_000_000)?;
    assert_transaction_compute_units(&harness.rpc, &signature, "transact 2x4", TRANSACT_CU_LIMIT)?;

    for _ in 0..2 {
        harness.deposit_sol("withdrawer", 1_000_000_000)?;
    }
    let signature = harness.withdraw_sol("withdrawer", 400_000_000)?;
    assert_transaction_compute_units(
        &harness.rpc,
        &signature,
        "SOL withdrawal",
        WITHDRAWAL_CU_LIMIT,
    )?;

    let owner = harness.register_merge_owner("merge-owner", true)?;
    for _ in 0..8 {
        harness.deposit_sol("merge-owner", 1_000_000_000)?;
    }
    let signature = harness.merge("merge-owner", &owner, SOL_MINT, 8)?;
    assert_transaction_compute_units(
        &harness.rpc,
        &signature,
        "merge 8 inputs at 24x1",
        MERGE_TRANSACTION_CU_LIMIT,
    )?;

    Ok(())
}
