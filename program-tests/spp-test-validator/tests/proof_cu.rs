//! Real-validator compute contracts for proof-bearing default-zone operations.

#![allow(dead_code)] // This focused binary composes a subset of the shared lifecycle fixture.

mod actions;
mod actor;
mod deposit_action;
mod harness;
mod localnet;

use anyhow::Result;
use serial_test::serial;
use zolana_test_utils::test_validator_asserts::assert_transaction_compute_units;
use zolana_transaction::SOL_MINT;

use harness::{LifecycleHarness, Rail};

// Local-validator baselines: P256 2x3 = 290,961; P256 withdrawal = 294,026;
// merge 8x1 = 326,407.
const P256_TRANSACTION_CU_LIMIT: u64 = 350_000;
const P256_WITHDRAWAL_CU_LIMIT: u64 = 350_000;
const MERGE_TRANSACTION_CU_LIMIT: u64 = 400_000;

#[test]
#[serial]
fn proof_bearing_default_zone_variants_stay_within_budget() -> Result<()> {
    let mut harness = LifecycleHarness::new()?;

    for _ in 0..2 {
        harness.deposit_sol("p256-sender", 1_000_000_000)?;
    }
    let signature =
        harness.transfer_asset("p256-sender", "p256-recipient", SOL_MINT, 400_000_000)?;
    assert_eq!(harness.last_rail, Some(Rail::Eddsa));
    assert_transaction_compute_units(
        &harness.rpc,
        &signature,
        "P256 transact 2x3",
        P256_TRANSACTION_CU_LIMIT,
    )?;

    for _ in 0..2 {
        harness.deposit_sol("p256-withdrawer", 1_000_000_000)?;
    }
    let signature = harness.withdraw_sol("p256-withdrawer", 400_000_000)?;
    assert_eq!(harness.last_rail, Some(Rail::Eddsa));
    assert_transaction_compute_units(
        &harness.rpc,
        &signature,
        "P256 SOL withdrawal 2x3",
        P256_WITHDRAWAL_CU_LIMIT,
    )?;

    let owner = harness.register_merge_owner("merge-owner", true)?;
    for _ in 0..8 {
        harness.deposit_sol("merge-owner", 1_000_000_000)?;
    }
    let signature = harness.merge("merge-owner", &owner, SOL_MINT, 8)?;
    assert_transaction_compute_units(
        &harness.rpc,
        &signature,
        "merge 8x1",
        MERGE_TRANSACTION_CU_LIMIT,
    )?;

    Ok(())
}
