//! Real-validator compute contracts for proof-bearing policy-zone operations.

#![allow(dead_code)] // This focused binary composes a subset of the shared lifecycle fixture.

mod actions;
mod actor;
mod harness;
mod support;

use anyhow::Result;
use serial_test::serial;
use zolana_test_utils::test_validator_asserts::assert_transaction_compute_units;
use zolana_transaction::SOL_MINT;

use harness::ZoneHarness;

// Local-validator baselines (measured 2026-07-22): EdDSA 2x3 = 162,830;
// withdrawal = 165,260; zone-authority 1x1 = 150,839;
// merge-zone 8x1 = 310,385. Each ceiling sits at roughly 20% over its own
// baseline so a consumption regression trips its variant's assert. The P256
// 2x3 case was removed with the P256 transact rail (PR164).
const ZONE_EDDSA_TRANSACTION_CU_LIMIT: u64 = 196_000;
const ZONE_WITHDRAWAL_CU_LIMIT: u64 = 199_000;
const ZONE_AUTHORITY_TRANSACTION_CU_LIMIT: u64 = 182_000;
const ZONE_MERGE_TRANSACTION_CU_LIMIT: u64 = 375_000;

#[test]
#[serial]
fn proof_bearing_zone_variants_stay_within_budget() -> Result<()> {
    let mut harness = ZoneHarness::new()?;
    harness.create_enabled_zone_config()?;

    harness.make_payer_actor("eddsa-sender")?;
    for _ in 0..2 {
        harness.zone_shield_sol("eddsa-sender", 1_000_000_000)?;
    }
    let signature =
        harness.zone_transfer("eddsa-sender", "eddsa-recipient", SOL_MINT, 300_000_000)?;
    assert_transaction_compute_units(
        &harness.rpc,
        &signature,
        "zone transact EdDSA 2x3",
        ZONE_EDDSA_TRANSACTION_CU_LIMIT,
    )?;

    harness.make_payer_actor("zone-withdrawer")?;
    for _ in 0..2 {
        harness.zone_shield_sol("zone-withdrawer", 1_000_000_000)?;
    }
    let (signature, _) = harness.zone_withdraw("zone-withdrawer", SOL_MINT, 250_000_000)?;
    assert_transaction_compute_units(
        &harness.rpc,
        &signature,
        "zone SOL withdrawal EdDSA 2x3",
        ZONE_WITHDRAWAL_CU_LIMIT,
    )?;

    harness.zone_shield_sol("authority-sender", 1_000_000_000)?;
    let signature =
        harness.zone_authority_transfer("authority-sender", "authority-recipient", SOL_MINT)?;
    assert_transaction_compute_units(
        &harness.rpc,
        &signature,
        "zone-authority transact 1x1",
        ZONE_AUTHORITY_TRANSACTION_CU_LIMIT,
    )?;

    for _ in 0..8 {
        harness.zone_shield_sol("zone-merge-owner", 1_000_000_000)?;
    }
    let signature = harness.merge_zone("zone-merge-owner", SOL_MINT, 8)?;
    assert_transaction_compute_units(
        &harness.rpc,
        &signature,
        "merge-zone 8x1",
        ZONE_MERGE_TRANSACTION_CU_LIMIT,
    )?;

    Ok(())
}
