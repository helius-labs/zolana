//! Real-validator compute contracts for proof-bearing policy-ring operations.

use anyhow::Result;
use serial_test::serial;
use zolana_test_utils::{
    test_validator_asserts::assert_transaction_compute_units, ring::RingHarness,
};
use zolana_transaction::SOL_MINT;

// Local-validator baselines (measured 2026-07-22): EdDSA 2x3 = 162,830;
// withdrawal = 165,260; ring-authority 1x1 = 150,839;
// merge-ring 8x1 = 310,385. Each ceiling sits at roughly 20% over its own
// baseline so a consumption regression trips its variant's assert. The P256
// 2x3 case was removed with the P256 transact rail (PR164).
const RING_EDDSA_TRANSACTION_CU_LIMIT: u64 = 196_000;
const RING_WITHDRAWAL_CU_LIMIT: u64 = 199_000;
const RING_AUTHORITY_TRANSACTION_CU_LIMIT: u64 = 182_000;
const RING_MERGE_TRANSACTION_CU_LIMIT: u64 = 375_000;

#[test]
#[serial]
fn proof_bearing_ring_variants_stay_within_budget() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;

    harness.make_payer_actor("eddsa-sender")?;
    for _ in 0..2 {
        harness.ring_shield_sol("eddsa-sender", 1_000_000_000)?;
    }
    let signature =
        harness.ring_transfer("eddsa-sender", "eddsa-recipient", SOL_MINT, 300_000_000)?;
    assert_transaction_compute_units(
        &harness.rpc,
        &signature,
        "ring transact EdDSA 2x3",
        RING_EDDSA_TRANSACTION_CU_LIMIT,
    )?;

    harness.make_payer_actor("ring-withdrawer")?;
    for _ in 0..2 {
        harness.ring_shield_sol("ring-withdrawer", 1_000_000_000)?;
    }
    let (signature, _) = harness.ring_withdraw("ring-withdrawer", SOL_MINT, 250_000_000)?;
    assert_transaction_compute_units(
        &harness.rpc,
        &signature,
        "ring SOL withdrawal EdDSA 2x3",
        RING_WITHDRAWAL_CU_LIMIT,
    )?;

    harness.ring_shield_sol("authority-sender", 1_000_000_000)?;
    let signature =
        harness.ring_authority_transfer("authority-sender", "authority-recipient", SOL_MINT)?;
    assert_transaction_compute_units(
        &harness.rpc,
        &signature,
        "ring-authority transact 1x1",
        RING_AUTHORITY_TRANSACTION_CU_LIMIT,
    )?;

    for _ in 0..8 {
        harness.ring_shield_sol("ring-merge-owner", 1_000_000_000)?;
    }
    let signature = harness.merge_ring("ring-merge-owner", SOL_MINT, 8)?;
    assert_transaction_compute_units(
        &harness.rpc,
        &signature,
        "merge-ring 8x1",
        RING_MERGE_TRANSACTION_CU_LIMIT,
    )?;

    Ok(())
}
