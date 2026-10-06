//! Real-validator compute contracts for proof-bearing policy-ring operations.

use anyhow::Result;
use serial_test::serial;
use zolana_test_utils::{
    ring::RingHarness, test_validator_asserts::assert_transaction_compute_units,
};
use zolana_transaction::SOL_MINT;

// Local-validator baselines (surfpool, 2026-10-06): EdDSA 2x4 = 153,949;
// withdrawal = 150,162; ring-authority 2x2 = 142,468; merge-ring 8 inputs at
// 24x1 = 202,894. The ceilings date from the wider-costing shapes these
// replaced (2x3, 1x1 authority, 8x1 merge) and sit 18% to 85% above the
// current baselines. The 51-input ring merge measures 301,037
// (`max_shapes`).
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
        "ring transact EdDSA 2x4",
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
        "ring SOL withdrawal EdDSA",
        RING_WITHDRAWAL_CU_LIMIT,
    )?;

    harness.ring_shield_sol("authority-sender", 1_000_000_000)?;
    let signature =
        harness.ring_authority_transfer("authority-sender", "authority-recipient", SOL_MINT)?;
    assert_transaction_compute_units(
        &harness.rpc,
        &signature,
        "ring-authority transact 2x2",
        RING_AUTHORITY_TRANSACTION_CU_LIMIT,
    )?;

    for _ in 0..8 {
        harness.ring_shield_sol("ring-merge-owner", 1_000_000_000)?;
    }
    let signature = harness.merge_ring("ring-merge-owner", SOL_MINT, 8)?;
    assert_transaction_compute_units(
        &harness.rpc,
        &signature,
        "merge-ring 8 inputs at 24x1",
        RING_MERGE_TRANSACTION_CU_LIMIT,
    )?;

    Ok(())
}
