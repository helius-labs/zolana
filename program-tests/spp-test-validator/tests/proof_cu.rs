//! Real-validator compute contracts for proof-bearing default-ring operations.

use anyhow::Result;
use serial_test::serial;
use std::time::Instant;
use zolana_test_utils::{
    lifecycle::LifecycleHarness, test_validator_asserts::assert_transaction_compute_units,
};
use zolana_transaction::SOL_MINT;

// Local-validator baselines: transact 2x3 = 290,961; withdrawal = 294,026;
// merge 8x1 = 326,407.
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
    assert_transaction_compute_units(&harness.rpc, &signature, "transact 2x3", TRANSACT_CU_LIMIT)?;

    for _ in 0..2 {
        harness.deposit_sol("withdrawer", 1_000_000_000)?;
    }
    let signature = harness.withdraw_sol("withdrawer", 400_000_000)?;
    assert_transaction_compute_units(
        &harness.rpc,
        &signature,
        "SOL withdrawal 2x3",
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
        "merge 8x1",
        MERGE_TRANSACTION_CU_LIMIT,
    )?;

    Ok(())
}

#[test]
#[ignore]
#[serial]
fn merge_spend_e2e_benchmark() -> Result<()> {
    let inputs = std::env::var("E2E_BENCH_INPUTS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(72);
    assert!(inputs > 0);

    let mut harness = LifecycleHarness::new()?;
    let setup_start = Instant::now();
    let owner = harness.register_merge_owner("bench-owner", true)?;
    for _ in 0..inputs {
        harness.deposit_sol("bench-owner", 1_000_000_000)?;
    }
    let setup_ms = setup_start.elapsed().as_millis();

    let spend_start = Instant::now();
    let mut merge_cu = 0;
    let mut merge_transactions: usize = 0;
    let mut remaining = inputs;
    while remaining > 0 {
        let count = 36.min(remaining);
        let signature =
            harness.merge_benchmark_direct_payer("bench-owner", &owner, SOL_MINT, count)?;
        merge_cu += assert_transaction_compute_units(
            &harness.rpc,
            &signature,
            "benchmark merge",
            1_400_000,
        )?;
        merge_transactions += 1;
        harness.sync("bench-owner")?;
        remaining -= count;
    }

    let mut merged = inputs.div_ceil(36);
    while merged > 2 {
        let signature =
            harness.merge_benchmark_direct_payer("bench-owner", &owner, SOL_MINT, merged)?;
        merge_cu += assert_transaction_compute_units(
            &harness.rpc,
            &signature,
            "benchmark consolidation",
            1_400_000,
        )?;
        merge_transactions += 1;
        harness.sync("bench-owner")?;
        merged = 1;
    }

    let transfer_cu = if merged == 1 {
        let signature = harness.transfer_single(
            "bench-owner",
            "bench-recipient",
            SOL_MINT,
            inputs as u64 * 1_000_000_000,
        )?;
        assert_transaction_compute_units(&harness.rpc, &signature, "benchmark transfer", 1_400_000)?
    } else if merged == 2 {
        let signature = harness.transfer_asset(
            "bench-owner",
            "bench-recipient",
            SOL_MINT,
            inputs as u64 * 1_000_000_000,
        )?;
        assert_transaction_compute_units(&harness.rpc, &signature, "benchmark transfer", 1_400_000)?
    } else {
        unreachable!("consolidation leaves at most two outputs");
    };
    let spend_ms = spend_start.elapsed().as_millis();
    println!(
        "E2E_BENCH variant=merge inputs={inputs} merge_transactions={merge_transactions} merged_outputs={merged} merge_cu={merge_cu} transfer_cu={transfer_cu} setup_ms={setup_ms} spend_ms={spend_ms}"
    );
    Ok(())
}

#[test]
#[ignore]
#[serial]
fn cached_merge_spend_e2e_benchmark() -> Result<()> {
    let inputs = std::env::var("E2E_BENCH_INPUTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(144);
    LifecycleHarness::new()?.cached_merge_spend_benchmark(inputs)
}
