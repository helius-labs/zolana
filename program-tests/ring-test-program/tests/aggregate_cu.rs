//! Compute, proving, and size cost of a batched ring transfer against the solo
//! path.
//!
//! A batch can exceed the transaction size limit before it exceeds any compute
//! limit, so every run reports the size whether or not the transaction landed.

use anyhow::Result;
use serial_test::serial;
use zolana_test_utils::{
    ring::{aggregate_transact::AggregateTiming, ring_transact::RingRail, RingHarness},
    test_validator_asserts::assert_transaction_compute_units,
};
use zolana_transaction::SOL_MINT;

/// Well above any measured batch. The run reports the number. This only catches
/// a runaway.
const AGGREGATE_CU_LIMIT: u64 = 1_400_000;

/// SIMD-0296 raises this to 4096 over QUIC, with the SIMD-0385 v1 transaction
/// format. Until then a batch that exceeds it cannot be sent.
const TRANSACTION_SIZE_LIMIT: usize = 1232;

fn report(
    harness: &RingHarness,
    label: &str,
    legs: usize,
    timing: &AggregateTiming,
    solo_cu: u64,
) -> Result<()> {
    println!("{label}, {legs} legs");
    println!(
        "  instruction data: {} bytes (transaction limit {TRANSACTION_SIZE_LIMIT})",
        timing.instruction_data_len
    );
    println!("  leg proving: {:?} ms", timing.leg_prove_ms);
    println!("  aggregate proving: {} ms", timing.aggregate_prove_ms);
    println!(
        "  total proving: {} ms against {} ms solo",
        timing.legs_total_ms() + timing.aggregate_prove_ms,
        timing.legs_total_ms()
    );

    match timing.signature {
        Some(signature) => {
            let consumed = assert_transaction_compute_units(
                &harness.rpc,
                &signature,
                label,
                AGGREGATE_CU_LIMIT,
            )?;
            let solo_total = solo_cu * legs as u64;
            println!("  aggregate: {consumed} CU against {solo_total} CU solo");
            if solo_total > consumed {
                println!("  saved: {} CU", solo_total - consumed);
            } else {
                println!("  cost: {} CU over solo", consumed - solo_total);
            }
        }
        None => println!("  not sent: over the transaction size limit"),
    }
    Ok(())
}

#[test]
#[serial]
fn aggregate_ring_eddsa_reports_cost() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;

    harness.make_payer_actor("agg-sender")?;
    for _ in 0..2 {
        harness.ring_shield_sol("agg-sender", 1_000_000_000)?;
    }
    let solo = harness.ring_transfer("agg-sender", "solo-recipient", SOL_MINT, 300_000_000)?;
    let solo_cu = assert_transaction_compute_units(
        &harness.rpc,
        &solo,
        "ring transact EdDSA 2x3",
        AGGREGATE_CU_LIMIT,
    )?;

    for legs in [2usize, 3] {
        // Every leg spends two of the sender's UTXOs.
        for _ in 0..(2 * legs) {
            harness.ring_shield_sol("agg-sender", 1_000_000_000)?;
        }
        let timing = harness.ring_aggregate_transfer(
            "agg-sender",
            legs,
            SOL_MINT,
            100_000_000,
            RingRail::Eddsa,
        )?;
        report(
            &harness,
            "aggregate ring transact EdDSA 2x3",
            legs,
            &timing,
            solo_cu,
        )?;
    }
    Ok(())
}

#[test]
#[serial]
fn aggregate_ring_p256_reports_cost() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;

    harness.make_p256_actor("aggp-sender")?;
    for _ in 0..2 {
        harness.ring_shield_sol("aggp-sender", 1_000_000_000)?;
    }
    let solo =
        harness.ring_transfer_p256("aggp-sender", "solo-p256-recipient", SOL_MINT, 300_000_000)?;
    let solo_cu = assert_transaction_compute_units(
        &harness.rpc,
        &solo,
        "ring transact P256 2x3",
        AGGREGATE_CU_LIMIT,
    )?;

    for legs in [2usize, 3] {
        for _ in 0..(2 * legs) {
            harness.ring_shield_sol("aggp-sender", 1_000_000_000)?;
        }
        let timing = harness.ring_aggregate_transfer(
            "aggp-sender",
            legs,
            SOL_MINT,
            100_000_000,
            RingRail::P256,
        )?;
        report(
            &harness,
            "aggregate ring transact P256 2x3",
            legs,
            &timing,
            solo_cu,
        )?;
    }
    Ok(())
}
