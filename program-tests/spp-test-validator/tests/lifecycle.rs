//! Local-validator lifecycle tests written as ordinary Rust programs.

mod actions;
mod actor;
mod deposit_action;
mod harness;

use anyhow::{Context, Result};
use serial_test::serial;
use solana_address::Address;
use zolana_transaction::SOL_MINT;

use actions::randomized::Workload;
use harness::{LifecycleHarness, Rail};

#[test]
#[serial]
fn p256_transfers_cover_sol_and_spl_assets() -> Result<()> {
    let mut harness = LifecycleHarness::new()?;
    harness.ensure_spl_asset()?;
    let spl = Address::new_from_array(harness.spl_asset()?.mint.to_bytes());

    for _ in 0..2 {
        harness.deposit_sol("sender", 1_000_000_000)?;
        harness.assert_deposited("sender", 1_000_000_000)?;
    }
    harness.transfer_asset("sender", "recipient", SOL_MINT, 400_000_000)?;
    assert_eq!(harness.last_rail, Some(Rail::Eddsa));
    harness.assert_last_event_decodes()?;
    harness.sync("sender")?;
    harness.sync("recipient")?;
    harness.assert_utxos("sender")?;
    harness.assert_utxos("recipient")?;
    harness.assert_no_utxos("bystander")?;

    for _ in 0..2 {
        harness.deposit_spl("sender", 1_000_000_000)?;
        harness.assert_deposited("sender", 1_000_000_000)?;
    }
    harness.transfer_asset("sender", "recipient", spl, 400_000_000)?;
    assert_eq!(harness.last_rail, Some(Rail::Eddsa));
    harness.sync("sender")?;
    harness.sync("recipient")?;
    harness.assert_utxos("sender")?;
    harness.assert_utxos("recipient")?;

    Ok(())
}

#[test]
#[serial]
fn p256_transfers_cover_mixed_assets_single_input_and_consolidation() -> Result<()> {
    let mut harness = LifecycleHarness::new()?;
    harness.ensure_spl_asset()?;
    let spl = Address::new_from_array(harness.spl_asset()?.mint.to_bytes());

    harness.deposit_sol("sender", 1_000_000_000)?;
    harness.deposit_spl("sender", 1_000_000_000)?;
    harness.transfer_mixed("sender", "recipient", spl, 400_000_000)?;
    assert_eq!(harness.last_rail, Some(Rail::Eddsa));
    harness.sync("sender")?;
    harness.sync("recipient")?;
    harness.assert_utxos("sender")?;
    harness.assert_utxos("recipient")?;

    harness.deposit_sol("sender", 1_000_000_000)?;
    harness.transfer_single("sender", "recipient", SOL_MINT, 600_000_000)?;
    assert_eq!(harness.last_rail, Some(Rail::Eddsa));
    harness.sync("sender")?;
    harness.sync("recipient")?;
    harness.assert_utxos("sender")?;
    harness.assert_utxos("recipient")?;

    harness.consolidate("sender", SOL_MINT)?;
    assert_eq!(harness.last_rail, Some(Rail::Eddsa));
    harness.sync("sender")?;
    harness.assert_utxos("sender")?;

    harness.deposit_spl("spl-sender", 1_000_000_000)?;
    harness.transfer_single("spl-sender", "spl-recipient", spl, 600_000_000)?;
    assert_eq!(harness.last_rail, Some(Rail::Eddsa));
    harness.sync("spl-sender")?;
    harness.sync("spl-recipient")?;
    harness.assert_utxos("spl-sender")?;
    harness.assert_utxos("spl-recipient")?;

    harness.consolidate("spl-sender", spl)?;
    assert_eq!(harness.last_rail, Some(Rail::Eddsa));
    harness.sync("spl-sender")?;
    harness.assert_utxos("spl-sender")?;

    Ok(())
}

#[test]
#[serial]
fn eddsa_transfer_updates_both_wallets_without_leaking_to_bystanders() -> Result<()> {
    let mut harness = LifecycleHarness::new()?;
    harness.make_eddsa_actor("eddsa-sender")?;
    for _ in 0..2 {
        harness.deposit_sol("eddsa-sender", 1_000_000_000)?;
    }
    harness.transfer_asset("eddsa-sender", "eddsa-recipient", SOL_MINT, 400_000_000)?;
    assert_eq!(harness.last_rail, Some(Rail::Eddsa));
    harness.sync("eddsa-sender")?;
    harness.sync("eddsa-recipient")?;
    harness.assert_utxos("eddsa-sender")?;
    harness.assert_utxos("eddsa-recipient")?;
    harness.assert_no_utxos("bystander")?;
    Ok(())
}

#[test]
#[serial]
fn eddsa_transfers_cover_spl_mixed_single_input_and_change_only() -> Result<()> {
    let mut harness = LifecycleHarness::new()?;
    harness.ensure_spl_asset()?;
    let spl = Address::new_from_array(harness.spl_asset()?.mint.to_bytes());
    harness.make_eddsa_actor("eddsa-sender")?;

    for _ in 0..2 {
        harness.deposit_spl("eddsa-sender", 1_000_000_000)?;
    }
    harness.transfer_asset("eddsa-sender", "recipient", spl, 400_000_000)?;
    assert_eq!(harness.last_rail, Some(Rail::Eddsa));
    harness.sync("eddsa-sender")?;
    harness.sync("recipient")?;
    harness.assert_utxos("eddsa-sender")?;
    harness.assert_utxos("recipient")?;

    harness.deposit_sol("eddsa-sender", 1_000_000_000)?;
    harness.deposit_spl("eddsa-sender", 1_000_000_000)?;
    harness.transfer_mixed("eddsa-sender", "recipient", spl, 250_000_000)?;
    assert_eq!(harness.last_rail, Some(Rail::Eddsa));
    harness.sync("eddsa-sender")?;
    harness.sync("recipient")?;
    harness.assert_utxos("eddsa-sender")?;
    harness.assert_utxos("recipient")?;

    harness.deposit_sol("eddsa-sender", 1_000_000_000)?;
    harness.transfer_single("eddsa-sender", "recipient", SOL_MINT, 300_000_000)?;
    assert_eq!(harness.last_rail, Some(Rail::Eddsa));
    harness.sync("eddsa-sender")?;
    harness.sync("recipient")?;
    harness.assert_utxos("eddsa-sender")?;
    harness.assert_utxos("recipient")?;

    harness.deposit_spl("eddsa-sender", 1_000_000_000)?;
    harness.transfer_single("eddsa-sender", "recipient", spl, 600_000_000)?;
    assert_eq!(harness.last_rail, Some(Rail::Eddsa));
    harness.sync("eddsa-sender")?;
    harness.sync("recipient")?;
    harness.assert_utxos("eddsa-sender")?;
    harness.assert_utxos("recipient")?;

    harness.consolidate("eddsa-sender", spl)?;
    assert_eq!(harness.last_rail, Some(Rail::Eddsa));
    harness.sync("eddsa-sender")?;
    harness.assert_utxos("eddsa-sender")?;

    harness.deposit_sol("eddsa-sender", 1_000_000_000)?;
    harness.consolidate("eddsa-sender", SOL_MINT)?;
    assert_eq!(harness.last_rail, Some(Rail::Eddsa));
    harness.sync("eddsa-sender")?;
    harness.assert_utxos("eddsa-sender")?;

    Ok(())
}

#[test]
#[serial]
fn p256_merge_covers_every_supported_input_count() -> Result<()> {
    let mut harness = LifecycleHarness::new()?;

    for count in 1..=8 {
        let name = format!("p256-owner-{count}");
        let p256_owner = harness
            .register_merge_owner(&name, true)
            .with_context(|| format!("register P256 merge owner for input count {count}"))?;
        for _ in 0..count {
            harness
                .deposit_sol(&name, 1_000_000_000)
                .with_context(|| format!("deposit P256 input for count {count}"))?;
        }
        harness
            .merge(&name, &p256_owner, SOL_MINT, count)
            .with_context(|| format!("merge {count} P256 inputs"))?;
        harness
            .assert_merged(&name)
            .with_context(|| format!("assert {count}-input P256 merge"))?;
    }

    Ok(())
}

#[test]
#[serial]
fn eddsa_merge_covers_every_supported_input_count() -> Result<()> {
    let mut harness = LifecycleHarness::new()?;
    let name = "eddsa-owner";
    harness
        .make_eddsa_actor(name)
        .context("create EdDSA merge owner")?;
    let eddsa_owner = harness
        .register_merge_owner(name, true)
        .context("register EdDSA merge owner")?;
    for count in 1..=8 {
        // An EdDSA actor must be the transaction payer, so all shapes share one
        // registered owner. Each successful merge leaves one output; add enough
        // deposits to bring the next operation to exactly `count` inputs.
        let deposits = if count == 1 { 1 } else { count - 1 };
        for _ in 0..deposits {
            harness
                .deposit_sol(name, 1_000_000_000)
                .with_context(|| format!("deposit EdDSA input for count {count}"))?;
        }
        harness
            .merge(name, &eddsa_owner, SOL_MINT, count)
            .with_context(|| format!("merge {count} EdDSA inputs"))?;
        harness
            .assert_merged(name)
            .with_context(|| format!("assert {count}-input EdDSA merge"))?;
    }
    Ok(())
}

#[test]
#[serial]
fn merge_rejects_an_owner_that_has_not_opted_in() -> Result<()> {
    let mut harness = LifecycleHarness::new()?;
    let disabled_owner = harness.register_merge_owner("disabled-owner", false)?;
    for _ in 0..3 {
        harness.deposit_sol("disabled-owner", 1_000_000_000)?;
    }
    harness.merge_expect_disabled("disabled-owner", &disabled_owner, SOL_MINT, 3)?;
    Ok(())
}

#[test]
#[serial]
fn eddsa_merge_rejects_an_owner_that_has_not_opted_in() -> Result<()> {
    let mut harness = LifecycleHarness::new()?;
    harness.make_eddsa_actor("disabled-eddsa-owner")?;
    let owner = harness.register_merge_owner("disabled-eddsa-owner", false)?;
    for _ in 0..3 {
        harness.deposit_sol("disabled-eddsa-owner", 1_000_000_000)?;
    }
    harness.merge_expect_disabled("disabled-eddsa-owner", &owner, SOL_MINT, 3)
}

/// A merge proof binds the owner's registered signing and viewing keys (read
/// from the `user_record`). Submitting a proof bound to one owner with a
/// different, also-merge-enabled owner's `user_record` must fail proof
/// verification: the program derives the owner public inputs from the passed
/// record, so they no longer match the proof.
#[test]
#[serial]
fn merge_rejects_a_proof_bound_to_a_foreign_user_record() -> Result<()> {
    let mut harness = LifecycleHarness::new()?;
    // Alice is the real merge owner: funded, merge-enabled, and the identity the
    // proof is bound to.
    let _alice = harness.register_merge_owner("alice", true)?;
    // Bob is a second merge-enabled owner whose registry record is substituted in.
    let bob = harness.register_merge_owner("bob", true)?;
    for _ in 0..3 {
        harness.deposit_sol("alice", 1_000_000_000)?;
    }
    harness.merge_expect_foreign_record_rejected("alice", &bob, SOL_MINT, 3)
}

#[test]
#[serial]
fn withdrawal_spends_inputs_and_preserves_wallet_consistency() -> Result<()> {
    let mut harness = LifecycleHarness::new()?;
    harness.make_eddsa_actor("sender")?;
    for _ in 0..2 {
        harness.deposit_sol("sender", 1_000_000_000)?;
    }
    harness.withdraw_sol("sender", 300_000_000)?;
    assert_eq!(harness.last_rail, Some(Rail::Eddsa));
    harness.sync("sender")?;
    harness.assert_utxos("sender")?;
    Ok(())
}

#[test]
#[serial]
fn p256_withdrawal_spends_inputs_and_preserves_wallet_consistency() -> Result<()> {
    let mut harness = LifecycleHarness::new()?;
    for _ in 0..2 {
        harness.deposit_sol("p256-sender", 1_000_000_000)?;
    }
    harness.withdraw_sol("p256-sender", 300_000_000)?;
    assert_eq!(harness.last_rail, Some(Rail::Eddsa));
    harness.sync("p256-sender")?;
    harness.assert_utxos("p256-sender")?;
    Ok(())
}

#[test]
#[serial]
fn randomized_mixed_asset_workload_preserves_conservation() -> Result<()> {
    let seed = std::env::var("ZOLANA_RANDOM_SEED")
        .ok()
        .map(|raw| {
            let raw = raw.trim();
            raw.strip_prefix("0x")
                .map_or_else(|| raw.parse(), |hex| u64::from_str_radix(hex, 16))
        })
        .transpose()?
        .unwrap_or_else(rand::random);
    let mut harness = LifecycleHarness::new()?;
    harness.run_random_workload(
        seed,
        Workload {
            target_txs: 50,
            num_actors: 8,
            num_spl: 3,
        },
    )
}
