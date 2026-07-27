//! Policy-zone lifecycle tests written as ordinary Rust programs.

mod actions;
mod actor;
mod harness;
mod localnet;
mod support;

use anyhow::Result;
use serial_test::serial;
use solana_address::Address;
use zolana_client::Rpc;
use zolana_transaction::SOL_MINT;

use harness::ZoneHarness;
use support::Variant;

#[test]
#[serial]
fn zone_config_admin_enforces_updates_rotation_and_authority() -> Result<()> {
    let mut harness = ZoneHarness::new()?;
    harness.create_enabled_zone_config()?;
    harness.assert_zone_config(true)?;

    harness.update_zone_config(false)?;
    harness.assert_zone_config(false)?;
    harness.rotate_zone_config_owner()?;
    harness.assert_zone_config(false)?;
    harness.old_owner_update_rejected()?;
    harness.create_invalid_zone_authority_rejected()?;
    Ok(())
}

#[test]
#[serial]
fn proofless_zone_deposits_cover_sol_spl_and_wrong_signer() -> Result<()> {
    let mut harness = ZoneHarness::new()?;
    harness.create_enabled_zone_config()?;
    harness.zone_shield_sol("alice", 1_000_000)?;
    harness.assert_zone_deposited("alice", 1_000_000)?;
    harness.zone_shield_spl("bob", 500)?;
    harness.assert_zone_deposited("bob", 500)?;
    harness.zone_shield_wrong_signer_rejected()?;
    Ok(())
}

#[test]
#[serial]
fn eddsa_zone_transfer_updates_recipient_wallet() -> Result<()> {
    let mut harness = ZoneHarness::new()?;
    harness.create_enabled_zone_config()?;
    harness.make_eddsa_actor("alice")?;
    for _ in 0..2 {
        harness.zone_shield_sol("alice", 1_000_000_000)?;
    }
    harness.zone_transfer("alice", "bob", SOL_MINT, 300_000_000)?;
    assert_eq!(harness.last_rail, Some(Variant::Eddsa));
    harness.sync("bob")?;
    harness.assert_utxos("bob")?;
    Ok(())
}

// NOTE(pr164): PR164 removed the P256 zone-transfer rail
// (`zone_transfer_p256` is gone; `Variant::P256` now errors), so the
// `p256_zone_transfer_updates_recipient_wallet` case was dropped.

/// INV-ZONE-TRANSACT-07: `zone_transact` does not require the zone's
/// `zone_authority_transact_is_enabled` flag — a valid zone transfer succeeds
/// end-to-end while the flag is 0 (the flag gates only
/// `zone_authority_transact`).
#[test]
#[serial]
fn zone_transact_succeeds_while_zone_authority_transact_is_disabled() -> Result<()> {
    let mut harness = ZoneHarness::new()?;
    harness.create_enabled_zone_config()?;
    harness.update_zone_config(false)?;
    harness.assert_zone_config(false)?;
    harness.make_eddsa_actor("alice")?;
    for _ in 0..2 {
        harness.zone_shield_sol("alice", 1_000_000_000)?;
    }
    harness.zone_transfer("alice", "bob", SOL_MINT, 300_000_000)?;
    assert_eq!(harness.last_rail, Some(Variant::Eddsa));
    harness.sync("bob")?;
    harness.assert_utxos("bob")?;
    Ok(())
}

#[test]
#[serial]
fn zone_merge_consolidates_inputs() -> Result<()> {
    let mut harness = ZoneHarness::new()?;
    harness.create_enabled_zone_config()?;
    for _ in 0..2 {
        harness.zone_shield_sol("gary", 1_000_000_000)?;
    }
    harness.merge_zone("gary", SOL_MINT, 2)?;
    harness.assert_merged_zone("gary")?;
    Ok(())
}

#[test]
#[serial]
fn zone_merge_view_tag_replay_is_rejected_atomically() -> Result<()> {
    let mut harness = ZoneHarness::new()?;
    harness.create_enabled_zone_config()?;
    for _ in 0..2 {
        harness.zone_shield_sol("merge-replay", 1_000_000_000)?;
    }
    harness.merge_zone_replay_rejected("merge-replay", SOL_MINT, 2)?;
    harness.assert_merged_zone("merge-replay")?;
    Ok(())
}

#[test]
#[serial]
fn zone_merge_rejects_a_proof_bound_to_another_zone() -> Result<()> {
    let mut harness = ZoneHarness::new()?;
    harness.create_enabled_zone_config()?;
    for _ in 0..2 {
        harness.zone_shield_sol("cross-zone-merge", 1_000_000_000)?;
    }
    harness.merge_zone_foreign_program_rejected("cross-zone-merge", SOL_MINT, 2)
}

#[test]
#[serial]
fn zone_merge_rejects_default_shielded_utxos() -> Result<()> {
    let mut harness = ZoneHarness::new()?;
    harness.create_enabled_zone_config()?;
    for _ in 0..2 {
        harness.shield_default_sol("cross-instruction-merge", 1_000_000_000)?;
    }
    harness.default_shielded_utxos_zone_merge_unprovable("cross-instruction-merge", SOL_MINT, 2)
}

#[test]
#[serial]
fn zone_authority_transfer_reowns_a_utxo() -> Result<()> {
    let mut harness = ZoneHarness::new()?;
    harness.create_enabled_zone_config()?;
    harness.zone_shield_sol("henry", 1_000_000_000)?;
    harness.zone_authority_transfer("henry", "ivan", SOL_MINT)?;
    Ok(())
}

#[test]
#[serial]
fn zone_withdraw_credits_the_public_recipient() -> Result<()> {
    let mut harness = ZoneHarness::new()?;
    harness.create_enabled_zone_config()?;
    harness.make_eddsa_actor("alice")?;
    for _ in 0..2 {
        harness.zone_shield_sol("alice", 1_000_000_000)?;
    }
    let (_, recipient) = harness.zone_withdraw("alice", SOL_MINT, 250_000_000)?;
    let recipient = harness
        .rpc
        .get_account(Address::new_from_array(recipient.to_bytes()))?
        .expect("zone withdrawal recipient");
    assert_eq!(recipient.lamports, 250_000_000);
    Ok(())
}

#[test]
#[serial]
fn invalid_proofs_and_disabled_authority_are_atomic() -> Result<()> {
    let mut harness = ZoneHarness::new()?;
    harness.create_enabled_zone_config()?;
    harness.make_eddsa_actor("alice")?;
    for _ in 0..3 {
        harness.zone_shield_sol("alice", 1_000_000_000)?;
    }
    harness.zone_transfer_bad_proof("alice", "bob", SOL_MINT, 1)?;
    harness.merge_zone_bad_proof("alice", SOL_MINT, 2)?;

    harness.zone_shield_sol("jane", 1_000_000_000)?;
    harness.zone_authority_transfer_bad_proof("jane", SOL_MINT)?;
    harness.zone_shield_sol("kyle", 1_000_000_000)?;
    harness.zone_authority_transfer_disabled("kyle", SOL_MINT)?;
    Ok(())
}
