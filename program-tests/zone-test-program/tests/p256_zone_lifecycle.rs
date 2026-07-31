//! P256 zone transact lifecycle, ported from the retired scenario suite
//! `features/p256_zone_lifecycle.feature`: a P256 owner zone-shields, proves
//! the ZoneP256 rail through the Go prover server, and submits through the
//! zone fixture program to the shielded pool. This runs alongside, and does
//! not replace, the existing EdDSA zone lifecycle.

use anyhow::Result;
use serial_test::serial;
use zolana_test_utils::zone::ZoneHarness;
use zolana_transaction::SOL_MINT;

/// The feature's happy path plus its invalid-commitment negative: a corrupted
/// BSB22 commitment is rejected at the encoding check and leaves the owner's
/// UTXOs spendable for the real transfer.
#[test]
#[serial]
fn p256_zone_transfer_updates_recipient_wallet() -> Result<()> {
    let mut harness = ZoneHarness::new()?;
    harness.create_enabled_zone_config()?;
    harness.make_p256_actor("piper")?;
    for _ in 0..2 {
        harness.zone_shield_sol("piper", 1_000_000_000)?;
    }

    harness.zone_transfer_p256_bad_commitment_rejected(
        "piper", "riley", SOL_MINT, 300_000_000,
    )?;

    harness.zone_transfer_p256("piper", "riley", SOL_MINT, 300_000_000)?;
    harness.sync("riley")?;
    harness.assert_utxos("riley");
    Ok(())
}

/// Cross-rail grafting: a proof is only valid under the circuit selector it
/// was built for. A P256 proof under the ZoneEddsa selector fails pairing
/// (7008); an eddsa proof under ZoneP256 can carry no valid BSB22 commitment,
/// so it fails the encoding check first (7007).
#[test]
#[serial]
fn cross_rail_proof_grafting_is_rejected() -> Result<()> {
    let mut harness = ZoneHarness::new()?;
    harness.create_enabled_zone_config()?;
    harness.make_p256_actor("piper")?;
    for _ in 0..2 {
        harness.zone_shield_sol("piper", 1_000_000_000)?;
    }
    harness.make_payer_actor("alice")?;
    for _ in 0..2 {
        harness.zone_shield_sol("alice", 1_000_000_000)?;
    }

    harness.p256_proof_under_eddsa_selector_rejected("piper", "riley", SOL_MINT, 300_000_000)?;
    harness.eddsa_proof_under_p256_selector_rejected("alice", "riley", SOL_MINT, 300_000_000)?;
    Ok(())
}

/// A real default-zone P256 input exposes the owner's P256 pubkey x-coordinate
/// as `default_owner_tag` on the wire, bound into the public input: a wrong
/// tag fails pairing (7008), the correct tag succeeds.
#[test]
#[serial]
fn default_zone_p256_input_exposes_and_binds_owner_tag() -> Result<()> {
    let mut harness = ZoneHarness::new()?;
    harness.create_enabled_zone_config()?;
    harness.make_p256_actor("piper")?;
    for _ in 0..2 {
        harness.shield_default_sol("piper", 1_000_000_000)?;
    }

    harness.zone_transfer_p256_wrong_default_owner_tag_rejected(
        "piper", "riley", SOL_MINT, 300_000_000,
    )?;
    harness.zone_transfer_p256_default_input_exposes_owner_tag(
        "piper", "riley", SOL_MINT, 300_000_000,
    )?;
    harness.sync("riley")?;
    Ok(())
}
