//! A hidden Ed25519 owner ring-shields, proves the AnonymousRingEddsa rail
//! through the Go prover server, and submits through the ring fixture program
//! to the shielded pool. This runs alongside, and does not replace, the
//! existing EdDSA ring lifecycle.

use anyhow::Result;
use serial_test::serial;
use spr_test_utils::ring::RingHarness;
use spr_transaction::SOL_MINT;

/// The feature's happy path plus its invalid-commitment negative: a corrupted
/// BSB22 commitment is rejected at the encoding check and leaves the owner's
/// UTXOs spendable for the real transfer.
#[test]
#[serial]
fn anonymous_ring_transfer_updates_recipient_wallet() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;
    harness.make_anonymous_actor("piper")?;
    for _ in 0..2 {
        harness.ring_shield_sol("piper", 1_000_000_000)?;
    }

    harness.ring_transfer_anonymous_bad_commitment_rejected(
        "piper",
        "riley",
        SOL_MINT,
        300_000_000,
    )?;

    harness.ring_transfer_anonymous("piper", "riley", SOL_MINT, 300_000_000)?;
    harness.sync("riley")?;
    harness.assert_utxos("riley");
    Ok(())
}

/// Cross-rail grafting: a proof is only valid under the circuit selector it
/// was built for. An anonymous proof under the ConfidentialRingEddsa selector fails pairing
/// (7008); an eddsa proof under AnonymousRingEddsa can carry no valid BSB22 commitment —
/// a zeroed one decodes as the point at infinity, so it also fails at pairing
/// (7008), while garbage bytes fail at encoding (7007, see the bad-commitment
/// leg of the lifecycle test).
#[test]
#[serial]
fn cross_rail_proof_grafting_is_rejected() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;
    harness.make_anonymous_actor("piper")?;
    for _ in 0..2 {
        harness.ring_shield_sol("piper", 1_000_000_000)?;
    }
    harness.make_payer_actor("alice")?;
    for _ in 0..2 {
        harness.ring_shield_sol("alice", 1_000_000_000)?;
    }

    harness.anonymous_proof_under_eddsa_selector_rejected(
        "piper",
        "riley",
        SOL_MINT,
        300_000_000,
    )?;
    harness.eddsa_proof_under_anonymous_selector_rejected(
        "alice",
        "riley",
        SOL_MINT,
        300_000_000,
    )?;
    Ok(())
}

/// A real default-ring hidden-owner input exposes the owner's Ed25519 key
/// as `default_owner_tag` on the wire, bound into the public input: a wrong
/// tag fails pairing (7008), the correct tag succeeds.
#[test]
#[serial]
fn default_ring_hidden_input_exposes_and_binds_owner_tag() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;
    harness.make_anonymous_actor("piper")?;
    for _ in 0..2 {
        harness.shield_default_sol("piper", 1_000_000_000)?;
    }

    harness.ring_transfer_anonymous_wrong_default_owner_tag_rejected(
        "piper",
        "riley",
        SOL_MINT,
        300_000_000,
    )?;
    harness.ring_transfer_anonymous_default_input_exposes_owner_tag(
        "piper",
        "riley",
        SOL_MINT,
        300_000_000,
    )?;
    harness.sync("riley")?;
    Ok(())
}
