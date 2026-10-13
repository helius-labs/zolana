//! RingP256 transact lifecycle: an owner whose Ed25519 signature is verified
//! inside the proof ring-shields, proves the RingP256 rail
//! (`transfer-p256-ring`) through the Go prover server, and submits through
//! the ring fixture program to the shielded pool while the harness payer
//! pays. This runs alongside, and does not replace, the existing EdDSA ring
//! lifecycle, where the owner signs the Solana transaction.

use anyhow::Result;
use serial_test::serial;
use zolana_test_utils::ring::RingHarness;
use zolana_transaction::SOL_MINT;

/// The feature's happy path plus its invalid-commitment negative: a corrupted
/// BSB22 commitment is rejected at the encoding check and leaves the owner's
/// UTXOs spendable for the real transfer.
#[test]
#[serial]
fn p256_ring_transfer_updates_recipient_wallet() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;
    harness.make_ring_signer_actor("piper")?;
    for _ in 0..2 {
        harness.ring_shield_sol("piper", 1_000_000_000)?;
    }

    harness.ring_transfer_p256_bad_commitment_rejected("piper", "riley", SOL_MINT, 300_000_000)?;

    harness.ring_transfer_p256("piper", "riley", SOL_MINT, 300_000_000)?;
    harness.sync("riley")?;
    harness.assert_utxos("riley");
    Ok(())
}

/// Cross-rail grafting: a proof is only valid under the circuit selector it
/// was built for. A RingP256 proof under the RingEddsa selector fails pairing
/// (7008); an eddsa proof under RingP256 can carry no valid BSB22 commitment —
/// a zeroed one decodes as the point at infinity, so it also fails at pairing
/// (7008), while garbage bytes fail at encoding (7007, see the bad-commitment
/// leg of the lifecycle test).
#[test]
#[serial]
fn cross_rail_proof_grafting_is_rejected() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;
    harness.make_ring_signer_actor("piper")?;
    for _ in 0..2 {
        harness.ring_shield_sol("piper", 1_000_000_000)?;
    }
    harness.make_payer_actor("alice")?;
    for _ in 0..2 {
        harness.ring_shield_sol("alice", 1_000_000_000)?;
    }

    harness.p256_proof_under_eddsa_selector_rejected("piper", "riley", SOL_MINT, 300_000_000)?;
    harness.eddsa_proof_under_p256_selector_rejected("alice", "riley", SOL_MINT, 300_000_000)?;
    Ok(())
}

/// A real default-ring input of the in-circuit signer exposes its Ed25519
/// public key as `default_owner_tag` on the wire, bound into the public input:
/// a wrong tag fails pairing (7008), the correct tag succeeds.
#[test]
#[serial]
fn default_ring_p256_input_exposes_and_binds_owner_tag() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;
    harness.make_ring_signer_actor("piper")?;
    for _ in 0..2 {
        harness.shield_default_sol("piper", 1_000_000_000)?;
    }

    harness.ring_transfer_p256_wrong_default_owner_tag_rejected(
        "piper",
        "riley",
        SOL_MINT,
        300_000_000,
    )?;
    harness.ring_transfer_p256_default_input_exposes_owner_tag(
        "piper",
        "riley",
        SOL_MINT,
        300_000_000,
    )?;
    harness.sync("riley")?;
    Ok(())
}
