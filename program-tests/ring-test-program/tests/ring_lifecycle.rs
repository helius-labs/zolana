//! Policy-ring lifecycle tests written as ordinary Rust programs.

use anyhow::Result;
use serial_test::serial;
use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_rpc_client::api::config::RpcTransactionConfig;
use solana_transaction_status_client_types::UiTransactionEncoding;
use zolana_client::Rpc;
use zolana_test_utils::ring::RingHarness;
use zolana_test_utils::test_validator_asserts::{fetch_account, token_amount};
use zolana_transaction::SOL_MINT;

fn spl_mint(harness: &RingHarness) -> Result<Address> {
    Ok(Address::new_from_array(
        harness.spl_asset()?.mint.to_bytes(),
    ))
}

#[test]
#[serial]
fn ring_config_admin_enforces_updates_rotation_and_authority() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;
    harness.assert_ring_config(true, false)?;

    harness.update_ring_config(false, true)?;
    harness.assert_ring_config(false, true)?;
    harness.rotate_ring_config_owner()?;
    harness.assert_ring_config(false, true)?;
    harness.update_ring_config(false, false)?;
    harness.assert_ring_config(false, false)?;
    harness.old_owner_update_rejected()?;
    harness.create_invalid_ring_authority_rejected()?;
    Ok(())
}

#[test]
#[serial]
fn proofless_ring_deposits_cover_sol_spl_and_wrong_signer() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;
    harness.ring_shield_sol("alice", 1_000_000)?;
    harness.assert_ring_deposited("alice", 1_000_000)?;
    harness.ring_shield_spl("bob", 500)?;
    harness.assert_ring_deposited("bob", 500)?;
    harness.ring_shield_wrong_signer_rejected()?;
    Ok(())
}

#[test]
#[serial]
fn eddsa_ring_transfer_updates_recipient_wallet() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;
    harness.make_payer_actor("alice")?;
    for _ in 0..2 {
        harness.ring_shield_sol("alice", 1_000_000_000)?;
    }
    harness.ring_transfer("alice", "bob", SOL_MINT, 300_000_000)?;
    harness.sync("bob")?;
    harness.assert_utxos("bob");
    Ok(())
}

#[test]
#[serial]
fn spl_ring_transfer_updates_recipient_wallet() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;
    harness.make_payer_actor("alice")?;
    for _ in 0..2 {
        harness.ring_shield_spl("alice", 400)?;
    }
    let mint = spl_mint(&harness)?;
    harness.ring_transfer("alice", "bob", mint, 300)?;
    harness.sync("bob")?;
    harness.assert_utxos("bob");
    harness.sync("alice")?;
    harness.assert_utxos("alice");
    Ok(())
}

#[test]
#[serial]
fn spl_ring_withdraw_credits_the_recipient_token_account() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;
    harness.make_payer_actor("alice")?;
    for _ in 0..2 {
        harness.ring_shield_spl("alice", 600)?;
    }
    let mint = spl_mint(&harness)?;
    let (_, recipient_token) = harness.ring_withdraw("alice", mint, 700)?;
    assert_eq!(
        token_amount(&fetch_account(&harness.rpc, &recipient_token)?),
        700,
        "withdrawn tokens"
    );
    assert_eq!(
        token_amount(&fetch_account(&harness.rpc, &harness.spl_asset()?.vault)?),
        500,
        "vault keeps the shielded remainder"
    );
    harness.sync("alice")?;
    harness.assert_utxos("alice");
    Ok(())
}

#[test]
#[serial]
fn mixed_asset_ring_transfer_returns_sol_change_beside_spl_change() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;
    harness.make_payer_actor("alice")?;
    harness.ring_shield_sol("alice", 1_000_000_000)?;
    harness.ring_shield_spl("alice", 800)?;
    let mint = spl_mint(&harness)?;
    harness.ring_transfer_mixed("alice", "bob", mint, 300)?;
    harness.sync("bob")?;
    harness.assert_utxos("bob");
    harness.sync("alice")?;
    harness.assert_utxos("alice");
    Ok(())
}

#[test]
#[serial]
fn spl_default_note_funds_an_eddsa_ring_transfer() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;
    harness.make_payer_actor("alice")?;
    harness.shield_default_spl("alice", 600)?;
    harness.ring_shield_spl("alice", 400)?;
    let mint = spl_mint(&harness)?;
    harness.ring_transfer("alice", "bob", mint, 900)?;
    harness.sync("bob")?;
    harness.assert_utxos("bob");
    Ok(())
}

/// Regenerate the `services/photon/tests/fixtures` transactions Photon's parser
/// replays: a real ring CPI (to prove it still finds the ring's `ring_config`
/// account) and a real registration (to prove it still reads the registry).
/// Ignored: it needs the localnet stack, while the fixtures it writes do not.
///
/// ```text
/// cargo test -p ring-test-program --test ring_lifecycle -- \
///     --ignored dump_ring_transact_fixture
/// ```
#[test]
#[serial]
#[ignore = "regenerates a committed fixture; needs the localnet stack"]
fn dump_ring_transact_fixture() -> Result<()> {
    let mut harness = RingHarness::new()?;
    let create_config = harness.create_enabled_ring_config()?;
    harness.make_payer_actor("alice")?;
    for _ in 0..2 {
        harness.ring_shield_sol("alice", 1_000_000_000)?;
    }
    let signature = harness.ring_transfer("alice", "bob", SOL_MINT, 300_000_000)?;

    // base64, matching what Photon's ingester requests -- the JSON encoding
    // yields a parsed message that `EncodedTransaction::decode` rejects.
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../services/photon/tests/fixtures");
    std::fs::create_dir_all(&fixtures)?;
    for (name, signature) in [
        ("ring_transact.json", signature),
        ("create_ring_config.json", create_config),
    ] {
        // base64, matching what Photon's ingester requests -- the JSON encoding
        // yields a parsed message that `EncodedTransaction::decode` rejects.
        let transaction = harness.rpc.client().get_transaction_with_config(
            &signature,
            RpcTransactionConfig {
                encoding: Some(UiTransactionEncoding::Base64),
                commitment: Some(CommitmentConfig::confirmed()),
                max_supported_transaction_version: Some(0),
            },
        )?;
        let path = fixtures.join(name);
        std::fs::write(&path, serde_json::to_vec_pretty(&transaction)?)?;
        println!("wrote {}", path.display());
    }
    Ok(())
}

// NOTE(pr164): PR164 removed the P256 ring-transfer rail
// (`ring_transfer_p256` is gone; only the eddsa rail remains), so the
// `p256_ring_transfer_updates_recipient_wallet` case was dropped.

/// INV-RING-TRANSACT-07: `ring_transact` does not require the ring's
/// `ring_authority_transact_is_enabled` flag — a valid ring transfer succeeds
/// end-to-end while the flag is 0 (the flag gates only
/// `ring_authority_transact`).
#[test]
#[serial]
fn ring_transact_succeeds_while_ring_authority_transact_is_disabled() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;
    harness.update_ring_config(false, false)?;
    harness.assert_ring_config(false, false)?;
    harness.make_payer_actor("alice")?;
    for _ in 0..2 {
        harness.ring_shield_sol("alice", 1_000_000_000)?;
    }
    harness.ring_transfer("alice", "bob", SOL_MINT, 300_000_000)?;
    harness.sync("bob")?;
    harness.assert_utxos("bob");
    Ok(())
}

#[test]
#[serial]
fn ring_merge_consolidates_inputs() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;
    for _ in 0..2 {
        harness.ring_shield_sol("gary", 1_000_000_000)?;
    }
    harness.merge_ring("gary", SOL_MINT, 2)?;
    harness.assert_merged_ring("gary")?;
    Ok(())
}

#[test]
#[serial]
fn ring_merge_nullifier_replay_is_rejected_atomically() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;
    for _ in 0..2 {
        harness.ring_shield_sol("merge-replay", 1_000_000_000)?;
    }
    harness.merge_ring_replay_rejected("merge-replay", SOL_MINT, 2)?;
    harness.assert_merged_ring("merge-replay")?;
    Ok(())
}

#[test]
#[serial]
fn ring_merge_rejects_a_proof_bound_to_another_ring() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;
    for _ in 0..2 {
        harness.ring_shield_sol("cross-ring-merge", 1_000_000_000)?;
    }
    harness.merge_ring_foreign_program_rejected("cross-ring-merge", SOL_MINT, 2)
}

#[test]
#[serial]
fn ring_merge_rejects_a_default_merge_proof() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;
    for _ in 0..2 {
        harness.shield_default_sol("cross-instruction-merge", 1_000_000_000)?;
    }
    harness.merge_transact_proof_replayed_as_ring_rejected("cross-instruction-merge", SOL_MINT, 2)
}

#[test]
#[serial]
fn ring_authority_transfer_reowns_a_utxo() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;
    harness.ring_shield_sol("henry", 1_000_000_000)?;
    harness.ring_authority_transfer("henry", "ivan", SOL_MINT)?;
    harness.sync("henry")?;
    harness.sync("ivan")?;
    harness.assert_utxos("henry");
    harness.assert_utxos("ivan");
    Ok(())
}

#[test]
#[serial]
fn ring_withdraw_credits_the_public_recipient() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;
    harness.make_payer_actor("alice")?;
    for _ in 0..2 {
        harness.ring_shield_sol("alice", 1_000_000_000)?;
    }
    let (_, recipient) = harness.ring_withdraw("alice", SOL_MINT, 250_000_000)?;
    let recipient = harness
        .rpc
        .get_account(Address::new_from_array(recipient.to_bytes()))?
        .expect("ring withdrawal recipient");
    assert_eq!(recipient.lamports, 250_000_000);
    Ok(())
}

#[test]
#[serial]
fn invalid_proofs_and_disabled_authority_are_atomic() -> Result<()> {
    let mut harness = RingHarness::new()?;
    harness.create_enabled_ring_config()?;
    harness.make_payer_actor("alice")?;
    for _ in 0..3 {
        harness.ring_shield_sol("alice", 1_000_000_000)?;
    }
    harness.ring_transfer_bad_proof("alice", "bob", SOL_MINT, 1)?;
    harness.merge_ring_bad_proof("alice", SOL_MINT, 2)?;

    harness.ring_shield_sol("jane", 1_000_000_000)?;
    harness.ring_authority_transfer_bad_proof("jane", SOL_MINT)?;
    harness.ring_shield_sol("kyle", 1_000_000_000)?;
    harness.ring_authority_transfer_disabled("kyle", SOL_MINT)?;
    Ok(())
}
