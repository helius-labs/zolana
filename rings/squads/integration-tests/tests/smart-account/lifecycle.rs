//! Localnet + Photon lifecycle tests for the Squads ring driven by a Squads
//! SMART ACCOUNT, routed through the mock backend `zolana-squads-client`.
//!
//! A real smart-account vault is the executing party and UTXO owner: it executes
//! `deposit` (tag 1, client-built) and creates and owns the async proposal
//! (`create_proposal`, tag 11, wrapped in `executeTransactionSyncV2`). Everything
//! else flows through the backend, which holds the auditor key. Viewing key
//! accounts are created at runtime, sync transfer and withdrawal are built by
//! `request_transact` on the smart-account rail, async proposals are settled by
//! the backend's background crank, and balances are read via `get_balances`. The
//! ring `owner` identity is the vault's `owner_pk_field`.
//!
//! `Harness::new` restarts the validator and Photon, so the protocol-config
//! singleton is never shared and these must run serially.

mod actions;
mod deposit_action;
mod fixture;
mod harness;
mod localnet;

use anyhow::Result;
use serial_test::serial;
use zolana_squads_client::SOL_ASSET_ID;

use harness::SquadsSmartAccountHarness as Harness;

/// Matches the registry id the SPL actions register their mint under.
const SPL_ASSET_ID: u64 = 2;

#[test]
#[serial]
fn sol_deposit_creates_a_ring_utxo_the_auditor_can_read() -> Result<()> {
    let mut harness = Harness::new()?;
    harness.ensure_viewing_key_account("alice")?;
    harness.deposit_sol("alice", 1_000_000)?;
    harness.assert_deposited("alice", 1_000_000)?;
    harness.assert_backend_balance("alice", SOL_ASSET_ID, 1_000_000)?;
    Ok(())
}

#[test]
#[serial]
fn spl_deposit_creates_a_ring_utxo_the_auditor_can_read() -> Result<()> {
    let mut harness = Harness::new()?;
    harness.ensure_spl_asset()?;
    harness.ensure_viewing_key_account("bob")?;
    harness.deposit_spl("bob", 500)?;
    harness.assert_deposited("bob", 500)?;
    harness.assert_backend_balance("bob", SPL_ASSET_ID, 500)?;
    Ok(())
}

#[test]
#[serial]
fn two_deposits_auto_merge_into_one_utxo() -> Result<()> {
    let mut harness = Harness::new()?;
    harness.ensure_viewing_key_account("alice")?;
    harness.deposit_sol("alice", 1_000_000_000)?;
    harness.deposit_sol("alice", 2_000_000_000)?;
    harness.wait_for_consolidated("alice", SOL_ASSET_ID, 3_000_000_000)?;
    Ok(())
}

#[test]
#[serial]
fn a_recipients_transferred_utxos_auto_merge() -> Result<()> {
    let mut harness = Harness::new()?;
    harness.ensure_viewing_key_account("wanda")?;
    harness.ensure_viewing_key_account("wendy")?;
    harness.transfer_sol(
        "wanda",
        1_000_000_000,
        "wendy",
        3_000_000_000,
        2_000_000_000,
    )?;
    harness.transfer_sol(
        "wanda",
        1_000_000_000,
        "wendy",
        3_000_000_000,
        2_000_000_000,
    )?;
    harness.wait_for_consolidated("wendy", SOL_ASSET_ID, 2_000_000_000)?;
    Ok(())
}

#[test]
#[serial]
fn a_sync_sol_transfer_moves_the_shielded_balance() -> Result<()> {
    let mut harness = Harness::new()?;
    harness.ensure_viewing_key_account("wanda")?;
    harness.ensure_viewing_key_account("wendy")?;
    harness.transfer_sol(
        "wanda",
        1_000_000_000,
        "wendy",
        3_000_000_000,
        2_000_000_000,
    )?;
    harness.assert_backend_balance("wendy", SOL_ASSET_ID, 1_000_000_000)?;
    harness.assert_backend_balance("wanda", SOL_ASSET_ID, 4_000_000_000)?;
    Ok(())
}

#[test]
#[serial]
fn the_crank_settles_a_transfer_proposal() -> Result<()> {
    let mut harness = Harness::new()?;
    harness.ensure_viewing_key_account("wanda")?;
    harness.ensure_viewing_key_account("wendy")?;
    harness.create_transfer_proposal(
        "wanda",
        1_000_000_000,
        "wendy",
        3_000_000_000,
        2_000_000_000,
    )?;
    let proposal = harness
        .pending_proposal
        .expect("create_transfer_proposal must record its proposal");
    harness.wait_for_proposal_settled(proposal)?;
    harness.assert_backend_balance("wendy", SOL_ASSET_ID, 1_000_000_000)?;
    harness.assert_backend_balance("wanda", SOL_ASSET_ID, 4_000_000_000)?;
    Ok(())
}

#[test]
#[serial]
fn a_sync_sol_withdrawal_leaves_the_pool() -> Result<()> {
    let mut harness = Harness::new()?;
    harness.ensure_viewing_key_account("wanda")?;
    harness.deposit_sol("wanda", 5_000_000_000)?;
    harness.assert_deposited("wanda", 5_000_000_000)?;
    harness.withdraw_sol("wanda", 2_000_000_000)?;
    harness.assert_withdrew("wanda", 2_000_000_000)?;
    harness.assert_backend_balance("wanda", SOL_ASSET_ID, 3_000_000_000)?;
    Ok(())
}

#[test]
#[serial]
fn the_crank_settles_a_withdrawal_proposal() -> Result<()> {
    let mut harness = Harness::new()?;
    harness.ensure_viewing_key_account("wade")?;
    harness.deposit_sol("wade", 5_000_000_000)?;
    harness.assert_deposited("wade", 5_000_000_000)?;
    harness.create_withdrawal_proposal("wade")?;
    let proposal = harness
        .pending_proposal
        .expect("create_withdrawal_proposal must record its proposal");
    harness.wait_for_proposal_settled(proposal)?;
    harness.assert_backend_balance("wade", SOL_ASSET_ID, 3_000_000_000)?;
    Ok(())
}

#[test]
#[serial]
fn a_sync_spl_withdrawal_leaves_the_pool() -> Result<()> {
    let mut harness = Harness::new()?;
    harness.ensure_spl_asset()?;
    harness.ensure_viewing_key_account("walt")?;
    harness.deposit_spl("walt", 1_000)?;
    harness.assert_deposited("walt", 1_000)?;
    harness.withdraw_spl("walt", 400)?;
    harness.assert_withdrew("walt", 400)?;
    Ok(())
}
