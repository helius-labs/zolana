//! Localnet + Photon lifecycle tests for the Squads ring P256 (keypair) rail:
//! `deposit` (tag 1) and `transact` withdrawal/transfer (tag 0). Every spend
//! routes through the `zolana-squads-client` backend's two-call P256 rail (probe,
//! client signs `sha256(private_tx_hash)`, `requestTransact`). The async
//! `execute_proposal` rail is not exercised here, because a background crank
//! cannot produce the in-circuit P256 owner signature a keypair spend requires.
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

use harness::SquadsKeypairHarness as Harness;

#[test]
#[serial]
fn sol_deposit_creates_a_ring_utxo() -> Result<()> {
    let mut harness = Harness::new()?;
    harness.create_viewing_key_account("alice")?;
    harness.deposit_sol("alice", 1_000_000)?;
    harness.assert_deposited("alice", 1_000_000)?;
    Ok(())
}

#[test]
#[serial]
fn spl_deposit_creates_a_ring_utxo() -> Result<()> {
    let mut harness = Harness::new()?;
    harness.ensure_spl_asset()?;
    harness.create_viewing_key_account("bob")?;
    harness.deposit_spl("bob", 500)?;
    harness.assert_deposited("bob", 500)?;
    Ok(())
}

#[test]
#[serial]
fn the_crank_consolidates_two_sol_deposits() -> Result<()> {
    let mut harness = Harness::new()?;
    harness.create_viewing_key_account("alice")?;
    harness.deposit_sol("alice", 3_000_000_000)?;
    harness.deposit_sol("alice", 2_000_000_000)?;
    harness.assert_consolidated_sol("alice", 5_000_000_000)?;
    Ok(())
}

#[test]
#[serial]
fn the_crank_consolidates_a_transfer_recipients_credits() -> Result<()> {
    let mut harness = Harness::new()?;
    harness.create_viewing_key_account("sam")?;
    harness.create_viewing_key_account("rachel")?;
    harness.deposit_sol("rachel", 1_000_000_000)?;
    harness.transfer_sol("sam", 2_000_000_000, "rachel", 3_000_000_000, 2_000_000_000)?;
    harness.assert_consolidated_sol("rachel", 3_000_000_000)?;
    Ok(())
}

#[test]
#[serial]
fn a_sol_transfer_credits_the_recipient_and_returns_change() -> Result<()> {
    let mut harness = Harness::new()?;
    harness.create_viewing_key_account("wanda")?;
    harness.create_viewing_key_account("wendy")?;
    harness.transfer_sol(
        "wanda",
        1_000_000_000,
        "wendy",
        3_000_000_000,
        2_000_000_000,
    )?;
    harness.assert_transfer_recipient("wendy", 1_000_000_000)?;
    harness.assert_transfer_change("wanda", 4_000_000_000)?;
    Ok(())
}

#[test]
#[serial]
fn a_sol_withdrawal_leaves_the_pool() -> Result<()> {
    let mut harness = Harness::new()?;
    harness.create_viewing_key_account("wanda")?;
    harness.deposit_sol("wanda", 5_000_000_000)?;
    harness.assert_deposited("wanda", 5_000_000_000)?;
    harness.withdraw_sol("wanda", 2_000_000_000)?;
    harness.assert_withdrew("wanda", 2_000_000_000)?;
    Ok(())
}

#[test]
#[serial]
fn an_spl_withdrawal_leaves_the_pool() -> Result<()> {
    let mut harness = Harness::new()?;
    harness.ensure_spl_asset()?;
    harness.create_viewing_key_account("walt")?;
    harness.deposit_spl("walt", 1_000)?;
    harness.assert_deposited("walt", 1_000)?;
    harness.withdraw_spl("walt", 400)?;
    harness.assert_withdrew("walt", 400)?;
    Ok(())
}
