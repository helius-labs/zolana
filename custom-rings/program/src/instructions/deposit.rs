use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::instructions::{
    loader::{load_config, validate_spp_program},
    policy::check_deposit,
    shared::cpi_spp_signed,
};

/// Proofless forwarder for SPP `RING_DEPOSIT`.
///
/// Deposit amounts are public on-chain, so the ring has no statement to prove
/// here. It checks the asset policy and lends its `ring_auth` signature.
/// Accounts `[config, <SPP ring deposit accounts>]`. `data` still carries the
/// leading tag byte because the client builds the instruction with the
/// interface's `RingDeposit` builder, which already emits SPP's tag 14 and lays
/// the accounts out exactly as SPP's deposit loader expects, so the forward is
/// verbatim and nothing is re-tagged.
#[inline(never)]
pub fn process_deposit_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let config_account = iter.next_account("config")?;
    let spp_accounts = iter.remaining()?;
    validate_spp_program(spp_accounts)?;
    {
        let config = load_config(config_account)?;
        check_deposit(&config, spp_accounts, data)?;
    }
    cpi_spp_signed(spp_accounts, data)
}
