use pinocchio::{
    address::address_eq,
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use wincode::{SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;

use crate::{error::CustomRingError, instructions::loader::load_config, state::TRANSACT_APPROVAL};

pub const APPROVAL_PDA_SEED: &[u8] = b"approval";
/// `[discriminator, bump]`. The bump is stored so `transact` re-derives the
/// address with one `create_program_address` instead of a bump search.
pub const APPROVAL_SIZE: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct ApproveTransactIxData {
    /// The `private_tx_hash` of the transact being approved. It commits to the
    /// inputs, outputs and every settlement leg, so an approval cannot be
    /// re-used for a different transfer.
    pub private_tx_hash: [u8; 32],
}

/// The approver signs off one transact by creating its approval account,
/// `[b"approval", private_tx_hash]`. `transact` consumes it. Accounts
/// `[approver(s), payer(w,s), config, approval(w), system_program]`.
#[inline(never)]
pub fn process_approve_transact_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ApproveTransactIxData { private_tx_hash } =
        wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;

    let mut iter = AccountIterator::new(accounts);
    let approver = iter.next_signer("approver")?;
    let payer = iter.next_signer_mut("payer")?;
    let config_account = iter.next_account("config")?;
    let approval = iter.next_mut("approval")?;
    let system_program = iter.next_account("system_program")?;

    if !pinocchio_system::check_id(system_program.address()) {
        return Err(CustomRingError::InvalidSystemProgram.into());
    }
    {
        let config = load_config(config_account)?;
        match config.approver() {
            Some(configured) if address_eq(configured, approver.address()) => {}
            _ => return Err(CustomRingError::UnauthorizedApprover.into()),
        }
    }
    let bump = find_approval_bump(approval.address(), &private_tx_hash)?;
    if approval.data_len() != 0 {
        return Err(CustomRingError::InvalidApproval.into());
    }

    let bump_seed = [bump];
    let seeds = [
        Seed::from(APPROVAL_PDA_SEED),
        Seed::from(private_tx_hash.as_ref()),
        Seed::from(bump_seed.as_ref()),
    ];
    // Handles the hot path (no lamports) and the cold path (lamports donated to
    // the address to make a bare `CreateAccount` fail).
    pinocchio_system::create_account_with_minimum_balance_signed(
        approval,
        APPROVAL_SIZE,
        &crate::ID,
        payer,
        None,
        &[Signer::from(seeds.as_ref())],
    )?;
    let mut data = approval
        .try_borrow_mut()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;
    data.copy_from_slice(&[TRANSACT_APPROVAL, bump]);
    Ok(())
}

/// The approver takes an approval back before it is spent; the account's
/// lamports go to `rent_recipient`. Accounts `[approver(s), rent_recipient(w),
/// config, approval(w)]`; data `ApproveTransactIxData`.
#[inline(never)]
pub fn process_revoke_approval_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ApproveTransactIxData { private_tx_hash } =
        wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;

    let mut iter = AccountIterator::new(accounts);
    let approver = iter.next_signer("approver")?;
    let rent_recipient = iter.next_mut("rent_recipient")?;
    let config_account = iter.next_account("config")?;
    let approval = iter.next_mut("approval")?;

    {
        let config = load_config(config_account)?;
        match config.approver() {
            Some(configured) if address_eq(configured, approver.address()) => {}
            _ => return Err(CustomRingError::UnauthorizedApprover.into()),
        }
    }
    if !approval.owned_by(&crate::ID) {
        return Err(CustomRingError::InvalidApproval.into());
    }
    check_approval(approval, &private_tx_hash)?;
    rent_recipient.set_lamports(
        rent_recipient
            .lamports()
            .checked_add(approval.lamports())
            .ok_or(ProgramError::ArithmeticOverflow)?,
    );
    approval.set_lamports(0);
    approval.close()
}

/// The approval account of `private_tx_hash` must be the canonical PDA. Fails
/// closed on any other address.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn find_approval_bump(approval: &Address, private_tx_hash: &[u8; 32]) -> Result<u8, ProgramError> {
    let (derived, bump) =
        Address::find_program_address(&[APPROVAL_PDA_SEED, private_tx_hash], &crate::ID);
    if !address_eq(approval, &derived) {
        return Err(CustomRingError::InvalidApproval.into());
    }
    Ok(bump)
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
fn find_approval_bump(
    _approval: &Address,
    _private_tx_hash: &[u8; 32],
) -> Result<u8, ProgramError> {
    unimplemented!("approval PDA derivation requires Solana runtime syscalls")
}

/// `approval` must be the approval account of `private_tx_hash`: this
/// program's, carrying the discriminator, at the address its stored bump
/// derives. One `create_program_address` instead of a bump search.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pub fn check_approval(approval: &AccountView, private_tx_hash: &[u8; 32]) -> ProgramResult {
    let bump = {
        let data = approval
            .try_borrow()
            .map_err(|_| ProgramError::AccountBorrowFailed)?;
        match *data {
            [TRANSACT_APPROVAL, bump] => bump,
            _ => return Err(CustomRingError::InvalidApproval.into()),
        }
    };
    let derived =
        Address::create_program_address(&[APPROVAL_PDA_SEED, private_tx_hash, &[bump]], &crate::ID)
            .map_err(|_| CustomRingError::InvalidApproval)?;
    if !address_eq(approval.address(), &derived) {
        return Err(CustomRingError::InvalidApproval.into());
    }
    Ok(())
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
pub fn check_approval(_approval: &AccountView, _private_tx_hash: &[u8; 32]) -> ProgramResult {
    unimplemented!("approval PDA derivation requires Solana runtime syscalls")
}
