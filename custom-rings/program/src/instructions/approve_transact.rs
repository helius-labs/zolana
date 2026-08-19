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
/// One discriminator byte; the address already binds the transaction.
pub const APPROVAL_SIZE: usize = 1;

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
        if !config.has_approver() || !address_eq(&config.approver, approver.address()) {
            return Err(CustomRingError::UnauthorizedApprover.into());
        }
    }
    let bump = verify_approval_pda(approval.address(), &private_tx_hash)?;
    if approval.data_len() != 0 {
        return Err(CustomRingError::InvalidApproval.into());
    }

    let bump_seed = [bump];
    let seeds = [
        Seed::from(APPROVAL_PDA_SEED),
        Seed::from(private_tx_hash.as_ref()),
        Seed::from(bump_seed.as_ref()),
    ];
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
    data[0] = TRANSACT_APPROVAL;
    Ok(())
}

/// The approval account of `private_tx_hash` must be the canonical PDA. Fails
/// closed on any other address.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pub fn verify_approval_pda(
    approval: &Address,
    private_tx_hash: &[u8; 32],
) -> Result<u8, ProgramError> {
    let (derived, bump) =
        Address::find_program_address(&[APPROVAL_PDA_SEED, private_tx_hash], &crate::ID);
    if !address_eq(approval, &derived) {
        return Err(CustomRingError::InvalidApproval.into());
    }
    Ok(bump)
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
pub fn verify_approval_pda(
    _approval: &Address,
    _private_tx_hash: &[u8; 32],
) -> Result<u8, ProgramError> {
    unimplemented!("approval PDA derivation requires Solana runtime syscalls")
}
