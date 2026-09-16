use custom_ring_interface::Delegate;
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::{
        loader::{load_delegate, UpgradeAuthorityCheck},
        shared::PdaCreate,
    },
    state::DelegateInitParams,
};

#[inline(never)]
pub fn process_set_delegate_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let delegate: [u8; 32] = data
        .try_into()
        .map_err(|_| CustomRingError::InvalidInstructionData)?;
    if delegate == [0; 32] {
        return Err(CustomRingError::InvalidDelegate.into());
    }

    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let delegate_account = iter.next_mut("delegate_pda")?;
    let system_program = iter.next_account("system_program")?;
    let program = iter.next_account("program")?;
    let program_data = iter.next_account("program_data")?;

    // 1. Only the upgrade authority may install a delegate, separate from
    // auditor key ownership.
    if !pinocchio_system::check_id(system_program.address()) {
        return Err(CustomRingError::InvalidSystemProgram.into());
    }
    UpgradeAuthorityCheck {
        program_id,
        authority,
        program,
        program_data,
    }
    .verify()?;
    // 2. Refuse replacement, permanence holds for the instructions in the
    // deployed binary.
    if load_delegate(program_id, delegate_account)?.is_some() {
        return Err(CustomRingError::DelegateAlreadySet.into());
    }

    // 3. Store the Solana signer at the canonical delegate PDA.
    let bump = PdaCreate {
        program_id,
        payer,
        seeds: &[Delegate::SEED],
        mismatch: CustomRingError::InvalidDelegate,
    }
    .create::<Delegate>(delegate_account)?;
    DelegateInitParams {
        delegate: Address::new_from_array(delegate),
        bump,
    }
    .init(delegate_account)
}
