use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::loader::{load_authorized_config, load_cosigner},
};

#[inline(never)]
pub fn process_clear_cosigner_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    if !data.is_empty() {
        return Err(CustomRingError::InvalidInstructionData.into());
    }

    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config_account = iter.next_account("config")?;
    let cosigner_account = iter.next_mut("cosigner")?;
    let rent_recipient = iter.next_mut("rent_recipient")?;
    if cosigner_account.address() == rent_recipient.address() {
        return Err(CustomRingError::InvalidCoSigner.into());
    }

    load_authorized_config(program_id, config_account, authority)?;
    if load_cosigner(program_id, cosigner_account)?.is_none() {
        return Err(CustomRingError::InvalidCoSigner.into());
    }

    let refund = rent_recipient
        .lamports()
        .checked_add(cosigner_account.lamports())
        .ok_or(ProgramError::ArithmeticOverflow)?;
    rent_recipient.set_lamports(refund);
    cosigner_account.set_lamports(0);
    cosigner_account.close()
}
