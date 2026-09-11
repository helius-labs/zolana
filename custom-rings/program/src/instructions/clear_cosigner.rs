use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::{
        loader::{load_authorized_config, load_cosigner},
        shared::close_into,
    },
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

    load_authorized_config(program_id, config_account, authority)?;
    if load_cosigner(program_id, cosigner_account)?.is_none() {
        return Err(CustomRingError::InvalidCoSigner.into());
    }
    close_into(
        cosigner_account,
        rent_recipient,
        CustomRingError::InvalidCoSigner,
    )
}
