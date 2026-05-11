use pinocchio::{error::ProgramError, AccountView};
use zolana_interface::instruction::InsertAddressesData;

use crate::{error::ShieldedPoolError, instructions::loader::MutableAddressTreeAccounts};

pub fn verify<'a>(
    accounts: &'a [AccountView],
    data: &InsertAddressesData,
) -> Result<MutableAddressTreeAccounts<'a>, ProgramError> {
    if data.addresses.is_empty() {
        return Err(ShieldedPoolError::EmptyAddressBatch.into());
    }
    crate::instructions::loader::load_mutable_address_tree_accounts(accounts)
}
