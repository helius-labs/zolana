use pinocchio::{error::ProgramError, AccountView};
use zolana_interface::instruction::CreateAddressTreeData;

use crate::{error::ShieldedPoolError, instructions::loader::MutableAddressTreeAccounts};

pub fn verify<'a>(
    accounts: &'a [AccountView],
    data: &CreateAddressTreeData,
) -> Result<MutableAddressTreeAccounts<'a>, ProgramError> {
    if data.height == 0 || data.queue_capacity == 0 {
        return Err(ShieldedPoolError::InvalidAddressTreeConfig.into());
    }
    crate::instructions::loader::load_mutable_address_tree_accounts(accounts)
}
