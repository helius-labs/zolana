use pinocchio::{error::ProgramError, AccountView};
use zolana_interface::instruction::BatchUpdateAddressTreeData;

use crate::{error::ShieldedPoolError, instructions::loader::MutableAddressTreeAccounts};

pub fn verify<'a>(
    accounts: &'a [AccountView],
    data: &BatchUpdateAddressTreeData,
) -> Result<MutableAddressTreeAccounts<'a>, ProgramError> {
    if data.new_root == [0u8; 32] {
        return Err(ShieldedPoolError::EmptyBatchUpdateRoot.into());
    }
    crate::instructions::loader::load_mutable_address_tree_accounts(accounts)
}
