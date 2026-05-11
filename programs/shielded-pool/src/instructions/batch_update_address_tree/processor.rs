use pinocchio::{AccountView, ProgramResult};
use zolana_interface::instruction::BatchUpdateAddressTreeData;

use super::verify::verify;
use crate::error::ShieldedPoolError;

pub fn process_batch_update_address_tree(
    accounts: &[AccountView],
    data: BatchUpdateAddressTreeData,
) -> ProgramResult {
    let verified = verify(accounts, &data)?;
    let _account_keys = (
        verified.signer.address(),
        verified.tree.address(),
        verified.queue.address(),
    );

    Err(ShieldedPoolError::AddressTreeMutationUnsupported.into())
}
