use pinocchio::{AccountView, ProgramResult};
use zolana_interface::instruction::CreateAddressTreeData;

use super::{init::batched_tree_params, verify::verify};
use crate::error::ShieldedPoolError;

pub fn process_create_address_tree(
    accounts: &[AccountView],
    data: CreateAddressTreeData,
) -> ProgramResult {
    let verified = verify(accounts, &data)?;
    let _batched_tree_params = batched_tree_params(&data);
    let _account_keys = (
        verified.signer.address(),
        verified.tree.address(),
        verified.queue.address(),
    );

    Err(ShieldedPoolError::AddressTreeMutationUnsupported.into())
}
