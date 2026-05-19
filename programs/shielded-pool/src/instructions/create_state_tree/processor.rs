use pinocchio::{AccountView, ProgramResult};
use zolana_interface::instruction::CreateStateTreeData;

use super::verify::verify;
use crate::error::ShieldedPoolError;

pub fn process_create_state_tree(
    accounts: &[AccountView],
    data: CreateStateTreeData,
) -> ProgramResult {
    let verified = verify(accounts, &data)?;
    let _account_keys = (verified.signer.address(), verified.tree.address());

    Err(ShieldedPoolError::StateTreeMutationUnsupported.into())
}
