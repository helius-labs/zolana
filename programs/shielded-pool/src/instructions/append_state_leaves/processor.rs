use pinocchio::{AccountView, ProgramResult};
use zolana_interface::instruction::AppendStateLeavesData;

use super::verify::verify;
use crate::error::ShieldedPoolError;

pub fn process_append_state_leaves(
    accounts: &[AccountView],
    data: AppendStateLeavesData,
) -> ProgramResult {
    let verified = verify(accounts, &data)?;
    let _account_keys = (verified.signer.address(), verified.tree.address());

    Err(ShieldedPoolError::StateTreeMutationUnsupported.into())
}
