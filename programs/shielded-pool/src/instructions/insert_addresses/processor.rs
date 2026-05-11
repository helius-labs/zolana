use pinocchio::{AccountView, ProgramResult};
use zolana_interface::instruction::InsertAddressesData;

use super::verify::verify;
use crate::error::ShieldedPoolError;

pub fn process_insert_addresses(
    accounts: &[AccountView],
    data: InsertAddressesData,
) -> ProgramResult {
    let verified = verify(accounts, &data)?;
    let _account_keys = (
        verified.signer.address(),
        verified.tree.address(),
        verified.queue.address(),
    );

    Err(ShieldedPoolError::AddressTreeMutationUnsupported.into())
}
