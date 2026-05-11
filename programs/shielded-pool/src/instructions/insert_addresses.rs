use pinocchio::{AccountView, ProgramResult};
use zolana_interface::instruction::InsertAddressesData;

use crate::error::ShieldedPoolError;

pub fn process_insert_addresses(
    _accounts: &[AccountView],
    data: InsertAddressesData,
) -> ProgramResult {
    if data.addresses.is_empty() {
        return Err(ShieldedPoolError::EmptyAddressBatch.into());
    }
    Ok(())
}
