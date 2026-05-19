use pinocchio::{AccountView, ProgramResult};
use zolana_interface::instruction::InsertAddressesData;

use super::verify::verify;
use crate::error::ShieldedPoolError;

pub fn process_insert_addresses(
    accounts: &[AccountView],
    data: InsertAddressesData,
) -> ProgramResult {
    let verified = verify(accounts, &data)?;
    let _account_keys = (verified.signer.address(), verified.tree.address());

    // TODO: load BatchedMerkleTreeAccount from tree bytes and call
    // insert_address_into_queue for each address in data.addresses. Tracking
    // separately from create since it touches the bloom filter + queue
    // batch metadata paths.
    Err(ShieldedPoolError::AddressTreeMutationUnsupported.into())
}
