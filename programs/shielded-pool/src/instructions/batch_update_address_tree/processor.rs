use pinocchio::{AccountView, ProgramResult};
use zolana_interface::instruction::BatchUpdateAddressTreeData;

use super::verify::verify;
use crate::error::ShieldedPoolError;

pub fn process_batch_update_address_tree(
    accounts: &[AccountView],
    data: BatchUpdateAddressTreeData,
) -> ProgramResult {
    let verified = verify(accounts, &data)?;
    let _account_keys = (verified.signer.address(), verified.tree.address());

    // TODO: verify the ZK proof against the in-account input queue's pending
    // batch and call BatchedMerkleTreeAccount::update_tree_from_address_queue.
    // Requires wiring groth16-solana + the address-tree verifying key, which
    // is its own slice.
    Err(ShieldedPoolError::AddressTreeMutationUnsupported.into())
}
