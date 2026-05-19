use light_concurrent_merkle_tree::zero_copy::ConcurrentMerkleTreeZeroCopyMut;
use light_hasher::Poseidon;
use pinocchio::{AccountView, ProgramResult};
use zolana_interface::instruction::AppendStateLeavesData;

use super::verify::verify;
use crate::{
    error::ShieldedPoolError, instructions::create_state_tree::init::HEIGHT,
};

pub fn process_append_state_leaves(
    accounts: &[AccountView],
    data: AppendStateLeavesData,
) -> ProgramResult {
    let verified = verify(accounts, &data)?;
    // SAFETY: `MutableStateTreeAccounts::tree` is the writable account passed
    // by the caller and not aliased with any other borrowed account.
    let bytes = unsafe { verified.tree.borrow_unchecked_mut() };
    let mut tree = ConcurrentMerkleTreeZeroCopyMut::<Poseidon, HEIGHT>::from_bytes_zero_copy_mut(
        bytes,
    )
    .map_err(|_| ShieldedPoolError::InvalidStateTreeAccounts)?;
    let refs: Vec<&[u8; 32]> = data.leaves.iter().collect();
    tree.append_batch(&refs)
        .map_err(|_| ShieldedPoolError::InvalidStateTreeAccounts)?;
    Ok(())
}
