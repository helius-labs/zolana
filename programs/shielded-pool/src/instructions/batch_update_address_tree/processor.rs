use light_batched_merkle_tree::merkle_tree::{
    BatchedMerkleTreeAccount, InstructionDataBatchNullifyInputs,
};
use light_compressed_account::instruction_data::compressed_proof::CompressedProof;
use light_merkle_tree_metadata::events::MerkleTreeEvent;
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_interface::instruction::BatchUpdateAddressTreeData;

use super::verify::verify;
use crate::{
    error::ShieldedPoolError,
    events::emit_address_tree_batch_updated,
    instructions::create_pool_tree::init::address_sub_tree_slice_mut,
};

pub fn process_batch_update_address_tree(
    program_id: &Address,
    accounts: &[AccountView],
    data: BatchUpdateAddressTreeData,
) -> ProgramResult {
    let verified = verify(program_id, accounts, &data)?;
    let tree_pubkey = *verified.tree.address();

    // SAFETY: tree is the writable account passed by the caller and not
    // aliased with any other borrowed account.
    let bytes = unsafe { verified.tree.borrow_unchecked_mut() };
    let address_slice = address_sub_tree_slice_mut(bytes)
        .map_err(|_| ShieldedPoolError::InvalidPoolTreeAccounts)?;
    let mut tree = BatchedMerkleTreeAccount::address_from_bytes(address_slice, &tree_pubkey)
        .map_err(|_| ShieldedPoolError::InvalidPoolTreeAccounts)?;

    let instruction = InstructionDataBatchNullifyInputs {
        new_root: data.new_root,
        compressed_proof: CompressedProof {
            a: data.compressed_proof_a,
            b: data.compressed_proof_b,
            c: data.compressed_proof_c,
        },
    };

    let event = tree
        .update_tree_from_address_queue(instruction)
        .map_err(|_| ShieldedPoolError::PoolTreeMutationFailed)?;

    if let MerkleTreeEvent::BatchAddressAppend(batch) = event {
        emit_address_tree_batch_updated(
            &tree_pubkey,
            batch.new_root,
            batch.root_index,
            batch.sequence_number,
        );
    }
    Ok(())
}
