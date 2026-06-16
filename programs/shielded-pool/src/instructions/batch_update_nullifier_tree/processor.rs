use light_batched_merkle_tree::merkle_tree::{
    BatchedMerkleTreeAccount, InstructionDataBatchNullifyInputs,
};
use light_verifier::CompressedProof;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_interface::instruction::BatchUpdateNullifierTreeData;

use super::verify::verify;
use crate::{
    error::ShieldedPoolError,
    instructions::{create_tree::init::address_sub_tree_slice_mut, loader},
    log::log,
};

pub fn process_batch_update_nullifier_tree(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: BatchUpdateNullifierTreeData,
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if !accounts[0].is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let verified = verify(program_id, accounts, &data)?;
    let tree_pubkey = *verified.tree.address();

    let bytes = loader::account_data_mut(verified.tree);
    let nullifier_slice =
        address_sub_tree_slice_mut(bytes).map_err(|_| ShieldedPoolError::InvalidTreeAccounts)?;
    let mut tree = BatchedMerkleTreeAccount::address_from_bytes(nullifier_slice, &tree_pubkey)
        .map_err(|_| ShieldedPoolError::InvalidTreeAccounts)?;

    let instruction = InstructionDataBatchNullifyInputs {
        new_root: data.new_root,
        compressed_proof: CompressedProof {
            a: data.compressed_proof_a,
            b: data.compressed_proof_b,
            c: data.compressed_proof_c,
        },
    };

    if tree.update_tree_from_address_queue(instruction).is_err() {
        log("batch_update_nullifier_tree: proof verification or queue update failed");
        return Err(ShieldedPoolError::NullifierTreeUpdateFailed.into());
    }
    Ok(())
}
