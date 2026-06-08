use light_batched_merkle_tree::merkle_tree::{
    BatchedMerkleTreeAccount, InstructionDataBatchNullifyInputs,
};
use light_verifier::CompressedProof;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_interface::instruction::BatchUpdateNullifierTreeData;

use super::{verify::verify, verifying_key};
use crate::{
    error::ShieldedPoolError,
    instructions::create_pool_tree::init::{
        address_sub_tree_slice_mut, current_nullifier_next_index, current_nullifier_root_index,
        nullifier_root_by_index, push_nullifier_root_with_next_index,
    },
    instructions::hash::{field_from_u64, hash_chain},
    log::log,
};

const SPP_NULLIFIER_BATCH_SIZE: u64 = 10;

pub fn process_batch_update_nullifier_tree(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: BatchUpdateNullifierTreeData,
) -> ProgramResult {
    let verified = verify(program_id, accounts, &data)?;
    let tree_pubkey = *verified.tree.address();

    // SAFETY: tree is the writable account passed by the caller and not
    // aliased with any other borrowed account.
    let bytes = unsafe { verified.tree.borrow_unchecked_mut() };
    let old_nullifier_root_index = current_nullifier_root_index(bytes)
        .map_err(|_| ShieldedPoolError::InvalidPoolTreeAccounts)?;
    let old_nullifier_root = nullifier_root_by_index(bytes, old_nullifier_root_index)
        .map_err(|_| ShieldedPoolError::InvalidPoolTreeAccounts)?;
    let start_index = current_nullifier_next_index(bytes)
        .map_err(|_| ShieldedPoolError::InvalidPoolTreeAccounts)?;

    let (batch_size, leaves_hash_chain) = {
        let address_slice = address_sub_tree_slice_mut(bytes)
            .map_err(|_| ShieldedPoolError::InvalidPoolTreeAccounts)?;
        let mut tree = BatchedMerkleTreeAccount::address_from_bytes(address_slice, &tree_pubkey)
            .map_err(|_| ShieldedPoolError::InvalidPoolTreeAccounts)?;

        if tree.queue_batches.zkp_batch_size != SPP_NULLIFIER_BATCH_SIZE {
            return Err(ShieldedPoolError::InvalidNullifierBatchUpdate.into());
        }

        let pending_batch_index = tree.queue_batches.pending_batch_index as usize;
        let first_ready_zkp_batch_index = tree.queue_batches.batches[pending_batch_index]
            .get_first_ready_zkp_batch()
            .map_err(|_| ShieldedPoolError::InvalidNullifierBatchUpdate)?
            as usize;
        let leaves_hash_chain =
            tree.hash_chain_stores[pending_batch_index][first_ready_zkp_batch_index];

        verify_nullifier_update_proof(
            old_nullifier_root,
            data.nullifier_new_root,
            leaves_hash_chain,
            start_index,
            &data,
        )?;

        let instruction = InstructionDataBatchNullifyInputs {
            new_root: data.address_new_root,
            compressed_proof: CompressedProof {
                a: data.address_compressed_proof_a,
                b: data.address_compressed_proof_b,
                c: data.address_compressed_proof_c,
            },
        };

        if tree.update_tree_from_address_queue(instruction).is_err() {
            log("batch_update_nullifier_tree: Light address queue update failed");
            return Err(ShieldedPoolError::BatchProofVerificationFailed.into());
        }

        (tree.queue_batches.zkp_batch_size, leaves_hash_chain)
    };

    let next_index = start_index
        .checked_add(batch_size)
        .ok_or(ShieldedPoolError::InvalidNullifierBatchUpdate)?;
    push_nullifier_root_with_next_index(bytes, data.nullifier_new_root, next_index)
        .map_err(|_| ShieldedPoolError::InvalidNullifierBatchUpdate)?;
    log_nullifier_update(leaves_hash_chain);
    Ok(())
}

fn verify_nullifier_update_proof(
    old_root: [u8; 32],
    new_root: [u8; 32],
    leaves_hash_chain: [u8; 32],
    start_index: u64,
    data: &BatchUpdateNullifierTreeData,
) -> ProgramResult {
    let public_input_hash = hash_chain(
        &[
            old_root,
            new_root,
            leaves_hash_chain,
            field_from_u64(start_index),
        ],
        ShieldedPoolError::InvalidNullifierBatchUpdate,
    )?;
    let proof = CompressedProof {
        a: data.nullifier_compressed_proof_a,
        b: data.nullifier_compressed_proof_b,
        c: data.nullifier_compressed_proof_c,
    };
    light_verifier::verify::<1>(&[public_input_hash], &proof, &verifying_key::VERIFYINGKEY).map_err(
        |_| {
            log("batch_update_nullifier_tree: SPP nullifier update proof failed");
            ProgramError::from(ShieldedPoolError::NullifierBatchProofVerificationFailed)
        },
    )
}

fn log_nullifier_update(_leaves_hash_chain: [u8; 32]) {
    log("batch_update_nullifier_tree: nullifier root cache advanced");
}
