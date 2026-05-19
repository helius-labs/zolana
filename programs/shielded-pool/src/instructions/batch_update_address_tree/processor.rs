use light_batched_merkle_tree::merkle_tree::{
    BatchedMerkleTreeAccount, InstructionDataBatchNullifyInputs,
};
use light_compressed_account::instruction_data::compressed_proof::CompressedProof;
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_interface::instruction::BatchUpdateAddressTreeData;

use super::verify::verify;
use crate::error::ShieldedPoolError;

pub fn process_batch_update_address_tree(
    program_id: &Address,
    accounts: &[AccountView],
    data: BatchUpdateAddressTreeData,
) -> ProgramResult {
    let verified = verify(program_id, accounts, &data)?;
    let tree_pubkey = *verified.tree.address();

    // SAFETY: `MutableAddressTreeAccounts::tree` is the writable account passed
    // by the caller and not aliased with any other borrowed account.
    let bytes = unsafe { verified.tree.borrow_unchecked_mut() };
    let mut tree = BatchedMerkleTreeAccount::address_from_bytes(bytes, &tree_pubkey)
        .map_err(|_| ShieldedPoolError::InvalidAddressTreeAccounts)?;

    let instruction = InstructionDataBatchNullifyInputs {
        new_root: data.new_root,
        compressed_proof: CompressedProof {
            a: data.compressed_proof_a,
            b: data.compressed_proof_b,
            c: data.compressed_proof_c,
        },
    };

    // Internally: builds public_input_hash from on-disk old_root + leaves
    // hash chain + next_index, verifies the Groth16 proof against
    // batch_address_append_40_250 verifying key (via light-verifier's
    // verify_batch_address_update), then updates the tree state.
    tree.update_tree_from_address_queue(instruction)
        .map_err(|_| ShieldedPoolError::AddressTreeMutationUnsupported)?;
    Ok(())
}
