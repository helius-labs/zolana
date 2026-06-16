use light_batched_merkle_tree::merkle_tree::InstructionDataBatchNullifyInputs;
use light_verifier::CompressedProof;
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_interface::instruction::BatchUpdateNullifierTreeData;
use zolana_interface::state::discriminator::TREE_ACCOUNT_DISCRIMINATOR;
use zolana_tree::TreeAccount;

use super::verify::verify;
use crate::{error::ShieldedPoolError, log::log};

pub fn process_batch_update_nullifier_tree(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: BatchUpdateNullifierTreeData,
) -> ProgramResult {
    let verified = verify(program_id, accounts, &data)?;

    let mut tree =
        TreeAccount::from_account_view_mut(verified.tree, program_id, TREE_ACCOUNT_DISCRIMINATOR)
            .map_err(ShieldedPoolError::from)?;

    let instruction = InstructionDataBatchNullifyInputs {
        new_root: data.new_root,
        compressed_proof: CompressedProof {
            a: data.compressed_proof_a,
            b: data.compressed_proof_b,
            c: data.compressed_proof_c,
        },
    };

    if tree
        .nullifer_tree
        .update_tree_from_address_queue(instruction)
        .is_err()
    {
        log("batch_update_nullifier_tree: proof verification or queue update failed");
        return Err(ShieldedPoolError::NullifierTreeUpdateFailed.into());
    }
    Ok(())
}
