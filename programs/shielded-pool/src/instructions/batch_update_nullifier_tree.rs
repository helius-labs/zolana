use light_account_checks::AccountIterator;
use light_batched_merkle_tree::merkle_tree::InstructionDataBatchNullifyInputs;
use light_verifier::CompressedProof;
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_interface::instruction::BatchUpdateNullifierTreeData;
use zolana_interface::state::discriminator::TREE_ACCOUNT_DISCRIMINATOR;
use zolana_tree::TreeAccount;

use zolana_interface::error::ShieldedPoolError;

use crate::instructions::protocol_config::loader::load_protocol_config;

pub fn process_batch_update_nullifier_tree(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: BatchUpdateNullifierTreeData,
) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let protocol_config = iter.next_account("protocol_config")?;
    let tree = iter.next_mut("tree")?;

    let config = load_protocol_config(protocol_config)?;
    config
        .check_forester_authority(authority.address())
        .map_err(ShieldedPoolError::from)?;
    drop(config);

    let mut tree = TreeAccount::from_account_view_mut(tree, program_id, TREE_ACCOUNT_DISCRIMINATOR)
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
        return Err(ShieldedPoolError::NullifierTreeUpdateFailed.into());
    }
    Ok(())
}
