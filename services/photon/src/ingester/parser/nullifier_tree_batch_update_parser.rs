use crate::ingester::error::IngesterError;
use crate::ingester::parser::state_update::{NullifierTreeBatchUpdate, StateUpdate};
use crate::ingester::typedefs::block_info::{Instruction, TransactionInfo};
use borsh::BorshDeserialize;
use zolana_interface::{
    instruction::{tag, BatchUpdateNullifierTreeData},
    pda,
};

const NULLIFIER_TREE_ACCOUNT_INDEX: usize = 2;

pub fn parse_nullifier_tree_batch_update(
    instruction: &Instruction,
    tx: &TransactionInfo,
) -> Result<Option<StateUpdate>, IngesterError> {
    if tx.error.is_some() || instruction.program_id != pda::shielded_pool_program_id() {
        return Ok(None);
    }

    let Some((instruction_tag, payload)) = instruction.data.split_first() else {
        return Ok(None);
    };
    if *instruction_tag != tag::BATCH_UPDATE_NULLIFIER_TREE {
        return Ok(None);
    }

    let tree = *instruction
        .accounts
        .get(NULLIFIER_TREE_ACCOUNT_INDEX)
        .ok_or_else(|| {
            IngesterError::ParserError(format!(
                "BatchUpdateNullifierTree instruction {} is missing tree account at index {}",
                tx.signature, NULLIFIER_TREE_ACCOUNT_INDEX
            ))
        })?;

    let data = BatchUpdateNullifierTreeData::try_from_slice(payload).map_err(|err| {
        IngesterError::ParserError(format!(
            "Failed to decode BatchUpdateNullifierTree instruction {}: {}",
            tx.signature, err
        ))
    })?;

    let mut state_update = StateUpdate::new();
    state_update
        .nullifier_tree_batch_updates
        .push(NullifierTreeBatchUpdate {
            tree,
            new_root: data.new_root,
            signature: tx.signature,
        });
    Ok(Some(state_update))
}

pub fn has_nullifier_tree_batch_update(tx: &TransactionInfo) -> bool {
    if tx.error.is_some() {
        return false;
    }

    tx.instruction_groups.iter().any(|instruction_group| {
        std::iter::once(&instruction_group.outer_instruction)
            .chain(instruction_group.inner_instructions.iter())
            .any(is_nullifier_tree_batch_update)
    })
}

fn is_nullifier_tree_batch_update(instruction: &Instruction) -> bool {
    instruction.program_id == pda::shielded_pool_program_id()
        && instruction.data.first() == Some(&tag::BATCH_UPDATE_NULLIFIER_TREE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingester::typedefs::block_info::InstructionGroup;
    use solana_pubkey::Pubkey;
    use solana_signature::Signature;
    use zolana_interface::instruction::{encode_instruction, CompressedProof};

    #[test]
    fn parses_batch_update_instruction() {
        let tree = Pubkey::new_from_array([7; 32]);
        let new_root = [9; 32];
        let data = BatchUpdateNullifierTreeData {
            new_root,
            old_root: [8; 32],
            zkp_batch_index: 0,
            compressed_proof: CompressedProof {
                a: [1; 32],
                b: [2; 64],
                c: [3; 32],
            },
        };
        let instruction = Instruction {
            program_id: pda::shielded_pool_program_id(),
            accounts: vec![
                Pubkey::new_from_array([4; 32]),
                Pubkey::new_from_array([5; 32]),
                tree,
            ],
            data: encode_instruction(tag::BATCH_UPDATE_NULLIFIER_TREE, &data),
            stack_height: None,
        };
        let tx = TransactionInfo {
            instruction_groups: vec![InstructionGroup {
                outer_instruction: instruction.clone(),
                inner_instructions: vec![],
            }],
            signature: Signature::from([8; 64]),
            error: None,
        };

        let state_update = parse_nullifier_tree_batch_update(&instruction, &tx)
            .unwrap()
            .unwrap();

        assert_eq!(state_update.nullifier_tree_batch_updates.len(), 1);
        assert_eq!(state_update.nullifier_tree_batch_updates[0].tree, tree);
        assert_eq!(
            state_update.nullifier_tree_batch_updates[0].new_root,
            new_root
        );
        assert_eq!(
            state_update.nullifier_tree_batch_updates[0].signature,
            tx.signature
        );
        assert!(has_nullifier_tree_batch_update(&tx));
    }

    #[test]
    fn ignores_non_batch_update_instruction() {
        let instruction = Instruction {
            program_id: pda::shielded_pool_program_id(),
            accounts: vec![],
            data: vec![tag::TRANSACT],
            stack_height: None,
        };
        let tx = TransactionInfo {
            instruction_groups: vec![],
            signature: Signature::from([8; 64]),
            error: None,
        };

        assert!(parse_nullifier_tree_batch_update(&instruction, &tx)
            .unwrap()
            .is_none());
    }
}
