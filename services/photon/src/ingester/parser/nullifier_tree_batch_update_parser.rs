use crate::ingester::error::IngesterError;
use crate::ingester::parser::state_update::{NullifierTreeBatchUpdate, StateUpdate};
use crate::ingester::typedefs::block_info::{Instruction, TransactionInfo};
use borsh::BorshDeserialize;
use zolana_interface::{
    instruction::{tag, BatchUpdateNullifierTreeData, BatchUpdateNullifierTreeFoldedData},
    pda,
    state::ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE,
};

const NULLIFIER_TREE_ACCOUNT_INDEX: usize = 2;

/// The unfolded rail settles exactly one zkp batch per instruction.
const UNFOLDED_RUN: u32 = 1;

/// A fold of one is not a fold, and the chain rejects it.
const MIN_FOLDED_RUN: u32 = 2;

/// A fold settles zkp batches of a single queue batch, and every zkp batch
/// holds at least one element, so no run can exceed the queue batch capacity.
const MAX_FOLDED_RUN: u64 = ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE;

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
    if !is_batch_update_tag(*instruction_tag) {
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

    let (run, new_root) = decode_batch_update(*instruction_tag, payload).map_err(|err| {
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
            new_root,
            run,
            signature: tx.signature,
        });
    Ok(Some(state_update))
}

/// Both rails that advance a nullifier tree. A folded run settles several zkp
/// batches and appends one root for all of them, so the indexer records one
/// update either way but must carry the run length to it.
fn is_batch_update_tag(instruction_tag: u8) -> bool {
    matches!(
        instruction_tag,
        tag::BATCH_UPDATE_NULLIFIER_TREE | tag::BATCH_UPDATE_NULLIFIER_TREE_FOLDED
    )
}

/// The zkp batches the instruction settles and the root the tree ends at. The
/// folded payload is `(run, inputs)`, so its `new_root` sits behind the run
/// length rather than at the front.
fn decode_batch_update(
    instruction_tag: u8,
    payload: &[u8],
) -> Result<(u32, [u8; 32]), std::io::Error> {
    if instruction_tag == tag::BATCH_UPDATE_NULLIFIER_TREE_FOLDED {
        let (run, data) = <(u32, BatchUpdateNullifierTreeFoldedData)>::try_from_slice(payload)?;
        if run < MIN_FOLDED_RUN || u64::from(run) > MAX_FOLDED_RUN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("folded run {run} is a length no tree can settle"),
            ));
        }
        return Ok((run, data.new_root));
    }
    Ok((
        UNFOLDED_RUN,
        BatchUpdateNullifierTreeData::try_from_slice(payload)?.new_root,
    ))
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
        && instruction
            .data
            .first()
            .is_some_and(|instruction_tag| is_batch_update_tag(*instruction_tag))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingester::typedefs::block_info::InstructionGroup;
    use solana_pubkey::Pubkey;
    use solana_signature::Signature;
    use zolana_interface::instruction::{encode_instruction, CommittedProof, CompressedProof};

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
        assert_eq!(state_update.nullifier_tree_batch_updates[0].run, 1);
        assert!(has_nullifier_tree_batch_update(&tx));
    }

    fn folded_payload(run: u32, new_root: [u8; 32]) -> (u32, BatchUpdateNullifierTreeFoldedData) {
        (
            run,
            BatchUpdateNullifierTreeFoldedData {
                old_root: [10; 32],
                new_root,
                proof: CommittedProof {
                    proof: CompressedProof {
                        a: [1; 32],
                        b: [2; 64],
                        c: [3; 32],
                    },
                    commitment: [4; 32],
                    commitment_pok: [5; 32],
                },
            },
        )
    }

    /// A folded run settles several zkp batches and appends one root. The
    /// indexer must read that root and the run length, or the tree it serves
    /// stops advancing the moment the forester turns folding on.
    #[test]
    fn parses_folded_batch_update_instruction() {
        let tree = Pubkey::new_from_array([7; 32]);
        let new_root = [11; 32];
        let data = folded_payload(3, new_root);
        let instruction = Instruction {
            program_id: pda::shielded_pool_program_id(),
            accounts: vec![
                Pubkey::new_from_array([4; 32]),
                Pubkey::new_from_array([5; 32]),
                tree,
            ],
            data: encode_instruction(tag::BATCH_UPDATE_NULLIFIER_TREE_FOLDED, &data),
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
        // The reconstruction window is this many zkp batches wide. Dropping it
        // reconstructs one batch and compares against the root of three.
        assert_eq!(state_update.nullifier_tree_batch_updates[0].run, 3);
        // The snapshot filter uses this, so a folded transaction that parses but
        // is not retained would still lose the update.
        assert!(has_nullifier_tree_batch_update(&tx));
    }

    /// A run the chain cannot have produced must fail at the parser, where it
    /// costs one transaction, rather than size a reconstruction window.
    #[test]
    fn rejects_a_run_no_tree_can_settle() {
        for run in [0, 1, u32::MAX] {
            let payload = encode_instruction(
                tag::BATCH_UPDATE_NULLIFIER_TREE_FOLDED,
                &folded_payload(run, [11; 32]),
            );
            assert!(
                decode_batch_update(tag::BATCH_UPDATE_NULLIFIER_TREE_FOLDED, &payload[1..])
                    .is_err(),
                "run {run} must not parse"
            );
        }
    }

    /// The two payloads differ in layout, so decoding one as the other must
    /// fail rather than read a root from the wrong offset.
    #[test]
    fn folded_payload_is_not_read_as_an_unfolded_one() {
        let unfolded = BatchUpdateNullifierTreeData {
            new_root: [9; 32],
            old_root: [8; 32],
            zkp_batch_index: 0,
            compressed_proof: CompressedProof {
                a: [1; 32],
                b: [2; 64],
                c: [3; 32],
            },
        };
        let payload = encode_instruction(tag::BATCH_UPDATE_NULLIFIER_TREE, &unfolded);
        assert!(
            decode_batch_update(tag::BATCH_UPDATE_NULLIFIER_TREE_FOLDED, &payload[1..]).is_err()
        );
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
