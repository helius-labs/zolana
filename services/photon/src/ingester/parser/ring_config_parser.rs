//! Indexing ring registrations.
//!
//! `CREATE_RING_CONFIG` emits no event, so unlike the state-transitioning
//! instructions this is read straight off the instruction rather than through
//! [`find_event_sites`](super::event_site::find_event_sites). That is safe for a
//! different reason: the instruction belongs to the pool, and only the pool can
//! execute it. Failed transactions never reach the parser, so anything seen here
//! passed the pool's own check that the config account is the `ring_auth` PDA of
//! the `program_id` in the instruction data -- the one and only place that
//! derivation is verified.

use borsh::BorshDeserialize;
use zolana_event::tag;
use zolana_interface::{instruction::CreateRingConfigData, pda};

use super::state_update::{RingConfigUpdate, StateUpdate};
use crate::ingester::{error::IngesterError, typedefs::block_info::TransactionInfo};

/// Index of the config account (the ring's `ring_auth` PDA) in
/// `CREATE_RING_CONFIG`: payer, protocol_config, ring_config, system_program.
const RING_CONFIG_ACCOUNT_INDEX: usize = 2;

pub fn parse_ring_configs(
    tx: &TransactionInfo,
    slot: u64,
) -> Result<Option<StateUpdate>, IngesterError> {
    let pool = pda::shielded_pool_program_id();
    let mut ring_configs = Vec::new();

    for group in &tx.instruction_groups {
        let instructions =
            std::iter::once(&group.outer_instruction).chain(group.inner_instructions.iter());
        for instruction in instructions {
            if instruction.program_id != pool
                || instruction.data.first() != Some(&tag::CREATE_RING_CONFIG)
            {
                continue;
            }

            let Some(ring_config) = instruction.accounts.get(RING_CONFIG_ACCOUNT_INDEX) else {
                return Err(IngesterError::ParserError(format!(
                    "create_ring_config in {} is missing its config account",
                    tx.signature
                )));
            };
            let data =
                CreateRingConfigData::try_from_slice(instruction.data.get(1..).unwrap_or_default())
                    .map_err(|err| {
                        IngesterError::ParserError(format!(
                            "Failed to decode create_ring_config in {}: {err}",
                            tx.signature
                        ))
                    })?;

            ring_configs.push(RingConfigUpdate {
                ring_config: ring_config.to_bytes(),
                program_id: data.program_id.to_bytes(),
                authority: data.authority.to_bytes(),
                slot,
            });
        }
    }

    if ring_configs.is_empty() {
        return Ok(None);
    }

    Ok(Some(StateUpdate {
        ring_configs,
        ..StateUpdate::new()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingester::typedefs::block_info::{Instruction, InstructionGroup};
    use solana_pubkey::Pubkey;
    use solana_signature::Signature;

    fn create_ring_config_data(program_id: Pubkey, authority: Pubkey) -> Vec<u8> {
        let mut data = vec![tag::CREATE_RING_CONFIG];
        borsh::to_writer(
            &mut data,
            &CreateRingConfigData {
                program_id: program_id.to_bytes().into(),
                authority: authority.to_bytes().into(),
            },
        )
        .expect("serialize");
        data
    }

    fn tx_with(instruction: Instruction) -> TransactionInfo {
        TransactionInfo {
            instruction_groups: vec![InstructionGroup {
                outer_instruction: instruction,
                inner_instructions: Vec::new(),
            }],
            signature: Signature::from([1; 64]),
            error: None,
        }
    }

    #[test]
    fn records_the_registered_ring() {
        let ring_program = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let (ring_config, _) = pda::ring_auth(&ring_program);
        let tx = tx_with(Instruction {
            program_id: pda::shielded_pool_program_id(),
            data: create_ring_config_data(ring_program, authority),
            accounts: vec![
                Pubkey::new_unique(),
                Pubkey::new_unique(),
                ring_config,
                Pubkey::new_unique(),
            ],
            stack_height: Some(1),
        });

        let update = parse_ring_configs(&tx, 7).expect("parse").expect("update");

        assert_eq!(
            update.ring_configs,
            vec![RingConfigUpdate {
                ring_config: ring_config.to_bytes(),
                program_id: ring_program.to_bytes(),
                authority: authority.to_bytes(),
                slot: 7,
            }]
        );
    }

    /// A foreign program cannot register a ring by mimicking the instruction:
    /// only the pool's own `CREATE_RING_CONFIG` performs the PDA check.
    #[test]
    fn ignores_the_instruction_under_a_foreign_program() {
        let ring_program = Pubkey::new_unique();
        let (ring_config, _) = pda::ring_auth(&ring_program);
        let tx = tx_with(Instruction {
            program_id: Pubkey::new_unique(),
            data: create_ring_config_data(ring_program, Pubkey::new_unique()),
            accounts: vec![
                Pubkey::new_unique(),
                Pubkey::new_unique(),
                ring_config,
                Pubkey::new_unique(),
            ],
            stack_height: Some(1),
        });

        assert!(parse_ring_configs(&tx, 7).expect("parse").is_none());
    }

    #[test]
    fn a_transaction_without_a_registration_yields_nothing() {
        let tx = tx_with(Instruction {
            program_id: pda::shielded_pool_program_id(),
            data: vec![tag::TRANSACT, 1, 2, 3],
            accounts: Vec::new(),
            stack_height: Some(1),
        });

        assert!(parse_ring_configs(&tx, 7).expect("parse").is_none());
    }
}
