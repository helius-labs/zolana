//! `create_ring_config` (tag 3) instruction builder (spec: squads
//! `create_ring_config`).

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, CreateRingConfigIxData},
    PROGRAM_ID_PUBKEY,
};

/// Builder for the `create_ring_config` instruction.
///
/// Account order mirrors the spec's `create_ring_config` "Accounts" list:
/// `creator`, `ring_config`, `system_program`.
pub struct CreateRingConfig {
    pub creator: Pubkey,
    pub ring_config: Pubkey,
    pub system_program: Pubkey,
    pub data: CreateRingConfigIxData,
}

impl CreateRingConfig {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::CREATE_RING_CONFIG];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("squads-ring instruction serialization is infallible"),
        );

        let accounts = vec![
            AccountMeta::new(self.creator, true),
            AccountMeta::new(self.ring_config, false),
            AccountMeta::new_readonly(self.system_program, false),
        ];

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        }
    }
}
