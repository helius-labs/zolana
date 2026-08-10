//! `update_ring_config` (tag 4) instruction builder (spec: squads
//! `update_ring_config`).

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, UpdateRingConfigIxData},
    PROGRAM_ID_PUBKEY,
};

/// Builder for the `update_ring_config` instruction.
///
/// Account order mirrors the spec's `update_ring_config` "Accounts" list:
/// `authority`, `ring_config`.
pub struct UpdateRingConfig {
    pub authority: Pubkey,
    pub ring_config: Pubkey,
    pub data: UpdateRingConfigIxData,
}

impl UpdateRingConfig {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::UPDATE_RING_CONFIG];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("squads-ring instruction serialization is infallible"),
        );

        let accounts = vec![
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new(self.ring_config, false),
        ];

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        }
    }
}
