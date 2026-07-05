//! `create_zone_config` (tag 3) instruction builder (spec: squads
//! `create_zone_config`).

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, CreateZoneConfigIxData},
    PROGRAM_ID_PUBKEY,
};

/// Builder for the `create_zone_config` instruction.
///
/// Account order mirrors the spec's `create_zone_config` "Accounts" list:
/// `creator`, `zone_config`, `system_program`.
pub struct CreateZoneConfig {
    pub creator: Pubkey,
    pub zone_config: Pubkey,
    pub system_program: Pubkey,
    pub data: CreateZoneConfigIxData,
}

impl CreateZoneConfig {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::CREATE_ZONE_CONFIG];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("squads-zone instruction serialization is infallible"),
        );

        let accounts = vec![
            AccountMeta::new(self.creator, true),
            AccountMeta::new(self.zone_config, false),
            AccountMeta::new_readonly(self.system_program, false),
        ];

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        }
    }
}
