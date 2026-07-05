//! `update_zone_config` (tag 4) instruction builder (spec: squads
//! `update_zone_config`).

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, UpdateZoneConfigIxData},
    PROGRAM_ID_PUBKEY,
};

/// Builder for the `update_zone_config` instruction.
///
/// Account order mirrors the spec's `update_zone_config` "Accounts" list:
/// `authority`, `zone_config`.
pub struct UpdateZoneConfig {
    pub authority: Pubkey,
    pub zone_config: Pubkey,
    pub data: UpdateZoneConfigIxData,
}

impl UpdateZoneConfig {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::UPDATE_ZONE_CONFIG];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("squads-zone instruction serialization is infallible"),
        );

        let accounts = vec![
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new(self.zone_config, false),
        ];

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        }
    }
}
