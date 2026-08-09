//! `update_viewing_key_account` (tag 6) instruction builder (spec: squads
//! `update_viewing_key_account`).

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, UpdateViewingKeyAccountIxData},
    PROGRAM_ID_PUBKEY,
};

/// Builder for the `update_viewing_key_account` instruction.
///
/// Account order mirrors the spec's `update_viewing_key_account` "Accounts"
/// list: `proposer`, `target`, `key_update_proposal`, `system_program`,
/// `zone_config`.
pub struct UpdateViewingKeyAccount {
    pub proposer: Pubkey,
    pub target: Pubkey,
    pub key_update_proposal: Pubkey,
    pub system_program: Pubkey,
    pub zone_config: Pubkey,
    pub data: UpdateViewingKeyAccountIxData,
}

impl UpdateViewingKeyAccount {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::UPDATE_VIEWING_KEY_ACCOUNT];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("squads-zone instruction serialization is infallible"),
        );

        let accounts = vec![
            AccountMeta::new(self.proposer, true),
            AccountMeta::new_readonly(self.target, false),
            AccountMeta::new(self.key_update_proposal, false),
            AccountMeta::new_readonly(self.system_program, false),
            AccountMeta::new_readonly(self.zone_config, false),
        ];

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        }
    }
}
