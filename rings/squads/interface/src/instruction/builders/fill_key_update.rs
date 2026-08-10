//! `fill_key_update` (tag 7) instruction builder (spec: squads `fill_key_update`).

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, FillKeyUpdateIxData},
    PROGRAM_ID_PUBKEY,
};

/// Builder for the `fill_key_update` instruction.
///
/// Account order mirrors the spec's `fill_key_update` "Accounts" list:
/// `executor`, `key_update_proposal`.
pub struct FillKeyUpdate {
    pub executor: Pubkey,
    pub key_update_proposal: Pubkey,
    pub data: FillKeyUpdateIxData,
}

impl FillKeyUpdate {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::FILL_KEY_UPDATE];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("squads-zone instruction serialization is infallible"),
        );

        let accounts = vec![
            AccountMeta::new(self.executor, true),
            AccountMeta::new(self.key_update_proposal, false),
        ];

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        }
    }
}
