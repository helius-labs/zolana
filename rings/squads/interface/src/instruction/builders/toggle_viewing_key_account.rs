//! `toggle_viewing_key_account` (tag 9) instruction builder (spec: squads
//! `toggle_viewing_key_account`).

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, ToggleViewingKeyAccountIxData},
    PROGRAM_ID_PUBKEY,
};

/// Builder for the `toggle_viewing_key_account` instruction.
///
/// Account order: `authority`, `viewing_key_account`, `ring_config`. The
/// authority is the account's owner or the ring co-signer, which the program
/// reads from `ring_config`.
pub struct ToggleViewingKeyAccount {
    pub authority: Pubkey,
    pub viewing_key_account: Pubkey,
    pub ring_config: Pubkey,
    pub data: ToggleViewingKeyAccountIxData,
}

impl ToggleViewingKeyAccount {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::TOGGLE_VIEWING_KEY_ACCOUNT];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("squads-ring instruction serialization is infallible"),
        );

        let accounts = vec![
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new(self.viewing_key_account, false),
            AccountMeta::new_readonly(self.ring_config, false),
        ];

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        }
    }
}
