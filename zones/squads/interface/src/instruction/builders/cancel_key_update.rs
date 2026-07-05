//! `cancel_key_update` (tag 15) instruction builder (spec: squads
//! `cancel_key_update`). Empty payload: only the dispatch tag rides the
//! instruction.

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{instruction::tag, PROGRAM_ID_PUBKEY};

/// Builder for the `cancel_key_update` instruction.
///
/// Account order mirrors the spec's `cancel_key_update` "Accounts" list:
/// `owner`, `target`, `key_update_proposal`, `rent_recipient`.
pub struct CancelKeyUpdate {
    pub owner: Pubkey,
    pub target: Pubkey,
    pub key_update_proposal: Pubkey,
    pub rent_recipient: Pubkey,
}

impl CancelKeyUpdate {
    pub fn instruction(&self) -> Instruction {
        let accounts = vec![
            AccountMeta::new_readonly(self.owner, true),
            AccountMeta::new_readonly(self.target, false),
            AccountMeta::new(self.key_update_proposal, false),
            AccountMeta::new(self.rent_recipient, false),
        ];

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: vec![tag::CANCEL_KEY_UPDATE],
        }
    }
}
