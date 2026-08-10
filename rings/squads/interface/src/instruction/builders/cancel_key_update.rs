//! `cancel_key_update` (tag 15) instruction builder (spec: squads
//! `cancel_key_update`). Empty payload: only the dispatch tag rides the
//! instruction.

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{instruction::tag, PROGRAM_ID_PUBKEY};

/// Builder for the `cancel_key_update` instruction.
///
/// Account order: `authority`, `target`, `key_update_proposal`,
/// `rent_recipient`, `ring_config`. The authority is the target's owner or the
/// ring co-signer, which the program reads from `ring_config`.
pub struct CancelKeyUpdate {
    pub authority: Pubkey,
    pub target: Pubkey,
    pub key_update_proposal: Pubkey,
    pub rent_recipient: Pubkey,
    pub ring_config: Pubkey,
}

impl CancelKeyUpdate {
    pub fn instruction(&self) -> Instruction {
        let accounts = vec![
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new_readonly(self.target, false),
            AccountMeta::new(self.key_update_proposal, false),
            AccountMeta::new(self.rent_recipient, false),
            AccountMeta::new_readonly(self.ring_config, false),
        ];

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: vec![tag::CANCEL_KEY_UPDATE],
        }
    }
}
