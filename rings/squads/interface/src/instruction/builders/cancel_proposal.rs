//! `cancel_proposal` (tag 12) instruction builder (spec: squads
//! `cancel_proposal`). Empty payload: only the dispatch tag rides the
//! instruction.

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{instruction::tag, PROGRAM_ID_PUBKEY};

/// Builder for the `cancel_proposal` instruction.
///
/// Account order: `authority`, `viewing_key_account`, `proposal`,
/// `rent_recipient`, `ring_config`. The authority is the account's owner or the
/// ring co-signer, which the program reads from `ring_config`.
pub struct CancelProposal {
    pub authority: Pubkey,
    pub viewing_key_account: Pubkey,
    pub proposal: Pubkey,
    pub rent_recipient: Pubkey,
    pub ring_config: Pubkey,
}

impl CancelProposal {
    pub fn instruction(&self) -> Instruction {
        let accounts = vec![
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new_readonly(self.viewing_key_account, false),
            AccountMeta::new(self.proposal, false),
            AccountMeta::new(self.rent_recipient, false),
            AccountMeta::new_readonly(self.ring_config, false),
        ];

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: vec![tag::CANCEL_PROPOSAL],
        }
    }
}
