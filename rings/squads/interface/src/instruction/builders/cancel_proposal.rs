//! `cancel_proposal` (tag 12) instruction builder (spec: squads
//! `cancel_proposal`). Empty payload: only the dispatch tag rides the
//! instruction.

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{instruction::tag, PROGRAM_ID_PUBKEY};

/// Builder for the `cancel_proposal` instruction.
///
/// Account order mirrors the spec's `cancel_proposal` "Accounts" list: `owner`,
/// `viewing_key_account`, `proposal`, `rent_recipient`.
pub struct CancelProposal {
    pub owner: Pubkey,
    pub viewing_key_account: Pubkey,
    pub proposal: Pubkey,
    pub rent_recipient: Pubkey,
}

impl CancelProposal {
    pub fn instruction(&self) -> Instruction {
        let accounts = vec![
            AccountMeta::new_readonly(self.owner, true),
            AccountMeta::new_readonly(self.viewing_key_account, false),
            AccountMeta::new(self.proposal, false),
            AccountMeta::new(self.rent_recipient, false),
        ];

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: vec![tag::CANCEL_PROPOSAL],
        }
    }
}
