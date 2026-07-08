//! `close_viewing_key_account` (tag 8) instruction builder (spec: squads
//! `close_viewing_key_account`). Empty payload: only the dispatch tag rides the
//! instruction.

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{instruction::tag, PROGRAM_ID_PUBKEY};

/// Builder for the `close_viewing_key_account` instruction.
///
/// Account order mirrors the spec's `close_viewing_key_account` "Accounts" list:
/// `owner`, `viewing_key_account`, `rent_recipient`.
///
// TODO(self-cpi-event): the spec records the account as a self-CPI event before
// clearing it. When that lands, append the program account here as the self-CPI
// target (and update the processor + tests to match).
pub struct CloseViewingKeyAccount {
    pub owner: Pubkey,
    pub viewing_key_account: Pubkey,
    pub rent_recipient: Pubkey,
}

impl CloseViewingKeyAccount {
    pub fn instruction(&self) -> Instruction {
        let accounts = vec![
            AccountMeta::new_readonly(self.owner, true),
            AccountMeta::new(self.viewing_key_account, false),
            AccountMeta::new(self.rent_recipient, false),
        ];

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: vec![tag::CLOSE_VIEWING_KEY_ACCOUNT],
        }
    }
}
