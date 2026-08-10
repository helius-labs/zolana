//! `close_viewing_key_account` (tag 8) instruction builder (spec: squads
//! `close_viewing_key_account`). Empty payload: only the dispatch tag rides the
//! instruction.

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{instruction::tag, PROGRAM_ID_PUBKEY};

/// Builder for the `close_viewing_key_account` instruction.
///
/// Account order: `authority`, `viewing_key_account`, `rent_recipient`,
/// `ring_config`. The authority is the account's owner or the ring co-signer,
/// which the program reads from `ring_config`. The program records the prior
/// account state as a self-CPI event, so `program` is appended last as a
/// loadable target.
pub struct CloseViewingKeyAccount {
    pub authority: Pubkey,
    pub viewing_key_account: Pubkey,
    pub rent_recipient: Pubkey,
    pub ring_config: Pubkey,
}

impl CloseViewingKeyAccount {
    pub fn instruction(&self) -> Instruction {
        let accounts = vec![
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new(self.viewing_key_account, false),
            AccountMeta::new(self.rent_recipient, false),
            AccountMeta::new_readonly(self.ring_config, false),
            AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
        ];

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: vec![tag::CLOSE_VIEWING_KEY_ACCOUNT],
        }
    }
}
