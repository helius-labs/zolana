//! `execute_key_update` (tag 14) instruction builder (spec: squads
//! `execute_key_update`).

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, ExecuteKeyUpdateIxData},
    PROGRAM_ID_PUBKEY,
};

/// Builder for the `execute_key_update` instruction.
///
/// Account order mirrors the spec's `execute_key_update` "Accounts" list:
/// `executor`, `co_signer`, `viewing_key_account`, `zone_config`,
/// `key_update_proposal`, `rent_recipient`, `system_program`. The program
/// records the pre-rotation account as a self-CPI event, so `program` is
/// appended last as a loadable target.
pub struct ExecuteKeyUpdate {
    pub executor: Pubkey,
    pub co_signer: Pubkey,
    pub viewing_key_account: Pubkey,
    pub zone_config: Pubkey,
    pub key_update_proposal: Pubkey,
    pub rent_recipient: Pubkey,
    pub system_program: Pubkey,
    pub data: ExecuteKeyUpdateIxData,
}

impl ExecuteKeyUpdate {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::EXECUTE_KEY_UPDATE];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("squads-zone instruction serialization is infallible"),
        );

        let accounts = vec![
            AccountMeta::new(self.executor, true),
            AccountMeta::new_readonly(self.co_signer, true),
            AccountMeta::new(self.viewing_key_account, false),
            AccountMeta::new_readonly(self.zone_config, false),
            AccountMeta::new(self.key_update_proposal, false),
            AccountMeta::new(self.rent_recipient, false),
            AccountMeta::new_readonly(self.system_program, false),
            // PROVISIONAL: the spec lists seven accounts but states the program
            // records the pre-rotation account via a self-CPI event; the program
            // account is appended last as a loadable target, mirroring the SPP
            // `emit_event` self-CPI pattern.
            AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
        ];

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        }
    }
}
