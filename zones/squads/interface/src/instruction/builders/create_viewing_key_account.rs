//! `create_viewing_key_account` (tag 5) instruction builder (spec: squads
//! `create_viewing_key_account`).

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, CreateViewingKeyAccountIxData},
    PROGRAM_ID_PUBKEY,
};

/// Builder for the `create_viewing_key_account` instruction.
///
/// Account order mirrors the spec's `create_viewing_key_account` "Accounts"
/// list: `fee_payer`, `owner`, `viewing_key_account`, `zone_config`,
/// `system_program`. `owner` signs only to register `recovery_keys`; for an
/// auditor-only account it is passed non-signer, surfaced via `owner_signs`.
pub struct CreateViewingKeyAccount {
    pub fee_payer: Pubkey,
    pub owner: Pubkey,
    /// Whether `owner` signs to register the supplied `recovery_keys`.
    pub owner_signs: bool,
    pub viewing_key_account: Pubkey,
    pub zone_config: Pubkey,
    pub system_program: Pubkey,
    pub data: CreateViewingKeyAccountIxData,
}

impl CreateViewingKeyAccount {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::CREATE_VIEWING_KEY_ACCOUNT];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("squads-zone instruction serialization is infallible"),
        );

        let accounts = vec![
            AccountMeta::new(self.fee_payer, true),
            AccountMeta::new_readonly(self.owner, self.owner_signs),
            AccountMeta::new(self.viewing_key_account, false),
            AccountMeta::new_readonly(self.zone_config, false),
            AccountMeta::new_readonly(self.system_program, false),
        ];

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        }
    }
}
