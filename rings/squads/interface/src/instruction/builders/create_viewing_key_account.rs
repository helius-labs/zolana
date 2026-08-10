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
/// list: `enrollment_authority`, `owner_identity`, `viewing_key_account`,
/// `ring_config`, `system_program`. `enrollment_authority` is the configured
/// ring co-signer and pays rent. `owner_identity` is the already-derived proof
/// identity field used verbatim as the PDA seed. Auditor-only enrollment does not
/// require it to sign. A non-empty recovery-key list requires control of this
/// exact account. The builder derives the signer bit from `data.recovery_keys`.
/// Derived identities that have no signing key must use the auditor-only path
/// until a versioned owner-auth scheme is available.
pub struct CreateViewingKeyAccount {
    pub enrollment_authority: Pubkey,
    pub owner_identity: Pubkey,
    pub viewing_key_account: Pubkey,
    pub ring_config: Pubkey,
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
                .expect("squads-ring instruction serialization is infallible"),
        );

        let accounts = vec![
            AccountMeta::new(self.enrollment_authority, true),
            AccountMeta::new_readonly(self.owner_identity, !self.data.recovery_keys.is_empty()),
            AccountMeta::new(self.viewing_key_account, false),
            AccountMeta::new_readonly(self.ring_config, false),
            AccountMeta::new_readonly(self.system_program, false),
        ];

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        }
    }
}
