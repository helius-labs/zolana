//! `merge_transact` (tag 2) instruction builder (spec: squads `merge_transact`).

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, MergeTransactIxData},
    PROGRAM_ID_PUBKEY,
};

/// Builder for the `merge_transact` instruction.
///
/// Account order mirrors the spec's `merge_transact` "Accounts" list:
/// `merge_authority`, `zone_config`, `owner_viewing_key_account`, `zone_auth`,
/// `spp_program`, then the `tree_accounts` tail as remaining accounts.
pub struct MergeTransact {
    pub merge_authority: Pubkey,
    pub zone_config: Pubkey,
    pub owner_viewing_key_account: Pubkey,
    pub zone_auth: Pubkey,
    pub spp_program: Pubkey,
    /// SPP Tree accounts holding the merged inputs; remaining accounts.
    pub tree_accounts: Vec<Pubkey>,
    pub data: MergeTransactIxData,
}

impl MergeTransact {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::MERGE_TRANSACT];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("squads-zone instruction serialization is infallible"),
        );

        let mut accounts = vec![
            AccountMeta::new(self.merge_authority, true),
            AccountMeta::new_readonly(self.zone_config, false),
            AccountMeta::new_readonly(self.owner_viewing_key_account, false),
            AccountMeta::new_readonly(self.zone_auth, false),
            AccountMeta::new_readonly(self.spp_program, false),
        ];
        for tree in &self.tree_accounts {
            accounts.push(AccountMeta::new(*tree, false));
        }

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        }
    }
}
