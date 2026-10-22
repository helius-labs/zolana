//! `merge_transact` (tag 2) instruction builder (spec: squads `merge_transact`).

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, MergeTransactIxData},
    PROGRAM_ID_PUBKEY,
};

/// Builder for the `merge_transact` instruction.
///
/// Account order: `merge_authority`, `ring_config`, `owner_viewing_key_account`,
/// then `spp_accounts`: the SPP `merge_ring` account list, forwarded unchanged.
pub struct MergeTransact {
    pub merge_authority: Pubkey,
    pub ring_config: Pubkey,
    pub owner_viewing_key_account: Pubkey,
    pub spp_accounts: Vec<AccountMeta>,
    pub data: MergeTransactIxData,
}

impl MergeTransact {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::MERGE_TRANSACT];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("squads-ring instruction serialization is infallible"),
        );

        let mut accounts = vec![
            AccountMeta::new(self.merge_authority, true),
            AccountMeta::new_readonly(self.ring_config, false),
            AccountMeta::new_readonly(self.owner_viewing_key_account, false),
        ];
        accounts.extend(self.spp_accounts.iter().cloned());

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        }
    }
}
