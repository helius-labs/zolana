//! `fold_transact` (tag 17) instruction builder.

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, FoldTransactIxData},
    PROGRAM_ID_PUBKEY,
};

/// Builder for the `fold_transact` instruction.
///
/// The account order is the `transact` transfer order unchanged. Every leg
/// spends the same sender and pays the same recipient, and SPP holds one tree,
/// so a leg needs no accounts of its own.
pub struct FoldTransact {
    pub payer: Pubkey,
    pub co_signer: Pubkey,
    pub zone_config: Pubkey,
    pub sender_viewing_key_account: Pubkey,
    pub recipient_viewing_key_account: Pubkey,
    pub ring_auth: Pubkey,
    pub spp_program: Pubkey,
    /// SPP tree accounts touched by the transaction. These are the remaining accounts.
    pub tree_accounts: Vec<Pubkey>,
    pub data: FoldTransactIxData,
}

impl FoldTransact {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::FOLD_TRANSACT];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("squads-zone instruction serialization is infallible"),
        );

        let mut accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new_readonly(self.co_signer, true),
            AccountMeta::new_readonly(self.zone_config, false),
            AccountMeta::new_readonly(self.sender_viewing_key_account, false),
            AccountMeta::new_readonly(self.recipient_viewing_key_account, false),
            AccountMeta::new_readonly(self.ring_auth, false),
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
