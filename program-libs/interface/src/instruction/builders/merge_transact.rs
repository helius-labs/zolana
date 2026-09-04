use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{builders::transact::nullifier_pda_accounts, tag, MergeTransactIxData},
    PROGRAM_ID_PUBKEY,
};

/// Builder for the `merge_transact` instruction. The account layout mirrors the
/// program loader (`MergeTransactAccounts::validate_and_parse`):
/// `input_tree` and `output_tree` (writable), `payer` (signer, writable),
/// `user_record` (read-only), the System Program, the program account for the
/// `emit_event` self-CPI, then one writable nullifier PDA per `nullifiers`
/// entry.
pub struct MergeTransact {
    pub input_tree: Pubkey,
    pub output_tree: Pubkey,
    pub payer: Pubkey,
    pub user_record: Pubkey,
    pub data: MergeTransactIxData,
}

impl MergeTransact {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::MERGE_TRANSACT];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("shielded-pool instruction serialization is infallible"),
        );

        let mut accounts = vec![
            AccountMeta::new(self.input_tree, false),
            AccountMeta::new(self.output_tree, false),
            AccountMeta::new(self.payer, true),
            AccountMeta::new_readonly(self.user_record, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
        ];
        accounts.extend(nullifier_pda_accounts(
            &self.input_tree,
            self.data.nullifiers.iter(),
        ));

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        }
    }
}
