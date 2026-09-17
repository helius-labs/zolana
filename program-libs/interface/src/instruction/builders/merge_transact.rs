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
/// `emit_event` self-CPI, one writable nullifier PDA per `nullifiers` entry,
/// then the writable cache account when `data.cache_slot` is set, then the
/// read-only receipt account when `data.receipt_offset` is set. The program
/// rejects any account beyond that, so each account and its data field must be
/// set together.
pub struct MergeTransact {
    pub input_tree: Pubkey,
    pub output_tree: Pubkey,
    pub payer: Pubkey,
    pub user_record: Pubkey,
    pub data: MergeTransactIxData,
    pub cache: Option<Pubkey>,
    pub receipt: Option<Pubkey>,
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
        if let Some(cache) = self.cache {
            accounts.push(AccountMeta::new(cache, false));
        }
        if let Some(receipt) = self.receipt {
            accounts.push(AccountMeta::new_readonly(receipt, false));
        }

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        }
    }
}
