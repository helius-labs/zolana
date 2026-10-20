use alloc::vec;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::{tag, MergeTransactIxData},
    PROGRAM_ID_PUBKEY,
};

use super::transact::nullifier_pda_accounts;

/// Builder for the `merge_transact` instruction. The account layout mirrors the
/// program loader (`MergeTransactAccounts::validate_and_parse`):
/// `input_tree` and `output_tree` (writable), `payer` (signer, writable),
/// `user_record` (read-only), the System Program, the program account for the
/// `emit_event` self-CPI, one writable nullifier PDA per `nullifiers` entry,
/// then the writable cache account and its signing writer when
/// `data.cache_slot` is set. The program rejects any account beyond that, so
/// `cache` and `data.cache_slot` must be set together.
pub struct MergeTransact {
    pub input_tree: Pubkey,
    pub output_tree: Pubkey,
    pub payer: Pubkey,
    pub user_record: Pubkey,
    pub data: MergeTransactIxData,
    pub cache: Option<CacheWriteAccounts>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheWriteAccounts {
    pub cache: Pubkey,
    pub writer: Pubkey,
}

impl CacheWriteAccounts {
    pub(super) fn account_metas(self) -> [AccountMeta; 2] {
        [
            AccountMeta::new(self.cache, false),
            AccountMeta::new_readonly(self.writer, true),
        ]
    }
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
        accounts.extend(
            self.cache
                .into_iter()
                .flat_map(CacheWriteAccounts::account_metas),
        );

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        }
    }
}
