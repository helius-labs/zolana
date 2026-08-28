use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{builders::transact::append_nullifier_marker_accounts, tag, MergeTransactIxData},
    PROGRAM_ID_PUBKEY,
};

/// Builder for the `merge_transact` instruction. The account layout mirrors the
/// program loader (`MergeTransactAccounts::validate_and_parse`):
/// `input_tree` and `output_tree` (writable), `payer` (signer, writable),
/// `user_record` (read-only), the System Program, one writable nullifier marker
/// per `nullifiers` entry, and the program account last for the `emit_event`
/// self-CPI.
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
        ];
        append_nullifier_marker_accounts(
            &mut accounts,
            &self.input_tree,
            self.data.nullifiers.iter(),
        );
        accounts.push(AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false));

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{instruction::instruction_data::merge_transact::MergeProof, pda};

    fn data(nullifiers: Vec<[u8; 32]>) -> MergeTransactIxData {
        MergeTransactIxData {
            expiry_unix_ts: u64::MAX,
            proof: MergeProof::zeroed(),
            output_utxo_hash: [0u8; 32],
            nullifiers,
            utxo_tree_root_index: vec![0; 8],
            nullifier_tree_root_index: vec![0; 8],
            private_tx_hash: [0u8; 32],
            eddsa_owner: false,
        }
    }

    #[test]
    fn eight_nullifier_markers_follow_system_program_and_precede_program_account() {
        let input_tree = Pubkey::new_unique();
        let nullifiers: Vec<[u8; 32]> = (1u8..=8).map(|i| [i; 32]).collect();
        let builder = MergeTransact {
            input_tree,
            output_tree: Pubkey::new_unique(),
            payer: Pubkey::new_unique(),
            user_record: Pubkey::new_unique(),
            data: data(nullifiers.clone()),
        };

        let ix = builder.instruction();
        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data.first(), Some(&tag::MERGE_TRANSACT));

        let mut expected = vec![
            AccountMeta::new(input_tree, false),
            AccountMeta::new(builder.output_tree, false),
            AccountMeta::new(builder.payer, true),
            AccountMeta::new_readonly(builder.user_record, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ];
        expected.extend(nullifiers.iter().map(|nullifier| {
            AccountMeta::new(pda::nullifier_marker(&input_tree, nullifier).0, false)
        }));
        expected.push(AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false));
        assert_eq!(ix.accounts, expected);
        assert_eq!(ix.accounts.len(), 5 + 8 + 1);
    }
}
