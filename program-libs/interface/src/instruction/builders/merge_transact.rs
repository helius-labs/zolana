use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use thiserror::Error;

use crate::{
    instruction::{
        builders::transact::nullifier_pda_accounts,
        instruction_data::merge_transact::MERGE_SUPPORTED_INPUT_COUNTS, tag, MergeTransactIxData,
    },
    PROGRAM_ID_PUBKEY,
};

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum MergeBuildError {
    #[error(
        "merge input vectors disagree: {nullifier_count} nullifiers, {utxo_root_index_count} UTXO root indices, and {nullifier_root_index_count} nullifier root indices"
    )]
    InputVectorLengthMismatch {
        nullifier_count: usize,
        utxo_root_index_count: usize,
        nullifier_root_index_count: usize,
    },
    #[error("merge input count {count} is not supported")]
    UnsupportedInputCount { count: usize },
    #[error("merge instruction data could not be serialized")]
    Serialization,
}

pub(super) fn validate_merge_data(data: &MergeTransactIxData) -> Result<(), MergeBuildError> {
    let nullifier_count = data.nullifiers.len();
    let utxo_root_index_count = data.utxo_tree_root_index.len();
    let nullifier_root_index_count = data.nullifier_tree_root_index.len();
    if utxo_root_index_count != nullifier_count || nullifier_root_index_count != nullifier_count {
        return Err(MergeBuildError::InputVectorLengthMismatch {
            nullifier_count,
            utxo_root_index_count,
            nullifier_root_index_count,
        });
    }
    if !MERGE_SUPPORTED_INPUT_COUNTS.contains(&nullifier_count) {
        return Err(MergeBuildError::UnsupportedInputCount {
            count: nullifier_count,
        });
    }
    Ok(())
}

/// Builder for the `merge_transact` instruction. The account layout mirrors the
/// program loader (`MergeTransactAccounts::validate_and_parse`):
/// `input_tree` and `output_tree` (writable), `payer` (signer, writable),
/// `user_record` (read-only), the System Program, the program account for the
/// `emit_event` self-CPI, then one writable nullifier PDA per `nullifiers`
/// entry.
///
/// # Compute budget
///
/// **No merge fits the 200,000 CU per-instruction default.** The caller must
/// prepend a `ComputeBudgetInstruction::set_compute_unit_limit`; this builder
/// deliberately returns only the merge instruction, so the returned account and
/// instruction list is exactly what the program consumes.
///
/// Measured on LiteSVM (`merge/functional.rs`, 2026-09), per supported input
/// count in [`MERGE_SUPPORTED_INPUT_COUNTS`]:
///
/// | inputs | observed CU       | suggested limit |
/// |--------|-------------------|-----------------|
/// | 8      | 193_000-212_000   | 400_000         |
/// | 36     | 406_000-446_000   | 800_000         |
///
/// The range, not a point, is the honest figure: each input's nullifier PDA is
/// derived with a canonical bump search whose iteration count depends on the
/// nullifier, so the cost moves with the inputs being merged. The Groth16
/// pairing is shape-independent; everything above it scales with the input
/// count.
///
/// [`MERGE_SUPPORTED_INPUT_COUNTS`]: crate::instruction::instruction_data::merge_transact::MERGE_SUPPORTED_INPUT_COUNTS
pub struct MergeTransact {
    pub input_tree: Pubkey,
    pub output_tree: Pubkey,
    pub payer: Pubkey,
    pub user_record: Pubkey,
    pub data: MergeTransactIxData,
}

impl MergeTransact {
    pub fn instruction(&self) -> Result<Instruction, MergeBuildError> {
        validate_merge_data(&self.data)?;

        let mut instruction_data = vec![tag::MERGE_TRANSACT];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .map_err(|_| MergeBuildError::Serialization)?,
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

        Ok(Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::instruction_data::merge_transact::MergeProof;

    fn data_with(input_count: usize) -> MergeTransactIxData {
        MergeTransactIxData {
            expiry_unix_ts: u64::MAX,
            proof: MergeProof::zeroed(),
            output_utxo_hash: [0u8; 32],
            eddsa_owner: false,
            private_tx_hash: [0u8; 32],
            nullifiers: vec![[0u8; 32]; input_count],
            utxo_tree_root_index: vec![0; input_count],
            nullifier_tree_root_index: vec![0; input_count],
        }
    }

    fn builder(data: MergeTransactIxData) -> MergeTransact {
        MergeTransact {
            input_tree: Pubkey::new_unique(),
            output_tree: Pubkey::new_unique(),
            payer: Pubkey::new_unique(),
            user_record: Pubkey::new_unique(),
            data,
        }
    }

    #[test]
    fn rejects_disagreeing_input_vector_lengths() {
        let mut data = data_with(MERGE_SUPPORTED_INPUT_COUNTS[0]);
        data.nullifier_tree_root_index.pop();

        assert_eq!(
            builder(data).instruction(),
            Err(MergeBuildError::InputVectorLengthMismatch {
                nullifier_count: MERGE_SUPPORTED_INPUT_COUNTS[0],
                utxo_root_index_count: MERGE_SUPPORTED_INPUT_COUNTS[0],
                nullifier_root_index_count: MERGE_SUPPORTED_INPUT_COUNTS[0] - 1,
            })
        );
    }

    #[test]
    fn rejects_unsupported_input_count() {
        let input_count = MERGE_SUPPORTED_INPUT_COUNTS[0] - 1;
        assert_eq!(
            builder(data_with(input_count)).instruction(),
            Err(MergeBuildError::UnsupportedInputCount { count: input_count })
        );
    }
}
