use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{
        builders::{
            merge_transact::{validate_merge_data, MergeBuildError},
            transact::nullifier_pda_accounts,
        },
        tag, MergeRingIxData, MergeTransactIxData,
    },
    pda, PROGRAM_ID_PUBKEY,
};

/// Builder for the `merge_ring` instruction, the policy-ring analog of
/// [`super::merge_transact::MergeTransact`]. The account layout mirrors the
/// program loader (`MergeRingAccounts::validate_and_parse`): `input_tree` and
/// `output_tree` (writable), `ring_config` (the ring's `ring_auth` PDA), `payer`
/// (signer), the System Program, the program account for the `emit_event`
/// self-CPI, then one writable nullifier PDA per `nullifiers` entry.
/// Instruction data is the output `ring_data_hash` followed by the
/// `MergeTransactIxData` body.
///
/// # Compute budget
///
/// The caller must raise the compute limit exactly as for
/// [`super::merge_transact::MergeTransact`], whose rustdoc carries the measured
/// per-shape figures; this rail runs the same merge tail behind a ring-program
/// CPI, so it costs strictly more and those figures are a floor, not a budget.
pub struct MergeRing {
    pub input_tree: Pubkey,
    pub output_tree: Pubkey,
    /// Calling ring program; its `ring_config` (canonical `ring_auth` PDA) signs.
    pub ring_program_id: Pubkey,
    pub payer: Pubkey,
    pub data: MergeTransactIxData,
    /// The output `ring_data_hash` the ring program selected; the merge proof
    /// binds it to `Output.Utxo.RingDataHash`.
    pub output_ring_data_hash: [u8; 32],
}

impl MergeRing {
    /// Instruction sent to the ring program, which CPIs into SPP. The `ring_auth`
    /// PDA is not a transaction-level signer; the ring program signs for it.
    pub fn instruction(&self) -> Result<Instruction, MergeBuildError> {
        self.build_instruction(self.ring_program_id, false)
    }

    /// The SPP instruction a ring program constructs for its own CPI: program id
    /// is SPP and the `ring_auth` PDA is passed as a signer.
    pub fn cpi_instruction(&self) -> Result<Instruction, MergeBuildError> {
        self.build_instruction(PROGRAM_ID_PUBKEY, true)
    }

    fn build_instruction(
        &self,
        program_id: Pubkey,
        auth_signer: bool,
    ) -> Result<Instruction, MergeBuildError> {
        validate_merge_data(&self.data)?;

        let ring_config = pda::ring_auth(&self.ring_program_id).0;

        let ix_data = MergeRingIxData {
            output_ring_data_hash: self.output_ring_data_hash,
            merge: self.data.clone(),
        };
        let mut instruction_data = vec![tag::RING_MERGE_TRANSACT];
        instruction_data.extend_from_slice(
            &ix_data
                .serialize()
                .map_err(|_| MergeBuildError::Serialization)?,
        );

        let mut accounts = vec![
            AccountMeta::new(self.input_tree, false),
            AccountMeta::new(self.output_tree, false),
            AccountMeta::new_readonly(ring_config, auth_signer),
            AccountMeta::new(self.payer, true),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
        ];
        accounts.extend(nullifier_pda_accounts(
            &self.input_tree,
            self.data.nullifiers.iter(),
        ));

        Ok(Instruction {
            program_id,
            accounts,
            data: instruction_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::instruction_data::merge_transact::MergeProof;

    fn nullifiers() -> Vec<[u8; 32]> {
        (1u8..=8).map(|i| [i; 32]).collect()
    }

    fn data() -> MergeTransactIxData {
        MergeTransactIxData {
            expiry_unix_ts: u64::MAX,
            proof: MergeProof::zeroed(),
            output_utxo_hash: [0u8; 32],
            nullifiers: nullifiers(),
            utxo_tree_root_index: vec![0; 8],
            nullifier_tree_root_index: vec![0; 8],
            private_tx_hash: [0u8; 32],
            eddsa_owner: false,
        }
    }

    fn expected_accounts(builder: &MergeRing, auth_signer: bool) -> Vec<AccountMeta> {
        let mut expected = vec![
            AccountMeta::new(builder.input_tree, false),
            AccountMeta::new(builder.output_tree, false),
            AccountMeta::new_readonly(pda::ring_auth(&builder.ring_program_id).0, auth_signer),
            AccountMeta::new(builder.payer, true),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
        ];
        expected.extend(builder.data.nullifiers.iter().map(|nullifier| {
            AccountMeta::new(pda::nullifier_pda(&builder.input_tree, nullifier).0, false)
        }));
        expected
    }

    /// The instruction targets the ring program, lays out `input_tree`,
    /// `output_tree`, `ring_config`, `payer`, System Program, program account,
    /// eight nullifier PDAs, and tags the data with `RING_MERGE_TRANSACT`
    /// followed by the 32-byte output `ring_data_hash`.
    #[test]
    fn instruction_account_order_and_ring_config() {
        let ring_program_id = Pubkey::new_unique();
        let builder = MergeRing {
            input_tree: Pubkey::new_unique(),
            output_tree: Pubkey::new_unique(),
            ring_program_id,
            payer: Pubkey::new_unique(),
            data: data(),
            output_ring_data_hash: [7u8; 32],
        };

        let ix = builder.instruction().expect("valid merge ring");
        assert_eq!(ix.program_id, ring_program_id);
        assert_eq!(ix.data.first(), Some(&tag::RING_MERGE_TRANSACT));
        assert_eq!(ix.data.get(1..33), Some(&[7u8; 32][..]));

        // `.instruction()` targets the ring program, so the `ring_auth` PDA is not
        // a transaction-level signer.
        assert_eq!(ix.accounts, expected_accounts(&builder, false));
        assert_eq!(ix.accounts.len(), 5 + 8 + 1);
    }

    #[test]
    fn cpi_instruction_marks_ring_auth_signer() {
        let ring_program_id = Pubkey::new_unique();
        let builder = MergeRing {
            input_tree: Pubkey::new_unique(),
            output_tree: Pubkey::new_unique(),
            ring_program_id,
            payer: Pubkey::new_unique(),
            data: data(),
            output_ring_data_hash: [0u8; 32],
        };

        let ix = builder.cpi_instruction().expect("valid merge ring");
        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.accounts, expected_accounts(&builder, true));
        assert!(ix.accounts[2].is_signer);
    }

    #[test]
    fn both_forms_reject_an_invalid_merge_shape() {
        let mut invalid_data = data();
        let input_count = invalid_data.nullifiers.len();
        invalid_data.utxo_tree_root_index.pop();
        let builder = MergeRing {
            input_tree: Pubkey::new_unique(),
            output_tree: Pubkey::new_unique(),
            ring_program_id: Pubkey::new_unique(),
            payer: Pubkey::new_unique(),
            data: invalid_data,
            output_ring_data_hash: [0u8; 32],
        };
        let expected = MergeBuildError::InputVectorLengthMismatch {
            nullifier_count: input_count,
            utxo_root_index_count: input_count - 1,
            nullifier_root_index_count: input_count,
        };

        assert_eq!(builder.instruction(), Err(expected));
        assert_eq!(builder.cpi_instruction(), Err(expected));
    }
}
