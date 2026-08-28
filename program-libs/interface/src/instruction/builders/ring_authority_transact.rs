use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{
        builders::transact::{
            append_interface_transfer_accounts, append_nullifier_marker_accounts,
            TransactInterfaceTransferAccounts,
        },
        tag, TransactIxData,
    },
    pda, PROGRAM_ID_PUBKEY,
};

/// Builder for the `ring_authority_transact` instruction: a ring-authority state
/// transition (freeze, thaw, permanent-delegate transfer) over ring-owned UTXOs.
/// The account layout matches `ring_transact` (the loader reuses
/// `RingTransactAccounts`): `payer`, `input_tree`, `output_tree`, the
/// SPP and System Program accounts, the `RingConfig` (the ring's
/// `ring_auth` PDA, which must have `ring_authority_transact_is_enabled` set),
/// one writable nullifier marker per input (in `inputs` order), then optional
/// settlement accounts.
pub struct RingAuthorityTransact {
    pub payer: Pubkey,
    pub input_tree: Pubkey,
    pub output_tree: Pubkey,
    /// Calling ring program; its `RingConfig` (canonical `ring_auth` PDA) signs.
    pub ring_program_id: Pubkey,
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    pub data: TransactIxData,
}

impl RingAuthorityTransact {
    /// Instruction sent to the ring program, which CPIs into SPP. The `ring_auth`
    /// PDA is not a transaction-level signer; the ring program signs for it.
    pub fn instruction(&self) -> Instruction {
        self.build_instruction(self.ring_program_id, false)
    }

    /// The SPP instruction a ring program constructs for its own CPI: program id
    /// is SPP and the `ring_auth` PDA is passed as a signer.
    pub fn cpi_instruction(&self) -> Instruction {
        self.build_instruction(PROGRAM_ID_PUBKEY, true)
    }

    fn build_instruction(&self, program_id: Pubkey, auth_signer: bool) -> Instruction {
        let ring_config = pda::ring_auth(&self.ring_program_id).0;

        let mut instruction_data = vec![tag::RING_AUTHORITY_TRANSACT];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("shielded-pool instruction serialization is infallible"),
        );

        let mut accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new(self.input_tree, false),
            AccountMeta::new(self.output_tree, false),
            AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(ring_config, auth_signer),
        ];
        append_nullifier_marker_accounts(
            &mut accounts,
            &self.input_tree,
            self.data.inputs.iter().map(|input| &input.nullifier_hash),
        );
        append_interface_transfer_accounts(
            &mut accounts,
            &self.data.interface_transfers,
            &self.interface_transfer_accounts,
        );
        Instruction {
            program_id,
            accounts,
            data: instruction_data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::instruction_data::transact::{
        CircuitId, InputUtxo, TransactIxData, TransactProof,
    };

    fn empty_data() -> TransactIxData {
        TransactIxData {
            proof: TransactProof::zeroed(),
            expiry_unix_ts: u64::MAX,
            private_tx_hash: [0u8; 32],
            circuit: CircuitId::RingAuthority(0, 0, 3),
            tx_viewing_pk: [0u8; 33],
            salt: [0u8; 16],
            inputs: Vec::new(),
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            outputs: Vec::new(),
            messages: Vec::new(),
        }
    }

    #[test]
    fn nullifier_markers_follow_ring_config() {
        let ring_program_id = Pubkey::new_unique();
        let input_tree = Pubkey::new_unique();
        let nullifiers = [[11u8; 32], [22u8; 32]];
        let mut data = empty_data();
        data.inputs = nullifiers
            .iter()
            .map(|nullifier_hash| InputUtxo {
                nullifier_hash: *nullifier_hash,
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: 0,
            })
            .collect();
        let builder = RingAuthorityTransact {
            payer: Pubkey::new_unique(),
            input_tree,
            output_tree: Pubkey::new_unique(),
            ring_program_id,
            interface_transfer_accounts: Vec::new(),
            data,
        };

        let ix = builder.instruction();
        let marker = |nullifier: &[u8; 32]| pda::nullifier_marker(&input_tree, nullifier).0;
        assert_eq!(
            ix.accounts,
            vec![
                AccountMeta::new(builder.payer, true),
                AccountMeta::new(input_tree, false),
                AccountMeta::new(builder.output_tree, false),
                AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new_readonly(pda::ring_auth(&ring_program_id).0, false),
                AccountMeta::new(marker(&nullifiers[0]), false),
                AccountMeta::new(marker(&nullifiers[1]), false),
            ]
        );
        assert_eq!(ix.accounts.len(), 6 + nullifiers.len());
    }

    #[test]
    fn instruction_account_order_and_ring_config() {
        let ring_program_id = Pubkey::new_unique();
        let builder = RingAuthorityTransact {
            payer: Pubkey::new_unique(),
            input_tree: Pubkey::new_unique(),
            output_tree: Pubkey::new_unique(),
            ring_program_id,
            interface_transfer_accounts: Vec::new(),
            data: empty_data(),
        };

        let ix = builder.instruction();
        assert_eq!(ix.program_id, ring_program_id);
        assert_eq!(ix.data.first(), Some(&tag::RING_AUTHORITY_TRANSACT));

        let ring_config = pda::ring_auth(&ring_program_id).0;
        let keys: Vec<_> = ix.accounts.iter().map(|m| m.pubkey).collect();
        assert_eq!(
            keys,
            vec![
                builder.payer,
                builder.input_tree,
                builder.output_tree,
                PROGRAM_ID_PUBKEY,
                Pubkey::default(),
                ring_config,
            ]
        );
        assert!(!ix.accounts[5].is_signer);
    }

    #[test]
    fn cpi_instruction_marks_ring_auth_signer() {
        let ring_program_id = Pubkey::new_unique();
        let builder = RingAuthorityTransact {
            payer: Pubkey::new_unique(),
            input_tree: Pubkey::new_unique(),
            output_tree: Pubkey::new_unique(),
            ring_program_id,
            interface_transfer_accounts: Vec::new(),
            data: empty_data(),
        };

        let ix = builder.cpi_instruction();
        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.accounts[5].pubkey, pda::ring_auth(&ring_program_id).0);
        assert!(ix.accounts[5].is_signer);
    }
}
