use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{
        builders::transact::{
            append_interface_transfer_accounts, TransactInterfaceTransferAccounts,
        },
        tag, TransactIxData,
    },
    pda, PROGRAM_ID_PUBKEY,
};

/// Builder for the `ring_transact` instruction, the confidential policy-ring analog
/// of [`super::transact::Transact`]. The account layout mirrors the program
/// loader (`RingTransactAccounts::validate_and_parse`): `payer`, `input_tree`,
/// `output_tree`, the SPP and System Program accounts, the `RingConfig` account
/// (the ring's `ring_auth` PDA), owner signers, then optional settlement accounts.
pub struct RingTransact {
    pub payer: Pubkey,
    pub input_tree: Pubkey,
    pub output_tree: Pubkey,
    /// Calling ring program; its `RingConfig` (canonical `ring_auth` PDA) signs.
    pub ring_program_id: Pubkey,
    pub owner_signers: Vec<Pubkey>,
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    pub data: TransactIxData,
}

impl RingTransact {
    /// Instruction sent to the ring program, which CPIs into SPP. The `ring_auth`
    /// PDA is not a transaction-level signer; the ring program signs for it in its
    /// CPI.
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

        let mut instruction_data = vec![tag::RING_TRANSACT];
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
        accounts.extend(
            self.owner_signers
                .iter()
                .copied()
                .map(|signer| AccountMeta::new_readonly(signer, true)),
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
        CircuitId, TransactIxData, TransactProof,
    };

    fn empty_data() -> TransactIxData {
        TransactIxData {
            proof: TransactProof::zeroed(),
            expiry_unix_ts: u64::MAX,
            private_tx_hash: [0u8; 32],
            circuit: CircuitId::RingEddsa(0, 0, 3),
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

    /// A pure shielded `ring_transact` lays out `payer`, `input_tree`,
    /// `output_tree`, SPP, System Program, the `RingConfig` (canonical
    /// `ring_auth` PDA), then owner signers, and tags the instruction data with
    /// `RING_TRANSACT`.
    #[test]
    fn instruction_account_order_and_ring_config() {
        let ring_program_id = Pubkey::new_unique();
        let owner_signer = Pubkey::new_unique();
        let builder = RingTransact {
            payer: Pubkey::new_unique(),
            input_tree: Pubkey::new_unique(),
            output_tree: Pubkey::new_unique(),
            ring_program_id,
            owner_signers: vec![owner_signer],
            interface_transfer_accounts: Vec::new(),
            data: empty_data(),
        };

        let ix = builder.instruction();
        assert_eq!(ix.program_id, ring_program_id);
        assert_eq!(ix.data.first(), Some(&tag::RING_TRANSACT));

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
                owner_signer,
            ]
        );
        // `.instruction()` targets the ring program, so the `ring_auth` PDA is not
        // a transaction-level signer.
        assert!(!ix.accounts[5].is_signer);
        assert!(ix.accounts[6].is_signer);
        assert!(ix.accounts[0].is_signer);
    }

    /// `.cpi_instruction()` targets SPP and marks the `ring_auth` PDA a signer.
    #[test]
    fn cpi_instruction_marks_ring_auth_signer() {
        let ring_program_id = Pubkey::new_unique();
        let builder = RingTransact {
            payer: Pubkey::new_unique(),
            input_tree: Pubkey::new_unique(),
            output_tree: Pubkey::new_unique(),
            ring_program_id,
            owner_signers: Vec::new(),
            interface_transfer_accounts: Vec::new(),
            data: empty_data(),
        };

        let ix = builder.cpi_instruction();
        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.accounts[5].pubkey, pda::ring_auth(&ring_program_id).0);
        assert!(ix.accounts[5].is_signer);
    }
}
