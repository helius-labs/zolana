use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{
        builders::transact::{
            append_interface_transfer_accounts, nullifier_pda_accounts,
            TransactInterfaceTransferAccounts,
        },
        tag, TransactIxData,
    },
    pda, PROGRAM_ID_PUBKEY,
};

/// Builder for the `ring_transact` instruction, the confidential policy-ring analog
/// of [`super::transact::Transact`]. The account layout mirrors the program
/// loader (`RingTransactAccounts::validate_and_parse`): `payer`, `input_tree`,
/// `output_tree`, the SPP and System Program accounts, the `RingConfig` account
/// (the ring's `ring_auth` PDA), one writable nullifier PDA per input (in
/// `inputs` order), owner signers, then optional settlement accounts.
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
        accounts.extend(nullifier_pda_accounts(
            &self.input_tree,
            self.data
                .tail
                .inputs
                .iter()
                .map(|input| &input.nullifier_hash),
        ));
        accounts.extend(
            self.owner_signers
                .iter()
                .copied()
                .map(|signer| AccountMeta::new_readonly(signer, true)),
        );
        append_interface_transfer_accounts(
            &mut accounts,
            &self.data.bound.interface_transfers,
            &self.interface_transfer_accounts,
        );
        Instruction {
            program_id,
            accounts,
            data: instruction_data,
        }
    }
}
