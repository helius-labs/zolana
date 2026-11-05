use alloc::{vec, vec::Vec};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use spr_interface::{
    instruction::{tag, TransactIxData},
    pda, PROGRAM_ID_PUBKEY,
};

use super::transact::{
    append_interface_transfer_accounts, transact_instruction_data, transact_nullifier_pda_accounts,
    TransactBuildError, TransactInterfaceTransferAccounts,
};

/// Builder for the `ring_authority_transact` instruction: a ring-authority state
/// transition (freeze, thaw, permanent-delegate transfer) over ring-owned UTXOs.
/// The account layout matches `ring_transact` (the loader reuses
/// `RingTransactAccounts`): `payer`, `output_tree`, the SPP and System Program
/// accounts, the `RingConfig` (the ring's
/// `ring_auth` PDA, which must have `ring_authority_transact_is_enabled` set),
/// one input tree per declared tree context, one writable nullifier PDA per
/// input (in `inputs` order), then optional
/// settlement accounts.
pub struct RingAuthorityTransact {
    pub payer: Pubkey,
    /// One tree per `data.tree_contexts` entry, in the same order.
    pub input_trees: Vec<Pubkey>,
    pub output_tree: Pubkey,
    /// Calling ring program; its `RingConfig` (canonical `ring_auth` PDA) signs.
    pub ring_program_id: Pubkey,
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    pub data: TransactIxData,
}

impl RingAuthorityTransact {
    /// Instruction sent to the ring program, which CPIs into SPP. The `ring_auth`
    /// PDA is not a transaction-level signer; the ring program signs for it.
    pub fn instruction(&self) -> Result<Instruction, TransactBuildError> {
        self.build_instruction(self.ring_program_id, false)
    }

    /// The SPP instruction a ring program constructs for its own CPI: program id
    /// is SPP and the `ring_auth` PDA is passed as a signer.
    pub fn cpi_instruction(&self) -> Result<Instruction, TransactBuildError> {
        self.build_instruction(PROGRAM_ID_PUBKEY, true)
    }

    fn build_instruction(
        &self,
        program_id: Pubkey,
        auth_signer: bool,
    ) -> Result<Instruction, TransactBuildError> {
        let ring_config = pda::ring_auth(&self.ring_program_id).0;

        let mut accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new(self.output_tree, false),
            AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(ring_config, auth_signer),
        ];
        accounts.extend(
            self.input_trees
                .iter()
                .map(|input_tree| AccountMeta::new(*input_tree, false)),
        );
        accounts.extend(transact_nullifier_pda_accounts(
            &self.input_trees,
            self.data.inputs.iter(),
        )?);
        append_interface_transfer_accounts(
            &mut accounts,
            &self.data.interface_transfers,
            &self.interface_transfer_accounts,
        )?;
        Ok(Instruction {
            program_id,
            accounts,
            data: transact_instruction_data(tag::RING_AUTHORITY_TRANSACT, &self.data)?,
        })
    }
}
