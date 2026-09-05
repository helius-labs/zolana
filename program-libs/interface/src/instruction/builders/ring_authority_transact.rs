use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{
        builders::transact::{
            append_interface_transfer_accounts, nullifier_pda_accounts, TransactBuildError,
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
/// one writable nullifier PDA per input (in `inputs` order), then optional
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
            AccountMeta::new(self.input_tree, false),
            AccountMeta::new(self.output_tree, false),
            AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(ring_config, auth_signer),
        ];
        accounts.extend(nullifier_pda_accounts(
            &self.input_tree,
            self.data.inputs.iter().map(|input| &input.nullifier_hash),
        ));
        append_interface_transfer_accounts(
            &mut accounts,
            &self.data.interface_transfers,
            &self.interface_transfer_accounts,
        )?;

        let mut instruction_data = vec![tag::RING_AUTHORITY_TRANSACT];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .map_err(|_| TransactBuildError::Serialization)?,
        );

        Ok(Instruction {
            program_id,
            accounts,
            data: instruction_data,
        })
    }
}
