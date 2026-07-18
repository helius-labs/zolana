use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::instruction_data::transact::TransactIxData, SHIELDED_POOL_PROGRAM_ID,
};

use crate::{err, escrow_authority_pda, tag, WithdrawIxData, WithdrawProof};

pub struct Withdraw {
    /// The creator's ed25519 pubkey, a dedicated readonly signer the timelock
    /// escrow program checks against the withdraw proof's committed owner.
    pub creator: Pubkey,
    pub payer: Pubkey,
    pub tree: Pubkey,
    pub withdraw_proof: WithdrawProof,
    pub unlock_timestamp: u64,
    pub spp_proof: TransactIxData,
}

/// The escrow utxo (input 0) is owned by the escrow-authority PDA appended
/// readonly after `tree`; the timelock escrow program signs for it via
/// `invoke_signed`. The signer index selects the account whose pubkey the SPP
/// proof's input_owner_pk_hash must match; it is not itself a proof public
/// input, so overriding it post-proof is safe.
const ESCROW_AUTHORITY_SIGNER_INDEX: u8 = 2;

impl Withdraw {
    pub fn instruction(self) -> Result<Instruction> {
        let Self {
            creator,
            payer,
            tree,
            withdraw_proof,
            unlock_timestamp,
            mut spp_proof,
        } = self;
        if let Some(escrow_input_utxo) = spp_proof.inputs.get_mut(0) {
            escrow_input_utxo.eddsa_signer_index = ESCROW_AUTHORITY_SIGNER_INDEX;
        }

        let serialized_ix = wincode::serialize(&WithdrawIxData {
            proof: withdraw_proof,
            unlock_timestamp,
            transact: spp_proof,
        })
        .map_err(err)?;

        // The creator is a dedicated readonly signer after the fee payer; the
        // timelock escrow program checks its pubkey against the withdraw
        // proof's committed owner.
        let accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(creator, true),
            AccountMeta::new(payer, true),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(escrow_authority_pda(), false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
        ];
        let mut instruction_data = vec![tag::WITHDRAW];
        instruction_data.extend_from_slice(&serialized_ix);
        Ok(Instruction {
            program_id: timelock_escrow_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
