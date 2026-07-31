use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::instruction_data::transact::TransactIxData, SHIELDED_POOL_PROGRAM_ID,
};

use crate::{err, escrow_authority_pda, tag, CreateEscrowIxData, EscrowOpenProof};

/// Both `authority` (the pair's maker, funding the reservation and paying for
/// the escrow account) and `owner` (authorizing the source UTXO spend) must
/// sign. The program signs for the escrow-authority-owned funding UTXO.
pub struct CreateEscrow {
    pub authority: Pubkey,
    pub owner: Pubkey,
    pub pair: Pubkey,
    pub escrow: Pubkey,
    pub tree: Pubkey,
    pub proof: EscrowOpenProof,
    /// The slot the proof commits to -- see `CreateEscrowIxData`'s doc
    /// comment. Must match whatever value `EscrowOpenProofInputParams::created_at`
    /// used to build the proof.
    pub created_at: u64,
    pub transact: TransactIxData,
}

impl CreateEscrow {
    pub fn instruction(self) -> Result<Instruction> {
        let CreateEscrow {
            authority,
            owner,
            pair,
            escrow,
            tree,
            proof,
            created_at,
            transact,
        } = self;

        let ix_data = CreateEscrowIxData {
            proof,
            created_at,
            transact,
        };
        let serialized = wincode::serialize(&ix_data).map_err(err)?;

        let mut instruction_data = vec![tag::CREATE_ESCROW];
        instruction_data.extend_from_slice(&serialized);

        let accounts = vec![
            AccountMeta::new(authority, true),
            AccountMeta::new_readonly(owner, true),
            AccountMeta::new_readonly(pair, false),
            AccountMeta::new(escrow, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            // Forwarded SPP `transact` CPI tail: payer, input tree, output tree,
            // SPP, System Program, the source owner, then escrow authority.
            AccountMeta::new(authority, true),
            AccountMeta::new(tree, false),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(owner, true),
            AccountMeta::new_readonly(escrow_authority_pda(&pair), false),
        ];

        Ok(Instruction {
            program_id: dynamic_swap_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
