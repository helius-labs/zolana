use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::instruction_data::transact::TransactIxData, SHIELDED_POOL_PROGRAM_ID,
};

use crate::{err, escrow_authority_pda, tag, CreateEscrowIxData, Groth16ProofBytes};

/// The taker signs alone: it authorizes spending its source UTXO (as the
/// transact CPI's payer) and pays the escrow account rent. The program signs
/// for the escrow-authority-owned order output; the maker is not involved.
pub struct CreateEscrow {
    pub taker: Pubkey,
    pub pair: Pubkey,
    pub escrow: Pubkey,
    pub tree: Pubkey,
    pub proof: Groth16ProofBytes,
    /// The taker's price limit; see `CreateEscrowIxData::max_price`.
    pub max_price: u64,
    pub transact: TransactIxData,
}

impl CreateEscrow {
    pub fn instruction(self) -> Result<Instruction> {
        let CreateEscrow {
            taker,
            pair,
            escrow,
            tree,
            proof,
            max_price,
            transact,
        } = self;

        let ix_data = CreateEscrowIxData {
            proof,
            max_price,
            transact,
        };
        let serialized = wincode::serialize(&ix_data).map_err(err)?;

        let mut instruction_data = vec![tag::CREATE_ESCROW];
        instruction_data.extend_from_slice(&serialized);

        let accounts = vec![
            AccountMeta::new(taker, true),
            AccountMeta::new(pair, false),
            AccountMeta::new(escrow, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            // Forwarded SPP `transact` CPI tail: payer (the taker, whose outer
            // signature authorizes the source input), input tree, output tree,
            // SPP, System Program, then the escrow authority (the single
            // owner-signer, flipped by the program's CPI).
            AccountMeta::new(taker, true),
            AccountMeta::new(tree, false),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(escrow_authority_pda(&pair), false),
        ];

        Ok(Instruction {
            program_id: dynamic_swap_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
