use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::instruction_data::transact::TransactIxData, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_program::instruction::nullifier_pda_accounts;

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
    /// Public lower edge of the pair-configured symmetric price window.
    pub public_price_floor: u64,
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
            public_price_floor,
            transact,
        } = self;

        let nullifier_pdas = nullifier_pda_accounts(
            &tree,
            transact.inputs.iter().map(|input| &input.nullifier_hash),
        );
        let ix_data = CreateEscrowIxData {
            proof,
            public_price_floor,
            transact,
        };
        let serialized = wincode::serialize(&ix_data).map_err(err)?;

        let mut instruction_data = vec![tag::CREATE_ESCROW];
        instruction_data.extend_from_slice(&serialized);

        let mut accounts = vec![
            AccountMeta::new(taker, true),
            AccountMeta::new(pair, false),
            AccountMeta::new(escrow, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            // Forwarded SPP `transact` CPI tail: payer (the taker, whose outer
            // signature authorizes the source input), output tree, SPP, System
            // Program, input tree, one nullifier PDA per input, then the escrow
            // authority (the single owner-signer, flipped by the program's CPI).
            AccountMeta::new(taker, true),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new(tree, false),
        ];
        accounts.extend(nullifier_pdas);
        accounts.push(AccountMeta::new_readonly(
            escrow_authority_pda(&pair),
            false,
        ));

        Ok(Instruction {
            program_id: dynamic_swap_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
