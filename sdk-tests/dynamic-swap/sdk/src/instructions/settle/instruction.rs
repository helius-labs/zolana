use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::instruction_data::transact::TransactIxData, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_program::instruction::nullifier_pda_accounts;

use crate::{err, escrow_authority_pda, pool_authority_pda, tag, Groth16ProofBytes, SettleIxData};

/// Fills one escrow before expiry from the pair's committed pool and closes
/// it. Maker-only: `authority` (the pair authority) signs and pays fees; the
/// payout is funded from a pool_authority-owned note, so no external funding
/// UTXO is involved.
pub struct Settle {
    pub authority: Pubkey,
    pub pair: Pubkey,
    pub escrow: Pubkey,
    pub rent_recipient: Pubkey,
    pub tree: Pubkey,
    pub proof: Groth16ProofBytes,
    pub transact: TransactIxData,
}

impl Settle {
    pub fn instruction(self) -> Result<Instruction> {
        let Settle {
            authority,
            pair,
            escrow,
            rent_recipient,
            tree,
            proof,
            transact,
        } = self;

        let nullifier_pdas = nullifier_pda_accounts(
            &tree,
            transact.inputs.iter().map(|input| &input.nullifier_hash),
        );
        let ix_data = SettleIxData { proof, transact };
        let serialized = wincode::serialize(&ix_data).map_err(err)?;

        let mut instruction_data = vec![tag::SETTLE];
        instruction_data.extend_from_slice(&serialized);

        let mut accounts = vec![
            AccountMeta::new(authority, true),
            AccountMeta::new(pair, false),
            AccountMeta::new(escrow, false),
            AccountMeta::new(rent_recipient, false),
            // Forwarded SPP `transact` CPI tail: payer (the authority), output
            // tree, SPP, System Program, input tree, one nullifier PDA per input,
            // then both owner-signers flipped by the program's CPI: the escrow
            // authority (order input) and the pool authority (pool input +
            // data-bearing pool change).
            AccountMeta::new_readonly(authority, true),
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
        accounts.push(AccountMeta::new_readonly(pool_authority_pda(&pair), false));

        Ok(Instruction {
            program_id: dynamic_swap_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
